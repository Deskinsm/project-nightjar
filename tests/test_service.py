import ast
import http.client
import inspect
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from nightjar import service
from nightjar.policy import PolicyLimits
from nightjar.service import (
    AUTHORIZATION_STATUS,
    EXECUTION_STATUS,
    LOOPBACK_HOST,
    MAX_REQUEST_BYTES,
    VALIDATE_PATH,
    ValidationRequestHandler,
    validate_mission_payload,
)

MISSION_ID = "42b6a3fd-1b5c-4d2a-9c86-b82679b2f88c"

SAFE_MISSION = {
    "mission_id": MISSION_ID,
    "description": "ATAK phase 0 validation probe.",
    "actions": [
        {"type": "takeoff", "altitude_m": 5},
        {"type": "goto", "north_m": 10, "east_m": 10, "altitude_m": 5},
        {"type": "return_home"},
        {"type": "land"},
    ],
}

UNSAFE_MISSION = {
    "mission_id": MISSION_ID,
    "description": "Beyond the policy fence.",
    "actions": [
        {"type": "takeoff", "altitude_m": 500},
        {"type": "goto", "north_m": 1000, "east_m": 1000, "altitude_m": 500},
        {"type": "land"},
    ],
}


# --- Structural guarantees ------------------------------------------------


def _import_targets(source: str) -> set[str]:
    """Normalize imports, including ``from . import approval`` forms."""

    tree = ast.parse(source)
    imported: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
            continue

        if not isinstance(node, ast.ImportFrom):
            continue

        if node.level:
            # service.py is directly inside the nightjar package. Imports above
            # that package are never needed by this Phase 0 boundary.
            if node.level != 1:
                imported.add(f"<relative-level-{node.level}>")
                continue

            if node.module:
                imported.add(f"nightjar.{node.module}")
            else:
                imported.update(f"nightjar.{alias.name}" for alias in node.names)
            continue

        module = node.module or ""
        if module == "nightjar":
            imported.update(f"nightjar.{alias.name}" for alias in node.names)
        elif module:
            imported.add(module)

    return imported


def test_service_module_imports_only_read_only_nightjar_dependencies() -> None:
    """Relative or absolute imports cannot quietly reach approval or execution."""

    source = Path("src/nightjar/service.py").read_text(encoding="utf-8")
    imported = _import_targets(source)

    nightjar_imports = {name for name in imported if name.startswith("nightjar.")}
    allowed_nightjar_imports = {
        "nightjar.models",
        "nightjar.policy",
        "nightjar.security",
    }

    assert nightjar_imports <= allowed_nightjar_imports
    assert not any(name == "mavsdk" or name.startswith("mavsdk.") for name in imported)
    assert not any(name.startswith("<relative-level-") for name in imported)


def test_serve_has_no_configurable_host_and_binds_loopback(monkeypatch) -> None:
    """Network exposure requires a code change, not a caller-supplied host."""

    assert tuple(inspect.signature(service.serve).parameters) == ("port",)
    assert LOOPBACK_HOST == "127.0.0.1"

    captured: dict[str, object] = {}

    class FakeServer:
        server_address = (LOOPBACK_HOST, 8787)

        def __init__(self, address, handler) -> None:
            captured["address"] = address
            captured["handler"] = handler

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr(service, "ThreadingHTTPServer", FakeServer)
    service.serve(port=8787)

    assert captured["address"] == (LOOPBACK_HOST, 8787)
    assert captured["handler"] is ValidationRequestHandler
    assert captured["closed"] is True


def test_authorization_and_execution_are_never_granted() -> None:
    for payload in ({"mission": SAFE_MISSION}, {"mission": UNSAFE_MISSION}, {}, {"mission": {}}):
        _, body = validate_mission_payload(payload)
        assert body["authorization"] == AUTHORIZATION_STATUS == "REQUIRED_NOT_GRANTED"
        assert body["execution"] == EXECUTION_STATUS == "NOT_AVAILABLE_IN_THIS_SERVICE"


# --- Contract -------------------------------------------------------------


def test_safe_mission_is_approved_with_full_contract() -> None:
    status, body = validate_mission_payload({"mission": SAFE_MISSION})

    assert status == 200
    assert body["approved"] is True
    assert body["reasons"] == []
    assert len(body["mission_sha256"]) == 64
    assert len(body["policy_sha256"]) == 64
    assert body["policy_limits"]["max_altitude_m"] == PolicyLimits().max_altitude_m
    assert body["normalized_mission"]["mission_id"] == MISSION_ID
    assert len(body["normalized_mission"]["actions"]) == 4


def test_unsafe_mission_is_rejected_with_reasons() -> None:
    status, body = validate_mission_payload({"mission": UNSAFE_MISSION})

    assert status == 200
    assert body["approved"] is False
    assert body["reasons"]
    assert any("altitude" in reason for reason in body["reasons"])


def test_hash_is_stable_across_calls_when_mission_id_is_supplied() -> None:
    first = validate_mission_payload({"mission": SAFE_MISSION})[1]["mission_sha256"]
    second = validate_mission_payload({"mission": SAFE_MISSION})[1]["mission_sha256"]

    assert first == second


def test_hash_changes_when_mission_id_is_omitted() -> None:
    """Documents the uuid4 default_factory gotcha the client must avoid."""

    without_id = {key: value for key, value in SAFE_MISSION.items() if key != "mission_id"}

    first = validate_mission_payload({"mission": without_id})[1]["mission_sha256"]
    second = validate_mission_payload({"mission": without_id})[1]["mission_sha256"]

    assert first != second


def test_missing_mission_key_is_rejected() -> None:
    status, body = validate_mission_payload({"actions": []})

    assert status == 422
    assert body["error"] == "schema"


def test_unknown_field_is_rejected() -> None:
    status, body = validate_mission_payload(
        {"mission": {**SAFE_MISSION, "override_policy": True}},
    )

    assert status == 422
    assert body["error"] == "schema"


def test_custom_limits_change_the_policy_hash() -> None:
    default_body = validate_mission_payload({"mission": SAFE_MISSION})[1]
    strict_body = validate_mission_payload(
        {"mission": SAFE_MISSION},
        limits=PolicyLimits(max_altitude_m=3.0),
    )[1]

    assert default_body["policy_sha256"] != strict_body["policy_sha256"]
    assert strict_body["approved"] is False


# --- HTTP layer -----------------------------------------------------------


@pytest.fixture
def live_service():
    httpd = ThreadingHTTPServer((LOOPBACK_HOST, 0), ValidationRequestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    yield f"http://{LOOPBACK_HOST}:{httpd.server_address[1]}"

    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def _request(base_url: str, path: str, payload: dict) -> urllib.request.Request:
    return urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )


def _post(base_url: str, path: str, payload: dict) -> tuple[int, dict]:
    request = _request(base_url, path, payload)

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_http_validate_round_trip(live_service: str) -> None:
    status, body = _post(live_service, VALIDATE_PATH, {"mission": SAFE_MISSION})

    assert status == 200
    assert body["approved"] is True
    assert body["authorization"] == "REQUIRED_NOT_GRANTED"


def test_http_responses_are_not_cacheable(live_service: str) -> None:
    request = _request(live_service, VALIDATE_PATH, {"mission": SAFE_MISSION})

    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.headers["Cache-Control"] == "no-store"


def test_http_unknown_route_is_rejected(live_service: str) -> None:
    status, body = _post(live_service, "/v1/missions/execute", {"mission": SAFE_MISSION})

    assert status == 404
    assert body["error"] == "route"


def test_http_get_is_rejected(live_service: str) -> None:
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(live_service + VALIDATE_PATH, timeout=5)

    assert exc_info.value.code == 405
    assert exc_info.value.headers["Cache-Control"] == "no-store"


def test_http_malformed_json_is_rejected(live_service: str) -> None:
    request = urllib.request.Request(
        live_service + VALIDATE_PATH,
        data=b"{not json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(request, timeout=5)

    assert exc_info.value.code == 400


def test_http_oversized_body_is_rejected(live_service: str) -> None:
    parsed = urllib.parse.urlsplit(live_service)

    assert parsed.hostname is not None
    assert parsed.port is not None

    connection = http.client.HTTPConnection(
        parsed.hostname,
        parsed.port,
        timeout=5,
    )

    try:
        connection.putrequest("POST", VALIDATE_PATH)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
        connection.endheaders()

        response = connection.getresponse()
        body = json.loads(response.read())

        assert response.status == 413
        assert body["error"] == "size"
        assert response.getheader("Connection") == "close"
    finally:
        connection.close()
