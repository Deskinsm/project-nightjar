"""Read-only mission validation service for the ATAK Phase 0 experiment.

This module deliberately imports only the schema, the policy engine, and the
hashing helpers. It does not import ``approval``, ``authorization``, ``replay``,
or any executor, so no code path here can issue an approval or cause execution.

``tests/test_service.py`` asserts that property against the module source.

Transport is plain HTTP bound to loopback. Phase 0 reaches the service from an
Android device through ``adb reverse tcp:8787 tcp:8787``; TLS is out of scope
until the prototype leaves USB.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pydantic import ValidationError

from nightjar.models import Mission
from nightjar.policy import PolicyEngine, PolicyLimits
from nightjar.security import mission_sha256, policy_sha256

SERVICE_VERSION = "0.1.0-phase0"
VALIDATE_PATH = "/v1/missions/validate"
MAX_REQUEST_BYTES = 64 * 1024
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

# Constants, not computed values. This service has no path that can emit
# anything else for these fields.
AUTHORIZATION_STATUS = "REQUIRED_NOT_GRANTED"
EXECUTION_STATUS = "NOT_AVAILABLE_IN_THIS_SERVICE"


def validate_mission_payload(
    payload: Any,
    limits: PolicyLimits | None = None,
) -> tuple[int, dict[str, Any]]:
    """Validate a mission proposal and return an (HTTP status, body) pair.

    Pure function: no I/O, no state, no side effects. The HTTP layer below is a
    thin wrapper so this can be exercised directly from tests.
    """

    active_limits = limits or PolicyLimits()

    if not isinstance(payload, dict) or "mission" not in payload:
        return 422, {
            "service_version": SERVICE_VERSION,
            "error": "schema",
            "reasons": ["Request body must be an object containing a 'mission' key."],
            "authorization": AUTHORIZATION_STATUS,
            "execution": EXECUTION_STATUS,
        }

    try:
        mission = Mission.model_validate(payload["mission"])
    except ValidationError as exc:
        return 422, {
            "service_version": SERVICE_VERSION,
            "error": "schema",
            "reasons": [
                f"{'.'.join(str(part) for part in error['loc']) or 'mission'}: {error['msg']}"
                for error in exc.errors()
            ],
            "policy_limits": asdict(active_limits),
            "authorization": AUTHORIZATION_STATUS,
            "execution": EXECUTION_STATUS,
        }

    decision = PolicyEngine(active_limits).evaluate(mission)

    return 200, {
        "service_version": SERVICE_VERSION,
        "approved": decision.approved,
        "reasons": list(decision.reasons),
        "mission_sha256": mission_sha256(mission),
        "policy_sha256": policy_sha256(active_limits),
        "policy_limits": asdict(active_limits),
        "normalized_mission": mission.model_dump(mode="json"),
        "authorization": AUTHORIZATION_STATUS,
        "execution": EXECUTION_STATUS,
    }


class ValidationRequestHandler(BaseHTTPRequestHandler):
    """Serves exactly one route. Everything else fails closed."""

    server_version = f"nightjar-validate/{SERVICE_VERSION}"
    protocol_version = "HTTP/1.1"

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        # The map client is served from file:// or another local port. The
        # service is loopback-bound, read-only, and stateless, so a permissive
        # origin costs nothing here. Revisit if it ever binds a real interface.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self._respond(
            405,
            {
                "service_version": SERVICE_VERSION,
                "error": "method",
                "reasons": [f"Use POST {VALIDATE_PATH}."],
                "authorization": AUTHORIZATION_STATUS,
                "execution": EXECUTION_STATUS,
            },
        )

    def do_POST(self) -> None:
        if self.path != VALIDATE_PATH:
            self._respond(
                404,
                {
                    "service_version": SERVICE_VERSION,
                    "error": "route",
                    "reasons": [f"Unknown route. The only route is POST {VALIDATE_PATH}."],
                    "authorization": AUTHORIZATION_STATUS,
                    "execution": EXECUTION_STATUS,
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1

        if length < 0 or length > MAX_REQUEST_BYTES:
            self.close_connection = True
            self._respond(
                413,
                {
                    "service_version": SERVICE_VERSION,
                    "error": "size",
                    "reasons": [f"Request body must be 1 to {MAX_REQUEST_BYTES} bytes."],
                    "authorization": AUTHORIZATION_STATUS,
                    "execution": EXECUTION_STATUS,
                },
            )
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._respond(
                400,
                {
                    "service_version": SERVICE_VERSION,
                    "error": "json",
                    "reasons": [f"Request body is not valid JSON: {exc}"],
                    "authorization": AUTHORIZATION_STATUS,
                    "execution": EXECUTION_STATUS,
                },
            )
            return

        status, body = validate_mission_payload(payload)
        self._respond(status, body)

    def log_message(self, format: str, *args: Any) -> None:
        # Deliberately quiet: mission proposals carry operator-selected
        # coordinates and must not land in a terminal scrollback by default.
        return


def serve(port: int = DEFAULT_PORT) -> None:
    """Run the Phase 0 service on IPv4 loopback only.

    The bind host is intentionally not a parameter. Changing network exposure
    requires a code change and review rather than a command-line or API option.
    """

    httpd = ThreadingHTTPServer((LOOPBACK_HOST, port), ValidationRequestHandler)
    actual_port = int(httpd.server_address[1])
    print(
        "Nightjar validation service (read-only) on "
        f"http://{LOOPBACK_HOST}:{actual_port}{VALIDATE_PATH}"
    )
    print("This service cannot authorize or execute anything.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
