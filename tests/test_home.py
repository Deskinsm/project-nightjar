from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nightjar.approval import (
    ApprovalError,
    build_approval_payload,
    sign_approval,
    verify_approval,
)
from nightjar.home import (
    FRAME_ID,
    home_sha256,
    snapshot_from_telemetry,
    within_tolerance,
)
from nightjar.models import Mission
from nightjar.policy import PolicyLimits
from nightjar.security import policy_sha256


def _home(**overrides):
    values = {
        "latitude_deg": 47.3977419,
        "longitude_deg": 8.5455938,
        "absolute_altitude_m": 488.0,
        "captured_at": "2026-01-01T00:00:00+00:00",
    }
    values.update(overrides)
    return snapshot_from_telemetry(**values)


def _mission() -> Mission:
    return Mission.model_validate(
        {
            "description": "Home binding test",
            "actions": [{"type": "takeoff", "altitude_m": 5}, {"type": "land"}],
        }
    )


def test_canonical_hash_stable_across_float_jitter() -> None:
    a = _home(latitude_deg=47.39774190000001)
    b = _home(latitude_deg=47.39774189999999)
    assert a.latitude_e7 == b.latitude_e7
    assert home_sha256(a) == home_sha256(b)

    moved = _home(latitude_deg=47.3977500)
    assert home_sha256(moved) != home_sha256(a)


def test_approval_missing_home_binding_is_rejected() -> None:
    with pytest.raises(TypeError):
        build_approval_payload(  # type: ignore[call-arg]
            mission=_mission(),
            limits=PolicyLimits(),
            executor="mavsdk",
        )


def test_tampered_home_fails_signature() -> None:
    key = Ed25519PrivateKey.generate()
    payload = build_approval_payload(
        mission=_mission(),
        limits=PolicyLimits(),
        executor="mavsdk",
        home=_home(),
        now_unix=int(time.time()),
        nonce="n" * 32,
    )
    envelope = sign_approval(key, payload)
    tampered = envelope.model_copy(
        update={
            "payload": payload.model_copy(
                update={"home_latitude_e7": payload.home_latitude_e7 + 1000}
            )
        }
    )
    with pytest.raises(ApprovalError, match="signature"):
        verify_approval(
            envelope=tampered,
            public_key=key.public_key(),
            mission=_mission(),
            limits=PolicyLimits(),
            expected_executor="mavsdk",
        )


def test_mission_rejects_client_supplied_home() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Mission.model_validate(
            {
                "description": "Client tries to supply home",
                "home": {"latitude_deg": 1.0},
                "actions": [{"type": "land"}],
            }
        )


def test_tolerance_change_changes_policy_hash() -> None:
    base = policy_sha256(PolicyLimits())
    changed = policy_sha256(PolicyLimits(home_horizontal_tolerance_m=5.0))
    assert base != changed


def test_within_tolerance_boundaries() -> None:
    origin = _home()
    same = _home()
    assert within_tolerance(origin, same, horizontal_m=2.0, vertical_m=3.0)

    far = _home(latitude_deg=origin.latitude_deg + 0.001)
    assert not within_tolerance(origin, far, horizontal_m=2.0, vertical_m=3.0)


def test_frame_id_is_home_ned_v1() -> None:
    payload = build_approval_payload(
        mission=_mission(),
        limits=PolicyLimits(),
        executor="mavsdk",
        home=_home(),
        now_unix=int(time.time()),
        nonce="n" * 32,
    )
    assert payload.frame_id == FRAME_ID
    assert payload.home_sha256 == home_sha256(_home())
