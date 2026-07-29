import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nightjar.approval import (
    ApprovalError,
    build_approval_payload,
    sign_approval,
    verify_approval,
)
from nightjar.models import Mission
from nightjar.policy import PolicyLimits

NOW = 1_800_000_000


def build_mission(altitude_m: float = 5) -> Mission:
    return Mission.model_validate(
        {
            "mission_id": "42b6a3fd-1b5c-4d2a-9c86-b82679b2f88c",
            "description": "Approval-envelope test mission.",
            "actions": [
                {
                    "type": "takeoff",
                    "altitude_m": altitude_m,
                },
                {
                    "type": "land",
                },
            ],
        }
    )


def build_signed_approval():
    private_key = Ed25519PrivateKey.generate()
    mission = build_mission()
    limits = PolicyLimits()

    payload = build_approval_payload(
        mission=mission,
        limits=limits,
        executor="mavsdk",
        ttl_seconds=300,
        now_unix=NOW,
        nonce="n" * 32,
    )

    envelope = sign_approval(private_key, payload)

    return private_key, mission, limits, envelope


def test_valid_approval_is_accepted() -> None:
    private_key, mission, limits, envelope = build_signed_approval()

    verified = verify_approval(
        envelope=envelope,
        public_key=private_key.public_key(),
        mission=mission,
        limits=limits,
        expected_executor="mavsdk",
        now_unix=NOW + 1,
    )

    assert verified == envelope.payload


def test_modified_mission_is_rejected() -> None:
    private_key, _, limits, envelope = build_signed_approval()

    with pytest.raises(ApprovalError, match="mission"):
        verify_approval(
            envelope=envelope,
            public_key=private_key.public_key(),
            mission=build_mission(altitude_m=6),
            limits=limits,
            expected_executor="mavsdk",
            now_unix=NOW + 1,
        )


def test_modified_policy_is_rejected() -> None:
    private_key, mission, _, envelope = build_signed_approval()

    with pytest.raises(ApprovalError, match="policy"):
        verify_approval(
            envelope=envelope,
            public_key=private_key.public_key(),
            mission=mission,
            limits=PolicyLimits(max_altitude_m=20),
            expected_executor="mavsdk",
            now_unix=NOW + 1,
        )


def test_wrong_executor_is_rejected() -> None:
    private_key, mission, limits, envelope = build_signed_approval()

    with pytest.raises(ApprovalError, match="executor"):
        verify_approval(
            envelope=envelope,
            public_key=private_key.public_key(),
            mission=mission,
            limits=limits,
            expected_executor="dry-run",
            now_unix=NOW + 1,
        )


def test_expired_approval_is_rejected() -> None:
    private_key, mission, limits, envelope = build_signed_approval()

    with pytest.raises(ApprovalError, match="expired"):
        verify_approval(
            envelope=envelope,
            public_key=private_key.public_key(),
            mission=mission,
            limits=limits,
            expected_executor="mavsdk",
            now_unix=NOW + 300,
        )


def test_untrusted_signature_is_rejected() -> None:
    _, mission, limits, envelope = build_signed_approval()
    untrusted_key = Ed25519PrivateKey.generate()

    with pytest.raises(ApprovalError, match="signature"):
        verify_approval(
            envelope=envelope,
            public_key=untrusted_key.public_key(),
            mission=mission,
            limits=limits,
            expected_executor="mavsdk",
            now_unix=NOW + 1,
        )
