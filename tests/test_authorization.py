from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nightjar.approval import (
    ApprovalError,
    build_approval_payload,
    sign_approval,
)
from nightjar.authorization import verify_and_consume_approval
from nightjar.models import Mission
from nightjar.policy import PolicyLimits
from nightjar.replay import ApprovalReplayError, SQLiteNonceStore

NOW = 1_800_000_000


def build_mission() -> Mission:
    return Mission.model_validate(
        {
            "mission_id": "42b6a3fd-1b5c-4d2a-9c86-b82679b2f88c",
            "description": "Authorization integration test.",
            "actions": [
                {
                    "type": "takeoff",
                    "altitude_m": 5,
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

    return (
        private_key,
        mission,
        limits,
        sign_approval(private_key, payload),
    )


def test_signed_approval_can_be_consumed_once(tmp_path: Path) -> None:
    private_key, mission, limits, envelope = build_signed_approval()
    store = SQLiteNonceStore(tmp_path / "approvals.sqlite3")

    verified = verify_and_consume_approval(
        envelope=envelope,
        public_key=private_key.public_key(),
        mission=mission,
        limits=limits,
        expected_executor="mavsdk",
        nonce_store=store,
        now_unix=NOW + 1,
    )

    assert verified == envelope.payload

    with pytest.raises(
        ApprovalReplayError,
        match="already been used",
    ):
        verify_and_consume_approval(
            envelope=envelope,
            public_key=private_key.public_key(),
            mission=mission,
            limits=limits,
            expected_executor="mavsdk",
            nonce_store=store,
            now_unix=NOW + 2,
        )


def test_invalid_signature_does_not_consume_nonce(
    tmp_path: Path,
) -> None:
    private_key, mission, limits, envelope = build_signed_approval()
    untrusted_key = Ed25519PrivateKey.generate()
    store = SQLiteNonceStore(tmp_path / "approvals.sqlite3")

    with pytest.raises(ApprovalError, match="signature"):
        verify_and_consume_approval(
            envelope=envelope,
            public_key=untrusted_key.public_key(),
            mission=mission,
            limits=limits,
            expected_executor="mavsdk",
            nonce_store=store,
            now_unix=NOW + 1,
        )

    verified = verify_and_consume_approval(
        envelope=envelope,
        public_key=private_key.public_key(),
        mission=mission,
        limits=limits,
        expected_executor="mavsdk",
        nonce_store=store,
        now_unix=NOW + 2,
    )

    assert verified == envelope.payload


def test_wrong_executor_does_not_consume_nonce(
    tmp_path: Path,
) -> None:
    private_key, mission, limits, envelope = build_signed_approval()
    store = SQLiteNonceStore(tmp_path / "approvals.sqlite3")

    with pytest.raises(ApprovalError, match="executor"):
        verify_and_consume_approval(
            envelope=envelope,
            public_key=private_key.public_key(),
            mission=mission,
            limits=limits,
            expected_executor="dry-run",
            nonce_store=store,
            now_unix=NOW + 1,
        )

    verified = verify_and_consume_approval(
        envelope=envelope,
        public_key=private_key.public_key(),
        mission=mission,
        limits=limits,
        expected_executor="mavsdk",
        nonce_store=store,
        now_unix=NOW + 2,
    )

    assert verified == envelope.payload
