from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nightjar.approval import ApprovalPayload, SignedApproval, verify_approval
from nightjar.models import Mission
from nightjar.policy import PolicyLimits
from nightjar.replay import NonceStore


def verify_and_consume_approval(
    *,
    envelope: SignedApproval,
    public_key: Ed25519PublicKey,
    mission: Mission,
    limits: PolicyLimits,
    expected_executor: str,
    nonce_store: NonceStore,
    now_unix: int | None = None,
    max_clock_skew_seconds: int = 30,
    max_lifetime_seconds: int = 300,
) -> ApprovalPayload:
    """Verify an approval and atomically consume its nonce.

    Verification always occurs before nonce consumption. Execution must occur
    only after this function returns successfully.
    """

    current_time = int(time.time()) if now_unix is None else now_unix

    payload = verify_approval(
        envelope=envelope,
        public_key=public_key,
        mission=mission,
        limits=limits,
        expected_executor=expected_executor,
        now_unix=current_time,
        max_clock_skew_seconds=max_clock_skew_seconds,
        max_lifetime_seconds=max_lifetime_seconds,
    )

    nonce_store.consume(
        nonce=payload.nonce,
        mission_sha256=payload.mission_sha256,
        policy_sha256=payload.policy_sha256,
        executor=payload.executor,
        expires_at_unix=payload.expires_at_unix,
        now_unix=current_time,
    )

    return payload
