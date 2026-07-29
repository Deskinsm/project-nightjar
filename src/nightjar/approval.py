from __future__ import annotations

import base64
import hmac
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, model_validator

from nightjar.models import Mission, StrictModel
from nightjar.policy import PolicyLimits
from nightjar.security import canonical_json_bytes, mission_sha256, policy_sha256


class ApprovalError(ValueError):
    """Raised when an approval envelope cannot be trusted."""


class ApprovalPayload(StrictModel):
    mission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executor: str = Field(min_length=1, max_length=64)
    issued_at_unix: int = Field(ge=0)
    expires_at_unix: int = Field(gt=0)
    nonce: str = Field(min_length=32, max_length=128)

    @model_validator(mode="after")
    def validate_time_window(self) -> ApprovalPayload:
        if self.expires_at_unix <= self.issued_at_unix:
            raise ValueError("Approval expiration must follow issuance.")
        return self


class SignedApproval(StrictModel):
    payload: ApprovalPayload
    signature_b64: str = Field(min_length=1, max_length=256)


def build_approval_payload(
    *,
    mission: Mission,
    limits: PolicyLimits,
    executor: str,
    ttl_seconds: int = 300,
    now_unix: int | None = None,
    nonce: str | None = None,
) -> ApprovalPayload:
    if ttl_seconds <= 0:
        raise ValueError("Approval TTL must be positive.")

    issued_at = int(time.time()) if now_unix is None else now_unix

    return ApprovalPayload(
        mission_sha256=mission_sha256(mission),
        policy_sha256=policy_sha256(limits),
        executor=executor,
        issued_at_unix=issued_at,
        expires_at_unix=issued_at + ttl_seconds,
        nonce=nonce or secrets.token_urlsafe(32),
    )


def approval_signing_bytes(payload: ApprovalPayload) -> bytes:
    return canonical_json_bytes(payload.model_dump(mode="json"))


def sign_approval(
    private_key: Ed25519PrivateKey,
    payload: ApprovalPayload,
) -> SignedApproval:
    signature = private_key.sign(approval_signing_bytes(payload))

    return SignedApproval(
        payload=payload,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_approval(
    *,
    envelope: SignedApproval,
    public_key: Ed25519PublicKey,
    mission: Mission,
    limits: PolicyLimits,
    expected_executor: str,
    now_unix: int | None = None,
    max_clock_skew_seconds: int = 30,
    max_lifetime_seconds: int = 300,
) -> ApprovalPayload:
    try:
        signature = base64.b64decode(
            envelope.signature_b64,
            validate=True,
        )
    except ValueError as exc:
        raise ApprovalError("Approval signature is not valid base64.") from exc

    try:
        public_key.verify(
            signature,
            approval_signing_bytes(envelope.payload),
        )
    except InvalidSignature as exc:
        raise ApprovalError("Approval signature is invalid.") from exc

    current_time = int(time.time()) if now_unix is None else now_unix
    payload = envelope.payload

    if payload.issued_at_unix > current_time + max_clock_skew_seconds:
        raise ApprovalError("Approval was issued too far in the future.")

    if current_time >= payload.expires_at_unix:
        raise ApprovalError("Approval has expired.")

    lifetime = payload.expires_at_unix - payload.issued_at_unix
    if lifetime > max_lifetime_seconds:
        raise ApprovalError("Approval lifetime exceeds the permitted maximum.")

    if not hmac.compare_digest(
        payload.mission_sha256,
        mission_sha256(mission),
    ):
        raise ApprovalError("Approval does not match this mission.")

    if not hmac.compare_digest(
        payload.policy_sha256,
        policy_sha256(limits),
    ):
        raise ApprovalError("Approval does not match this policy.")

    if payload.executor != expected_executor:
        raise ApprovalError("Approval does not authorize this executor.")

    return payload
