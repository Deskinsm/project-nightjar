from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from nightjar.models import Mission
from nightjar.policy import PolicyLimits


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a value deterministically for hashing and signing."""

    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return serialized.encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Return the SHA-256 digest of a canonically serialized value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def mission_sha256(mission: Mission) -> str:
    """Bind approval to the exact mission, including its ID and description."""

    return sha256_hex(mission.model_dump(mode="json"))


def policy_sha256(limits: PolicyLimits) -> str:
    """Bind approval to the exact policy limits used during evaluation."""

    return sha256_hex(asdict(limits))
