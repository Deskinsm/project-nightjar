#!/usr/bin/env python3
"""Acceptance-only adapter that injects a failure during hold.

This is not part of the normal Nightjar execution path. It exists solely
so the PX4 acceptance harness can exercise recovery against a live
software simulation while still using the real authorization and
executor machinery.

The adapter constructs a normal MavsdkExecutor with a sleep function
that raises after a short delay. The connection remains available so
recovery can land the vehicle, and the original error is preserved by
the executor's existing recovery path.

Usage (invoked by the harness, not by operators directly):

    python scripts/acceptance_failure_adapter.py \
        missions/mavsdk_simulation_mission.json \
        --approval-file approval.json \
        --public-key-file approver-public.pem \
        --nonce-db approvals.sqlite3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from pydantic import ValidationError

from nightjar.approval import ApprovalError
from nightjar.cli import load_ed25519_public_key, load_mission, load_signed_approval
from nightjar.mavsdk_executor import (
    MavsdkExecutor,
    MavsdkExecutorError,
    MavsdkPolicyRejectedError,
    UnsupportedMavsdkActionError,
)
from nightjar.policy import PolicyEngine, PolicyLimits
from nightjar.replay import ApprovalReplayError, SQLiteNonceStore

INJECTED_ERROR = "Acceptance-only injected failure during hold."


async def _failing_sleep(duration: float) -> None:
    """Sleep briefly, then raise so recovery can still land the vehicle."""
    await asyncio.sleep(min(duration, 1.0))
    raise MavsdkExecutorError(INJECTED_ERROR)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Acceptance-only MAVSDK failure injection adapter."
    )
    parser.add_argument("mission", type=Path)
    parser.add_argument("--approval-file", type=Path, required=True)
    parser.add_argument("--public-key-file", type=Path, required=True)
    parser.add_argument("--nonce-db", type=Path)
    args = parser.parse_args()

    try:
        mission = load_mission(args.mission)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"Mission could not be loaded: {exc}")
        return 2

    limits = PolicyLimits()
    policy_engine = PolicyEngine(limits)
    decision = policy_engine.evaluate(mission)
    print(f"Mission: {mission.mission_id}")
    print(f"Description: {mission.description}")
    print(f"Policy decision: {'APPROVED' if decision.approved else 'REJECTED'}")
    for reason in decision.reasons:
        print(f"  - {reason}")
    if not decision.approved:
        return 1

    try:
        envelope = load_signed_approval(args.approval_file)
        public_key = load_ed25519_public_key(args.public_key_file)
        nonce_store = SQLiteNonceStore(args.nonce_db)
    except (
        OSError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
        TypeError,
        UnsupportedAlgorithm,
        sqlite3.Error,
    ) as exc:
        print(f"Authorization material could not be loaded: {exc}")
        return 3

    try:
        executor = MavsdkExecutor(
            public_key=public_key,
            nonce_store=nonce_store,
            limits=limits,
            sleep_function=_failing_sleep,
        )
        result = executor.execute(mission, approval=envelope)
    except (ApprovalError, ApprovalReplayError, sqlite3.Error) as exc:
        print(f"Execution blocked: {exc}")
        return 4
    except (UnsupportedMavsdkActionError, MavsdkPolicyRejectedError) as exc:
        print(f"Execution blocked: {exc}")
        return 4
    except MavsdkExecutorError as exc:
        print(f"Execution failed: {exc}")
        return 5
    except Exception as exc:  # noqa: BLE001
        print(f"Execution failed: {exc}")
        return 5

    print("Signed approval verified and consumed.")
    print(f"MAVSDK simulation complete. Audit log: {result.log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
