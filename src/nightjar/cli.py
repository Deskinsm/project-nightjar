from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import ValidationError

from nightjar.approval import ApprovalError, SignedApproval
from nightjar.authorization import verify_and_consume_approval
from nightjar.executor import DryRunExecutor
from nightjar.models import Mission
from nightjar.policy import PolicyEngine, PolicyLimits
from nightjar.replay import ApprovalReplayError, SQLiteNonceStore


def load_mission(path: Path) -> Mission:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return Mission.model_validate(payload)


def load_signed_approval(path: Path) -> SignedApproval:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return SignedApproval.model_validate(payload)


def load_ed25519_public_key(path: Path) -> Ed25519PublicKey:
    key = load_pem_public_key(path.read_bytes())

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Approval key must be an Ed25519 public key.")

    return key


def print_decision(
    mission: Mission,
    policy_engine: PolicyEngine,
) -> bool:
    decision = policy_engine.evaluate(mission)

    print(f"Mission: {mission.mission_id}")
    print(f"Description: {mission.description}")
    print(f"Policy decision: {'APPROVED' if decision.approved else 'REJECTED'}")

    for reason in decision.reasons:
        print(f"  - {reason}")

    return decision.approved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nightjar")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate",
        help="Validate and policy-check a mission.",
    )
    validate.add_argument("mission", type=Path)

    run = subparsers.add_parser(
        "run",
        help="Authorize and execute a mission.",
    )
    run.add_argument("mission", type=Path)
    run.add_argument(
        "--executor",
        choices=("dry-run",),
        required=True,
        help="Executor authorized by the signed approval.",
    )
    run.add_argument(
        "--approval-file",
        type=Path,
        required=True,
        help="Signed approval envelope in JSON format.",
    )
    run.add_argument(
        "--public-key-file",
        type=Path,
        required=True,
        help="Trusted Ed25519 approver public key in PEM format.",
    )
    run.add_argument(
        "--nonce-db",
        type=Path,
        help="Optional path to the consumed-approval SQLite database.",
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        mission = load_mission(args.mission)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"Mission could not be loaded: {exc}")
        return 2

    limits = PolicyLimits()
    policy_engine = PolicyEngine(limits)

    if not print_decision(mission, policy_engine):
        return 1

    if args.command == "validate":
        return 0

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
        verify_and_consume_approval(
            envelope=envelope,
            public_key=public_key,
            mission=mission,
            limits=limits,
            expected_executor=args.executor,
            nonce_store=nonce_store,
        )
    except (ApprovalError, ApprovalReplayError, sqlite3.Error) as exc:
        print(f"Execution blocked: {exc}")
        return 4

    print("Signed approval verified and consumed.")

    if args.executor == "dry-run":
        result = DryRunExecutor().execute(mission)
        print(f"Dry run complete. Audit log: {result.log_path}")
        return 0

    print(f"Unsupported executor: {args.executor}")
    return 5


if __name__ == "__main__":
    raise SystemExit(main())
