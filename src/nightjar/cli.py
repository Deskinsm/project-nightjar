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
        choices=("dry-run", "mavsdk"),
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

    home = subparsers.add_parser(
        "home",
        help="Trusted home commands.",
    )
    home_sub = home.add_subparsers(dest="home_command", required=True)
    snapshot = home_sub.add_parser(
        "snapshot",
        help="Capture the vehicle home from telemetry and write it to a file.",
    )
    snapshot.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write the home snapshot JSON.",
    )
    snapshot.add_argument(
        "--system-address",
        default="udpin://127.0.0.1:14540",
        help="MAVSDK system address. Defaults to the loopback PX4 endpoint.",
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "home":
        return _home_snapshot(args)

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

    if args.executor == "dry-run":
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

        result = DryRunExecutor().execute(mission)
        print(f"Dry run complete. Audit log: {result.log_path}")
        return 0

    if args.executor == "mavsdk":
        # Approval consumption stays inside MavsdkExecutor so capability and
        # policy checks can reject the mission before the nonce is spent.
        try:
            from nightjar.mavsdk_executor import (
                HomeMismatchError,
                HomeUnavailableError,
                MavsdkExecutor,
                MavsdkExecutorError,
                MavsdkPolicyRejectedError,
                UnsupportedMavsdkActionError,
            )

            executor = MavsdkExecutor(
                public_key=public_key,
                nonce_store=nonce_store,
                limits=limits,
            )
            result = executor.execute(mission, approval=envelope)
        except (ApprovalError, ApprovalReplayError, sqlite3.Error) as exc:
            print(f"Execution blocked: {exc}")
            return 4
        except (UnsupportedMavsdkActionError, MavsdkPolicyRejectedError) as exc:
            print(f"Execution blocked: {exc}")
            return 4
        except HomeUnavailableError as exc:
            print(f"Home unavailable: {exc}")
            return 6
        except HomeMismatchError as exc:
            print(f"Home mismatch: {exc}")
            return 7
        except MavsdkExecutorError as exc:
            print(f"Execution failed: {exc}")
            return 5
        except Exception as exc:  # noqa: BLE001
            print(f"Execution failed: {exc}")
            return 5

        print("Signed approval verified and consumed.")
        print(f"MAVSDK simulation complete. Audit log: {result.log_path}")
        return 0

    print(f"Unsupported executor: {args.executor}")
    return 5


def _home_snapshot(args: argparse.Namespace) -> int:
    """Capture home from telemetry. Never accepts a client-supplied origin."""
    import asyncio

    from nightjar.home import snapshot_from_telemetry
    from nightjar.mavsdk_executor import HomeUnavailableError, MavsdkExecutorError

    async def capture() -> int:
        try:
            from mavsdk import System
        except ImportError as exc:
            print(f"MAVSDK is not installed: {exc}")
            return 5

        drone = System()
        try:
            await drone.connect(system_address=args.system_address)
            async for state in drone.core.connection_state():
                if state.is_connected:
                    break
            async for health in drone.telemetry.health():
                if health.is_home_position_ok and health.is_global_position_ok:
                    break
            else:
                raise HomeUnavailableError("Health stream ended before home was OK.")
            async for home in drone.telemetry.home():
                snapshot = snapshot_from_telemetry(
                    latitude_deg=home.latitude_deg,
                    longitude_deg=home.longitude_deg,
                    absolute_altitude_m=home.absolute_altitude_m,
                )
                break
            else:
                raise HomeUnavailableError("Home stream ended before a position arrived.")
        except (HomeUnavailableError, MavsdkExecutorError, asyncio.TimeoutError) as exc:
            print(f"Home unavailable: {exc}")
            return 6
        finally:
            stop = getattr(drone, "_stop_mavsdk_server", None)
            if callable(stop):
                try:
                    stop()
                except Exception as exc:  # noqa: BLE001
                    print(f"MAVSDK server stop failed: {type(exc).__name__}")

        args.output.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        print(f"Home snapshot written to {args.output}")
        return 0

    return asyncio.run(capture())


if __name__ == "__main__":
    raise SystemExit(main())
