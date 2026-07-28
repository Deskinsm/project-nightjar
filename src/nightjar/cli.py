from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from nightjar.executor import DryRunExecutor
from nightjar.models import Mission
from nightjar.policy import PolicyEngine


def load_mission(path: Path) -> Mission:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return Mission.model_validate(payload)


def print_decision(mission: Mission) -> bool:
    decision = PolicyEngine().evaluate(mission)
    print(f"Mission: {mission.mission_id}")
    print(f"Description: {mission.description}")
    print(f"Policy decision: {'APPROVED' if decision.approved else 'REJECTED'}")

    for reason in decision.reasons:
        print(f"  - {reason}")

    return decision.approved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nightjar")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate and policy-check a mission.")
    validate.add_argument("mission", type=Path)

    run = subparsers.add_parser("run", help="Policy-check and dry-run a mission.")
    run.add_argument("mission", type=Path)
    run.add_argument(
        "--approve",
        action="store_true",
        help="Record explicit human approval and run the dry-run executor.",
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        mission = load_mission(args.mission)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"Mission could not be loaded: {exc}")
        return 2

    approved = print_decision(mission)
    if not approved:
        return 1

    if args.command == "run":
        if not args.approve:
            print("Execution blocked: explicit --approve flag is required.")
            return 3

        result = DryRunExecutor().execute(mission)
        print(f"Dry run complete. Audit log: {result.log_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
