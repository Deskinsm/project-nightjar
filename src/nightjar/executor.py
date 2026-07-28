from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nightjar.audit import write_audit_record
from nightjar.models import Mission


@dataclass(frozen=True)
class ExecutionResult:
    completed: bool
    log_path: Path


class DryRunExecutor:
    """Simulates execution without connecting to any vehicle."""

    def execute(self, mission: Mission) -> ExecutionResult:
        log_path = write_audit_record(
            mission_id=mission.mission_id,
            event="mission_started",
            details={"description": mission.description},
        )

        for sequence, action in enumerate(mission.actions, start=1):
            write_audit_record(
                mission_id=mission.mission_id,
                event="action_simulated",
                details={
                    "sequence": sequence,
                    "action": action.model_dump(mode="json"),
                },
            )

        write_audit_record(
            mission_id=mission.mission_id,
            event="mission_completed",
            details={"executor": "dry_run"},
        )
        return ExecutionResult(completed=True, log_path=log_path)
