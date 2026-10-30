"""Outcome checks for the PX4 acceptance harness.

These functions decide PASS/FAIL from exit codes, stdout, and audit
content. They are deliberately strict so that a connection failure,
failed recovery, missing audit, or unrelated authorization error cannot
produce an overall PASS.
"""

from __future__ import annotations

import json
from pathlib import Path

INJECTED_ERROR = "Acceptance-only injected failure during hold."


def _read_audit(path: Path | None) -> tuple[list[dict] | None, str | None]:
    """Return (records, error). error is set on parse failure so callers can FAIL cleanly."""
    if path is None or not path.exists():
        return [], None
    records = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return None, f"audit could not be parsed: {exc}"
    return records, None


def signed_mission_passed(
    *, exit_code: int, stdout: str, audit_path: Path | None
) -> tuple[bool, str]:
    """Require exit 0, success message, and a completed audit record."""
    if exit_code != 0:
        return False, f"exit code {exit_code}, expected 0"
    if "MAVSDK simulation complete" not in stdout:
        return False, "missing success confirmation in stdout"
    records, error = _read_audit(audit_path)
    if error:
        return False, error
    if not records:
        return False, "required audit log is missing"
    completed = [r for r in records if r.get("event") == "mission_completed"]
    if not completed:
        return False, "audit does not contain mission_completed"
    return True, "signed mission completed with audit confirmation"


def replay_rejected(
    *,
    exit_code: int,
    stdout: str,
    audit_path: Path | None,
) -> tuple[bool, str]:
    """Require the already-used rejection.

    Absence of an audit file is supporting evidence that the executor did
    not proceed to mission_started. Direct proof that MAVSDK system
    creation never occurs on replay lives in the existing regression
    tests, because the executor creates the system before writing the
    first audit record.
    """
    if exit_code != 4:
        return False, f"exit code {exit_code}, expected 4"
    if "already been used" not in stdout and "already used" not in stdout.lower():
        return False, "missing already-used rejection in stdout"
    if audit_path is not None and audit_path.exists():
        return False, "replay produced an audit log (supporting evidence of early progress)"
    return True, (
        "replay rejected with already-used; no audit written "
        "(supporting evidence; system-creation proof is in regression tests)"
    )


def controlled_failure_recovered(
    *,
    exit_code: int,
    stdout: str,
    audit_path: Path | None,
) -> tuple[bool, str]:
    """Require the injected error, landing_confirmed recovery, and no recovery error."""
    if exit_code != 5:
        return False, f"exit code {exit_code}, expected 5"
    if INJECTED_ERROR not in stdout:
        return False, "injected error not visible in stdout"
    records, error = _read_audit(audit_path)
    if error:
        return False, error
    if not records:
        return False, "required audit log is missing"
    failed = [r for r in records if r.get("event") == "mission_failed"]
    if not failed:
        return False, "audit does not contain mission_failed"
    details = failed[-1].get("details") or {}
    if details.get("recovery_status") != "landing_confirmed":
        return False, (
            f"recovery_status is {details.get('recovery_status')!r}, expected landing_confirmed"
        )
    if details.get("recovery_error_type") is not None:
        return False, f"recovery_error_type is {details.get('recovery_error_type')!r}"
    if INJECTED_ERROR not in str(details.get("error", "")):
        return False, "injected error not preserved in audit details"
    return True, "injected failure recovered with landing_confirmed"
