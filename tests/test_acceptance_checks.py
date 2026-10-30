from __future__ import annotations

import json
from pathlib import Path

from nightjar.acceptance_checks import (
    INJECTED_ERROR,
    controlled_failure_recovered,
    replay_rejected,
    signed_mission_passed,
)


def _write_audit(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def test_signed_mission_requires_exit_zero_and_audit(tmp_path: Path) -> None:
    audit = tmp_path / "m.jsonl"
    _write_audit(audit, [{"event": "mission_completed", "details": {}}])

    ok, detail = signed_mission_passed(
        exit_code=0,
        stdout="MAVSDK simulation complete. Audit log: ...",
        audit_path=audit,
    )
    assert ok, detail

    # Connection failure must not pass.
    ok, detail = signed_mission_passed(
        exit_code=5,
        stdout="Execution failed: Timed out waiting for PX4.",
        audit_path=audit,
    )
    assert not ok
    assert "exit code" in detail

    # Missing audit must not pass.
    ok, detail = signed_mission_passed(
        exit_code=0,
        stdout="MAVSDK simulation complete.",
        audit_path=None,
    )
    assert not ok
    assert "audit" in detail


def test_replay_requires_already_used_and_no_audit(tmp_path: Path) -> None:
    ok, detail = replay_rejected(
        exit_code=4,
        stdout="Execution blocked: Approval nonce has already been used.",
        audit_path=None,
    )
    assert ok, detail

    # Unrelated authorization error must not pass.
    ok, detail = replay_rejected(
        exit_code=4,
        stdout="Execution blocked: Approval signature is invalid.",
        audit_path=None,
    )
    assert not ok
    assert "already" in detail

    # An audit file means system creation may have occurred.
    audit = tmp_path / "m.jsonl"
    _write_audit(audit, [{"event": "mission_started", "details": {}}])
    ok, detail = replay_rejected(
        exit_code=4,
        stdout="Execution blocked: Approval nonce has already been used.",
        audit_path=audit,
    )
    assert not ok
    assert "audit" in detail


def test_malformed_audit_is_a_failure_not_an_exception(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not valid json\n", encoding="utf-8")

    ok, detail = signed_mission_passed(
        exit_code=0,
        stdout="MAVSDK simulation complete.",
        audit_path=bad,
    )
    assert not ok
    assert "parsed" in detail

    ok, detail = controlled_failure_recovered(
        exit_code=5,
        stdout=f"Execution failed: {INJECTED_ERROR}",
        audit_path=bad,
    )
    assert not ok
    assert "parsed" in detail


def test_controlled_failure_requires_landing_confirmed(tmp_path: Path) -> None:
    audit = tmp_path / "m.jsonl"
    _write_audit(
        audit,
        [
            {
                "event": "mission_failed",
                "details": {
                    "error": INJECTED_ERROR,
                    "recovery_status": "landing_confirmed",
                    "recovery_error_type": None,
                },
            }
        ],
    )
    ok, detail = controlled_failure_recovered(
        exit_code=5,
        stdout=f"Execution failed: {INJECTED_ERROR}",
        audit_path=audit,
    )
    assert ok, detail

    # Connection failure (no recovery) must not pass.
    bad_audit = tmp_path / "bad.jsonl"
    _write_audit(
        bad_audit,
        [
            {
                "event": "mission_failed",
                "details": {
                    "error": "Timed out waiting for PX4.",
                    "recovery_status": "not_required",
                    "recovery_error_type": None,
                },
            }
        ],
    )
    ok, detail = controlled_failure_recovered(
        exit_code=5,
        stdout="Execution failed: Timed out waiting for PX4.",
        audit_path=bad_audit,
    )
    assert not ok

    # Failed recovery must not pass.
    failed_recovery = tmp_path / "failed.jsonl"
    _write_audit(
        failed_recovery,
        [
            {
                "event": "mission_failed",
                "details": {
                    "error": INJECTED_ERROR,
                    "recovery_status": "failed",
                    "recovery_error_type": "MavsdkExecutorError",
                },
            }
        ],
    )
    ok, detail = controlled_failure_recovered(
        exit_code=5,
        stdout=f"Execution failed: {INJECTED_ERROR}",
        audit_path=failed_recovery,
    )
    assert not ok
    assert "recovery_status" in detail or "recovery_error" in detail

    # Missing audit must not pass.
    ok, detail = controlled_failure_recovered(
        exit_code=5,
        stdout=f"Execution failed: {INJECTED_ERROR}",
        audit_path=None,
    )
    assert not ok
    assert "audit" in detail
