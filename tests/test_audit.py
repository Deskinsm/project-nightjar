import json
from pathlib import Path
from uuid import uuid4

import pytest

from nightjar.audit import (
    default_audit_directory,
    write_audit_record,
    write_audit_record_best_effort,
)


def test_default_audit_directory_is_absolute() -> None:
    assert default_audit_directory().is_absolute()


def test_write_audit_record_uses_injected_directory(tmp_path) -> None:
    mission_id = uuid4()
    audit_directory = tmp_path / "nested" / "audit"

    path = write_audit_record(
        mission_id=mission_id,
        event="test_event",
        details={"result": "success"},
        log_directory=audit_directory,
    )

    expected_path = audit_directory.resolve() / f"{mission_id}.jsonl"

    assert path == expected_path
    assert path.exists()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["mission_id"] == str(mission_id)
    assert record["event"] == "test_event"
    assert record["details"] == {"result": "success"}
    assert record["timestamp_utc"]


# --- Strict primitive stays strict ------------------------------------------


def test_strict_writer_raises_when_directory_is_a_file(tmp_path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    with pytest.raises(OSError):
        write_audit_record(
            mission_id=uuid4(),
            event="test_event",
            details={},
            log_directory=blocker,
        )


# --- Best-effort wrapper ------------------------------------------------------


def test_best_effort_returns_path_and_writes_on_success(tmp_path) -> None:
    mission_id = uuid4()

    path = write_audit_record_best_effort(
        mission_id=mission_id,
        event="test_event",
        details={"result": "success"},
        log_directory=tmp_path,
    )

    assert path is not None
    assert path.exists()
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert record["event"] == "test_event"


def test_best_effort_swallows_real_filesystem_failure(tmp_path, capsys) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    mission_id = uuid4()

    path = write_audit_record_best_effort(
        mission_id=mission_id,
        event="action_completed",
        details={"sequence": 2},
        log_directory=blocker,
    )

    assert path is None

    stderr = capsys.readouterr().err
    assert "nightjar-audit-fallback" in stderr
    assert f"mission_id={mission_id}" in stderr
    assert "event=action_completed" in stderr


def test_best_effort_swallows_patched_writer_failure(monkeypatch, capsys) -> None:
    def failing_writer(**kwargs) -> Path:
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr("nightjar.audit.write_audit_record", failing_writer)

    path = write_audit_record_best_effort(
        mission_id=uuid4(),
        event="action_started",
        details={},
    )

    assert path is None
    assert "error_type=RuntimeError" in capsys.readouterr().err


def test_best_effort_swallows_non_oserror_failure(monkeypatch, capsys) -> None:
    """A serialization error is not an OSError and must still be swallowed."""

    def type_error_writer(**kwargs) -> Path:
        raise TypeError("Object of type set is not JSON serializable")

    monkeypatch.setattr("nightjar.audit.write_audit_record", type_error_writer)

    path = write_audit_record_best_effort(
        mission_id=uuid4(),
        event="action_completed",
        details={},
    )

    assert path is None
    assert "error_type=TypeError" in capsys.readouterr().err


def test_best_effort_fallback_omits_details_and_exception_message(monkeypatch, capsys) -> None:
    detail_sentinel = "DETAIL-45.4871"
    message_sentinel = "MESSAGE-/home/operator/audit"

    def failing_writer(**kwargs) -> Path:
        raise RuntimeError(message_sentinel)

    monkeypatch.setattr("nightjar.audit.write_audit_record", failing_writer)

    write_audit_record_best_effort(
        mission_id=uuid4(),
        event="action_started",
        details={"north_m": detail_sentinel},
    )

    stderr = capsys.readouterr().err
    assert detail_sentinel not in stderr
    assert message_sentinel not in stderr
