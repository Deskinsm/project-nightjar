import json
from uuid import uuid4

from nightjar.audit import default_audit_directory, write_audit_record


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
