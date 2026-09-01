from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID


def default_audit_directory() -> Path:
    """Return Nightjar's absolute, platform-appropriate audit directory."""
    if os.name == "nt":
        configured_base = os.environ.get("LOCALAPPDATA")
        base = Path(configured_base) if configured_base else Path.home() / "AppData" / "Local"
    else:
        configured_base = os.environ.get("XDG_STATE_HOME")
        base = Path(configured_base) if configured_base else Path.home() / ".local" / "state"

    return (base.expanduser() / "nightjar" / "audit").resolve()


def write_audit_record(
    *,
    mission_id: UUID,
    event: str,
    details: dict[str, Any],
    log_directory: Path | None = None,
) -> Path:
    """Write one audit record, raising on any failure.

    This is the strict primitive. It gates everything that happens before the
    vehicle can move: if Nightjar cannot record that a flight is starting, the
    flight must not start.
    """
    directory = (
        default_audit_directory() if log_directory is None else log_directory.expanduser().resolve()
    )
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    record = {
        "timestamp_utc": timestamp.isoformat(),
        "mission_id": str(mission_id),
        "event": event,
        "details": details,
    }

    path = directory / f"{mission_id}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")

    return path


def write_audit_record_best_effort(
    *,
    mission_id: UUID,
    event: str,
    details: dict[str, Any],
    log_directory: Path | None = None,
) -> Path | None:
    """Write one audit record without propagating ordinary writer failures.

    Used only once the vehicle may be airborne. Past that point an
    observability failure must not interrupt flight control, so any
    ``Exception`` from the writer is reported to stderr and swallowed. Returns
    the record path on success and ``None`` on failure.

    ``Exception`` is caught rather than ``OSError`` so that a serialization
    error cannot strand an aircraft either. ``BaseException`` is deliberately
    not caught: interruption and recovery are a separate boundary.
    """
    try:
        return write_audit_record(
            mission_id=mission_id,
            event=event,
            details=details,
            log_directory=log_directory,
        )
    except Exception as exc:  # noqa: BLE001 - broad catch is the safety boundary
        _emit_audit_fallback(mission_id=mission_id, event=event, exc=exc)
        return None


def _emit_audit_fallback(*, mission_id: UUID, event: str, exc: BaseException) -> None:
    """Report a lost audit record to stderr.

    Deliberately austere: mission ID, event, and exception type only. The
    record's ``details`` and the exception message are both omitted, since
    either may carry operator-selected coordinates or filesystem paths. The
    emit itself is wrapped so the fallback can never become a second failure
    site.
    """
    line = (
        f"nightjar-audit-fallback mission_id={mission_id} "
        f"event={event} error_type={type(exc).__name__}"
    )
    try:
        print(line, file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 - fallback output must never become a second failure
        return
