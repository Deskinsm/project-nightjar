from __future__ import annotations

import json
import os
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
