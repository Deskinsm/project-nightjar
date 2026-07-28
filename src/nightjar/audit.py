from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID


def write_audit_record(
    *,
    mission_id: UUID,
    event: str,
    details: dict[str, Any],
    log_directory: Path = Path("logs"),
) -> Path:
    log_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc)
    record = {
        "timestamp_utc": timestamp.isoformat(),
        "mission_id": str(mission_id),
        "event": event,
        "details": details,
    }
    path = log_directory / f"{mission_id}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return path
