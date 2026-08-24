import json

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent

LOG_DIR = BASE_DIR / "logs"

AUDIT_FILE = LOG_DIR / "audit.jsonl"


def log_event(
    event_type: str,
    details: dict[str, Any] | None = None
) -> None:

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    record = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "event_type": event_type,

        "details": details or {}
    }

    with open(
        AUDIT_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(record)
            + "\n"
        )