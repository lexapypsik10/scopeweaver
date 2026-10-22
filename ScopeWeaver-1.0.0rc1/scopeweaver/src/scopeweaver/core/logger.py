from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL. Open failure aborts the run; no silent unaudited activity."""

    def __init__(self, path: Path, run_id: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._stream = os.fdopen(os.open(path, flags, 0o600), "a", encoding="utf-8")
        self.run_id = run_id

    def event(self, action: str, **fields: Any) -> None:
        record = {
            "time": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "action": action,
            **fields,
        }
        self._stream.write(json.dumps(record, ensure_ascii=True) + "\n")
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()
