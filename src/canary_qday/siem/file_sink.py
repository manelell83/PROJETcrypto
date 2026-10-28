"""Append-only JSONL sink (fallback SIEM, and the source for offline analysis)."""

from __future__ import annotations

import threading
from pathlib import Path

from pydantic import BaseModel

from canary_qday.siem.schemas import to_json


class FileSink:
    """Writes one sorted-key JSON event per line."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def send(self, event: BaseModel) -> None:
        """Append the event."""
        line = to_json(event) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def flush(self) -> int:
        """Nothing is ever buffered."""
        return 0
