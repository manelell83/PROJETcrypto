"""Splunk HTTP Event Collector sink.

POST {hec_url}/services/collector/event with header `Authorization: Splunk <token>`.
If the SIEM is unreachable the event is appended to an on-disk buffer and
retried by flush(). The HEC token is read from a Docker secret / env var and
never logged.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import httpx
from pydantic import BaseModel

from canary_qday.common.logging import get_logger, log_event

_log = get_logger("siem.hec")


class SplunkHecSink:
    """Ships events to Splunk HEC (or the mock HEC in CI)."""

    def __init__(
        self,
        hec_url: str,
        token: str,
        buffer_path: Path | str,
        index: str = "canary",
        sourcetype: str = "canary:event",
        verify_tls: bool | str = True,
        timeout: float = 5.0,
    ) -> None:
        self._url = hec_url.rstrip("/") + "/services/collector/event"
        self._headers = {"Authorization": f"Splunk {token}"}
        self._buffer = Path(buffer_path)
        self._buffer.parent.mkdir(parents=True, exist_ok=True)
        self._index = index
        self._sourcetype = sourcetype
        self._verify = verify_tls
        self._timeout = timeout
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"SplunkHecSink(url={self._url!r}, token=<redacted>)"

    def _envelope(self, event: BaseModel) -> str:
        return json.dumps(
            {
                "event": event.model_dump(),
                "index": self._index,
                "sourcetype": self._sourcetype,
                "source": "canary-qday",
            },
            sort_keys=True,
        )

    def _post(self, body: str) -> bool:
        try:
            r = httpx.post(
                self._url,
                content=body,
                headers=self._headers,
                timeout=self._timeout,
                verify=self._verify,
            )
        except httpx.HTTPError:
            return False
        return r.status_code == 200

    def send(self, event: BaseModel) -> None:
        """Send now; on failure append to the disk buffer."""
        body = self._envelope(event)
        if not self._post(body):
            with self._lock, self._buffer.open("a", encoding="utf-8") as fh:
                fh.write(body + "\n")
            log_event(_log, "hec unavailable, event buffered", url=self._url)

    def flush(self) -> int:
        """Retry buffered events in order; keep those that still fail."""
        with self._lock:
            if not self._buffer.exists():
                return 0
            lines = [ln for ln in self._buffer.read_text(encoding="utf-8").splitlines() if ln]
            pending = [ln for ln in lines if not self._post(ln)]
            self._buffer.write_text("".join(p + "\n" for p in pending), encoding="utf-8")
            return len(pending)
