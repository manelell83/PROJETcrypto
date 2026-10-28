"""SiemSink interface: everything that ships events goes through it, so the SIEM stays swappable."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class SiemSink(Protocol):
    """Destination for security events."""

    def send(self, event: BaseModel) -> None:
        """Ship one event. Must not raise on transient SIEM failure (buffer instead)."""
        ...

    def flush(self) -> int:
        """Retry buffered events; return how many are still pending."""
        ...


def make_sink(kind: str, **kwargs: object) -> SiemSink:
    """Factory: 'file' or 'hec'."""
    if kind == "file":
        from canary_qday.siem.file_sink import FileSink

        return FileSink(**kwargs)  # type: ignore[arg-type]
    if kind == "hec":
        from canary_qday.siem.splunk_hec import SplunkHecSink

        return SplunkHecSink(**kwargs)  # type: ignore[arg-type]
    raise ValueError("unknown sink kind")
