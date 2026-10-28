"""Lab-only TCP capture relay for the attacker (M8 increment 3).

This is **not** tcpdump/scapy + pcap: a small asyncio relay that sits between the
traffic generator and the proxy, forwards every frame unchanged, and records it.
Documented deviation from the spec (same captured content, different transport;
see docs/m8-status.md).

It records only what already travels on the wire -- the public key `ek`
(KEY_RESPONSE), the KEM ciphertext `ct` and stream id (HELLO), and the
AEAD-encrypted DATA payloads. It never sees or writes a private key, shared
secret, session key or plaintext: none of those cross the relay.

`guard.require_lab()` runs before any socket is opened.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from canary_qday.channel import framing
from canary_qday.common.errors import FrameError
from lab.attacker.guard import require_lab


class CaptureWriter:
    """Append framed messages to a 0600 JSONL capture file (one frame per line)."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self._fh = os.fdopen(fd, "w", encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)

    def record(self, direction: str, frame: framing.Frame) -> None:
        """Store one frame as {dir, frame_hex} (full length-prefixed bytes)."""
        raw = framing.encode(frame.type, frame.payload)
        self._fh.write(json.dumps({"dir": direction, "frame_hex": raw.hex()}) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class Relay:
    """Forward frames between a client and the proxy, recording each one."""

    def __init__(self, proxy_host: str, proxy_port: int, capture_path: Path, profile: str) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.capture_path = capture_path
        self.profile = profile

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        cap: CaptureWriter,
    ) -> None:
        try:
            while True:
                frame = await framing.read_frame(reader)
                cap.record(direction, frame)
                writer.write(framing.encode(frame.type, frame.payload))
                await writer.drain()
        except (FrameError, ConnectionError):
            pass  # clean EOF or peer reset: stop this direction
        finally:
            writer.close()

    async def _handle(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        cap: CaptureWriter,
    ) -> None:
        proxy_reader, proxy_writer = await asyncio.open_connection(
            self.proxy_host, self.proxy_port
        )
        await asyncio.gather(
            self._pump(client_reader, proxy_writer, "c2s", cap),
            self._pump(proxy_reader, client_writer, "s2c", cap),
        )

    async def start(
        self, host: str, port: int
    ) -> tuple[asyncio.AbstractServer, CaptureWriter]:
        """Guard, then open the capture file and start listening on (host, port)."""
        require_lab(self.profile, self.proxy_host)  # before any socket is opened
        cap = CaptureWriter(self.capture_path)

        async def on_client(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            await self._handle(r, w, cap)

        server = await asyncio.start_server(on_client, host, port)
        return server, cap
