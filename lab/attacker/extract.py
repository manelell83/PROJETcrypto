"""Extract the public attacker-visible fields from a capture file (M8 increment 3).

Reads a JSONL capture written by `capture.CaptureWriter` and returns the public
handshake material: profile, epoch, key_id, `ek`, `stream_id`, `ct`, and the
AEAD-encrypted DATA records. It does **not** decrypt anything and does not solve
the KEM; that is a later increment.

The capture is treated as hostile input: every line and every frame is parsed
through `channel.framing`/`channel.handshake`, which validate version, length,
type and field sizes. Anything malformed raises `ExtractError`; the function
never raises a raw parser error and never returns partial or unverified data.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from canary_qday.channel import framing
from canary_qday.channel.framing import FrameType
from canary_qday.channel.handshake import parse_hello, parse_key_response
from canary_qday.common.errors import CanaryError

#: Hard caps so a malicious capture cannot exhaust memory.
MAX_FRAMES = 100_000
MAX_LINE_CHARS = 4 * (framing.MAX_BODY + 16)


class ExtractError(ValueError):
    """The capture is malformed or incomplete."""


@dataclass(frozen=True)
class CapturedStream:
    """Public fields an attacker can read off the wire for one stream."""

    profile: str
    epoch: int
    key_id: bytes
    ek: bytes
    stream_id: bytes
    ct: bytes
    data_records: list[tuple[int, bytes]]


def _frames(capture_path: Path) -> Iterator[framing.Frame]:
    with capture_path.open(encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            if index >= MAX_FRAMES:
                raise ExtractError("capture has too many frames")
            text = line.strip()
            if not text:
                continue
            if len(text) > MAX_LINE_CHARS:
                raise ExtractError("capture line too long")
            try:
                record = json.loads(text)
                raw = bytes.fromhex(record["frame_hex"])
            except (ValueError, KeyError, TypeError):
                raise ExtractError("malformed capture line") from None
            try:
                frame, rest = framing.decode(raw)
            except CanaryError as err:
                raise ExtractError(f"invalid frame: {err}") from None
            if rest:
                raise ExtractError("trailing bytes after frame")
            yield frame


def extract(capture_path: Path) -> CapturedStream:
    """Parse a capture and return its public fields, or raise ExtractError."""
    key_response: tuple[str, int, bytes, bytes] | None = None
    hello = None
    data: list[tuple[int, bytes]] = []
    for frame in _frames(capture_path):
        try:
            if frame.type is FrameType.KEY_RESPONSE:
                key_response = parse_key_response(frame)
            elif frame.type is FrameType.HELLO:
                hello = parse_hello(frame)
            elif frame.type is FrameType.DATA:
                data.append(framing.unpack_data(frame.payload))
        except CanaryError as err:
            raise ExtractError(f"invalid {frame.type.name}: {err}") from None

    if key_response is None:
        raise ExtractError("no KEY_RESPONSE (ek) in capture")
    if hello is None:
        raise ExtractError("no HELLO (ct) in capture")
    profile, epoch, key_id, ek = key_response
    if hello.key_id != key_id:
        raise ExtractError("HELLO and KEY_RESPONSE key_id disagree")
    if hello.profile != profile:
        raise ExtractError("HELLO and KEY_RESPONSE profile disagree")
    return CapturedStream(profile, epoch, key_id, ek, hello.stream_id, hello.ct, data)
