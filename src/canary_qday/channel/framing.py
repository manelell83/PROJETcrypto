"""Length-prefixed frames with a version byte.

Wire format: len (u32 BE, length of body) || body
body = version (u8) || type (u8) || payload

All parsing validates lengths first and raises FrameError on anything odd.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import IntEnum

from canary_qday.common.errors import FrameError

VERSION = 1
MAX_BODY = 64 * 1024


class FrameType(IntEnum):
    """Frame types of the canary channel."""

    KEY_REQUEST = 1  # client -> server: profile_id (u8)
    KEY_RESPONSE = 2  # server -> client: profile_id u8, epoch u32, key_id 8B, ek
    HELLO = 3  # client -> server: profile_id u8, epoch u32, key_id 8B, stream_id 16B, ct
    DATA = 4  # either direction: seq u64, aead ciphertext
    ERROR = 5  # server -> client: short ASCII error code


@dataclass(frozen=True)
class Frame:
    """A parsed frame."""

    type: FrameType
    payload: bytes

    def header(self) -> bytes:
        """version || type, used as AEAD associated data prefix."""
        return bytes([VERSION, self.type])


def encode(ftype: FrameType, payload: bytes) -> bytes:
    """Serialise a frame."""
    body = bytes([VERSION, ftype]) + payload
    if len(body) > MAX_BODY:
        raise FrameError("frame too large")
    return struct.pack(">I", len(body)) + body


def decode_body(body: bytes) -> Frame:
    """Parse a frame body (without the length prefix)."""
    if len(body) < 2 or len(body) > MAX_BODY:
        raise FrameError("bad frame length")
    if body[0] != VERSION:
        raise FrameError("unsupported version")
    try:
        ftype = FrameType(body[1])
    except ValueError:
        raise FrameError("unknown frame type") from None
    return Frame(ftype, body[2:])


def decode(data: bytes) -> tuple[Frame, bytes]:
    """Parse one frame from a buffer; return (frame, remaining bytes)."""
    if len(data) < 4:
        raise FrameError("truncated length")
    (length,) = struct.unpack(">I", data[:4])
    if length > MAX_BODY or length < 2:
        raise FrameError("bad frame length")
    if len(data) < 4 + length:
        raise FrameError("truncated frame")
    return decode_body(data[4 : 4 + length]), data[4 + length :]


async def read_frame(reader: asyncio.StreamReader) -> Frame:
    """Read exactly one frame from a stream."""
    try:
        head = await reader.readexactly(4)
        (length,) = struct.unpack(">I", head)
        if length > MAX_BODY or length < 2:
            raise FrameError("bad frame length")
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise FrameError("connection closed mid-frame") from None
    return decode_body(body)


def pack_data(seq: int, ciphertext: bytes) -> bytes:
    """DATA payload: seq (u64) || ciphertext."""
    return seq.to_bytes(8, "big") + ciphertext


def unpack_data(payload: bytes) -> tuple[int, bytes]:
    """Inverse of pack_data."""
    if len(payload) < 8 + 16:
        raise FrameError("DATA frame too short")
    return int.from_bytes(payload[:8], "big"), payload[8:]
