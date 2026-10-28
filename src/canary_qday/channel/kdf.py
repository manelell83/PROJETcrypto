"""Session key derivation: HKDF-SHA256 (RFC 5869) with the profile bound in info."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LABEL = b"canary-qday/v1"


@dataclass(frozen=True)
class SessionKeys:
    """Directional AEAD keys. Never log or serialise instances of this class."""

    c2s: bytes
    s2c: bytes

    def __repr__(self) -> str:
        return "SessionKeys(<redacted>)"


def transcript_hash(*parts: bytes) -> bytes:
    """SHA-256 over length-prefixed parts, so concatenation is unambiguous."""
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def derive_session_keys(ss: bytes, profile_id: int, transcript: bytes) -> SessionKeys:
    """K = HKDF-SHA256(ss, salt=empty, info=LABEL || profile_id || H(transcript))."""
    if len(transcript) != 32:
        raise ValueError("transcript must be a 32-byte hash")
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=LABEL + bytes([profile_id]) + transcript,
    ).derive(ss)
    return SessionKeys(okm[:32], okm[32:])
