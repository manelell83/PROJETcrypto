"""ChaCha20-Poly1305 (RFC 8439) with a 96-bit per-direction counter nonce."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from canary_qday.common.errors import AuthError, FrameError, ReplayError

MAX_SEQ = (1 << 64) - 1


def nonce_for(seq: int) -> bytes:
    """96-bit nonce: 4 zero bytes || 64-bit big-endian sequence number."""
    return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")


class Sealer:
    """Encrypts outgoing records; the counter only moves forward, so nonces never repeat."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._seq = 0

    def seal(self, plaintext: bytes, aad_prefix: bytes) -> tuple[int, bytes]:
        """Return (seq, ciphertext||tag). aad = aad_prefix || seq."""
        if self._seq > MAX_SEQ:
            raise FrameError("sequence number exhausted")
        seq = self._seq
        self._seq += 1
        aad = aad_prefix + seq.to_bytes(8, "big")
        return seq, self._aead.encrypt(nonce_for(seq), plaintext, aad)


class Opener:
    """Decrypts incoming records, accepting only the next expected sequence number."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._expected = 0

    def open(self, seq: int, ciphertext: bytes, aad_prefix: bytes) -> bytes:
        """Verify and decrypt; replayed or reordered records are rejected."""
        if seq != self._expected:
            raise ReplayError("unexpected sequence number")
        aad = aad_prefix + seq.to_bytes(8, "big")
        try:
            pt = self._aead.decrypt(nonce_for(seq), ciphertext, aad)
        except InvalidTag:
            raise AuthError("record authentication failed") from None
        self._expected += 1
        return pt
