"""HMAC signature shared by the alert sender (SIEM) and receiver (response engine)."""

from __future__ import annotations

import hashlib
import hmac


def sign_hmac(secret: bytes, ts: str, body: bytes) -> str:
    """hex HMAC-SHA256(secret, ts || "." || body)."""
    return hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
