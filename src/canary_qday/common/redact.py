"""Redaction helpers: identifiers that are safe to log instead of secrets."""

from __future__ import annotations

import hashlib
import re
from typing import Any

SENSITIVE_KEYS = frozenset(
    {
        "token",
        "secret",
        "secrets",
        "password",
        "api_key",
        "credentials",
        "dk",
        "sk",
        "ss",
        "session_key",
        "key",
        "plaintext",
        "payload",
        "hec_token",
        "authorization",
        "x-signature",
    }
)
REDACTED = "<redacted>"
_TOKEN_RE = re.compile(r"/t/[0-9a-f]{32}")
_FAKE_RE = re.compile(r"FAKE-[A-Za-z0-9_-]{8,}")


def token_id(token: str) -> str:
    """Truncated SHA-256 of a trap token (8 hex chars), safe to log."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


def token_hash(token: str) -> str:
    """Full SHA-256 of a trap token, used as the registry lookup key."""
    return hashlib.sha256(token.encode()).hexdigest()


def redact(obj: Any) -> Any:
    """Return a copy of obj with sensitive fields and token-like substrings masked."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if str(k).lower() in SENSITIVE_KEYS else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list | tuple):
        return [redact(v) for v in obj]
    if isinstance(obj, bytes):
        return REDACTED
    if isinstance(obj, str):
        return _FAKE_RE.sub("FAKE-" + REDACTED, _TOKEN_RE.sub("/t/" + REDACTED, obj))
    return obj
