"""Trap tokens and synthetic credentials embedded in generated payloads."""

from __future__ import annotations

import re
import secrets

TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")

SECRET_KINDS: dict[str, int] = {
    # kind -> sensitivity (1 low .. 5 critical)
    "api_key": 3,
    "db_password": 5,
    "session_cookie": 2,
}


def new_token() -> str:
    """A 128-bit random trap token, hex encoded."""
    return secrets.token_hex(16)


def is_token(value: str) -> bool:
    """True if value has the exact shape of a trap token."""
    return bool(TOKEN_RE.fullmatch(value))


def new_fake_secret(kind: str) -> str:
    """A synthetic credential, clearly marked FAKE so it can never be mistaken for a real one."""
    if kind not in SECRET_KINDS:
        raise ValueError("unknown secret kind")
    return f"FAKE-{kind}-{secrets.token_urlsafe(18)}"


def trap_url(base_url: str, token: str) -> str:
    """The canary URL embedded in the payload."""
    return f"{base_url.rstrip('/')}/t/{token}"
