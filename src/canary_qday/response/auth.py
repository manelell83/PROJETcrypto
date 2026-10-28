"""Webhook authentication (spec 7.3).

Two implementations of AlertAuthenticator:
  * HmacHeader: X-Signature = hex HMAC-SHA256(secret, ts || "." || body), X-Timestamp,
    +-120 s window, replay cache on the signature. Used by the mock SIEM and any
    sender able to set headers (e.g. a Splunk custom alert action).
  * SharedSecretPath: secret in the URL path, compared in constant time, plus a
    freshness check on the alert's own timestamp. For Splunk's native webhook,
    which cannot add custom headers; must be combined with network isolation.
Both reject replays by alert_id in the engine (E_REPLAY).
"""

from __future__ import annotations

import hmac
import time
from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from canary_qday.common.errors import AuthError, ReplayError, StaleError
from canary_qday.common.sig import sign_hmac

WINDOW_S = 120
__all__ = ["AlertAuthenticator", "HmacHeader", "SharedSecretPath", "check_alert_ts", "sign_hmac"]


class AlertAuthenticator(Protocol):
    """Verifies that an alert really comes from the SIEM and is fresh."""

    def verify(
        self, headers: Mapping[str, str], body: bytes, path_secret: str | None, now: float
    ) -> None:
        """Raise AuthError / StaleError / ReplayError, or return None if acceptable."""
        ...


class HmacHeader:
    """HMAC over timestamp and body, with a bounded nonce cache."""

    def __init__(self, secret: bytes, window_s: int = WINDOW_S, cache: int = 10_000) -> None:
        if len(secret) < 32:
            raise ValueError("webhook secret must be >= 32 bytes")
        self._secret = secret
        self._window = window_s
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._cache = cache

    def __repr__(self) -> str:
        return "HmacHeader(<redacted>)"

    def verify(
        self, headers: Mapping[str, str], body: bytes, path_secret: str | None, now: float
    ) -> None:
        """Check signature, then timestamp window, then replay."""
        lower = {k.lower(): v for k, v in headers.items()}
        ts, sig = lower.get("x-timestamp"), lower.get("x-signature")
        if not ts or not sig or not ts.isdigit() or len(sig) != 64:
            raise AuthError("missing or malformed signature headers")
        if not hmac.compare_digest(sign_hmac(self._secret, ts, body), sig):
            raise AuthError("bad signature")
        if abs(now - int(ts)) > self._window:
            raise StaleError("timestamp outside window")
        if sig in self._seen:
            raise ReplayError("signature already used")
        self._seen[sig] = now
        while len(self._seen) > self._cache:
            self._seen.popitem(last=False)


class SharedSecretPath:
    """Secret URL path segment; freshness from the alert body's `ts` field."""

    def __init__(self, secret: str, window_s: int = 600) -> None:
        if len(secret) < 32:
            raise ValueError("path secret must be >= 32 chars")
        self._secret = secret
        self._window = window_s

    def __repr__(self) -> str:
        return "SharedSecretPath(<redacted>)"

    def verify(
        self, headers: Mapping[str, str], body: bytes, path_secret: str | None, now: float
    ) -> None:
        """Constant-time path comparison; staleness is checked by check_alert_ts."""
        if path_secret is None or not hmac.compare_digest(
            path_secret.encode(), self._secret.encode()
        ):
            raise AuthError("bad path secret")


def check_alert_ts(ts: str, now: float | None = None, window_s: int = 600) -> None:
    """Reject alerts whose own timestamp is too old or in the future."""
    now = time.time() if now is None else now
    try:
        t = datetime.fromisoformat(ts).timestamp()
    except ValueError:
        raise StaleError("bad alert timestamp") from None
    if abs(now - t) > window_s:
        raise StaleError("alert timestamp outside window")
