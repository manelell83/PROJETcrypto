"""Typed exceptions. Messages must never contain secret material."""

from __future__ import annotations


class CanaryError(Exception):
    """Base class for all project errors."""

    code = "E_INTERNAL"


class FrameError(CanaryError):
    """Malformed, oversized or out-of-order frame."""

    code = "E_FRAME"


class AuthError(CanaryError):
    """AEAD tag or alert signature verification failed."""

    code = "E_SIG_INVALID"


class ReplayError(CanaryError):
    """A frame, handshake or alert was seen before."""

    code = "E_REPLAY"


class StaleError(CanaryError):
    """Timestamp outside the accepted window."""

    code = "E_STALE"


class PolicyError(CanaryError):
    """Request refused by policy (unknown profile, downgrade, missing approval...)."""

    code = "E_POLICY"


class NotFoundError(CanaryError):
    """Unknown incident, stream or key."""

    code = "E_NOT_FOUND"


class ConfigError(CanaryError):
    """Invalid configuration or insecure file permissions."""

    code = "E_CONFIG"


__all__ = [
    "AuthError",
    "CanaryError",
    "ConfigError",
    "FrameError",
    "NotFoundError",
    "PolicyError",
    "ReplayError",
    "StaleError",
]
