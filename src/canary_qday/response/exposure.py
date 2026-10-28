"""Exposure computation (spec 7.5).

* key-level exposure: every stream encrypted to the same key_id (the attacker
  holds that private key);
* algorithmic exposure: every stream using the same params_id (the attacker can
  repeat the attack on the other keys of that parameter set).

The past cannot be fixed: payloads of exposed streams that were captured must
be considered disclosed. What can be neutralised are the secrets they carried
(rotation) and future traffic (profile switch).
"""

from __future__ import annotations

from dataclasses import dataclass

from canary_qday.common.store import SecretRow, Store, StreamRow


@dataclass(frozen=True)
class Exposure:
    """Result of an exposure computation."""

    key_level: tuple[str, ...]
    algorithmic: tuple[str, ...]  # includes key_level
    window_start: float | None
    window_end: float
    to_rotate: tuple[SecretRow, ...]  # prioritised, active and not expired
    skipped_expired: tuple[str, ...]
    already_inactive: tuple[str, ...]


def priority(secret: SecretRow, now: float) -> float:
    """sensitivity x remaining lifetime (seconds)."""
    return secret.sensitivity * max(0.0, secret.expires_at - now)


def compute(store: Store, *, key_id: str, params_id: str, now: float) -> Exposure:
    """Compute both exposure sets and the prioritised rotation list."""
    key_streams: list[StreamRow] = store.streams(key_id=key_id)
    algo_streams: list[StreamRow] = store.streams(params_id=params_id)
    key_ids = tuple(s.stream_id for s in key_streams)
    algo_ids = tuple(sorted({s.stream_id for s in algo_streams} | set(key_ids)))
    start = min((s.started_at for s in algo_streams), default=None)
    secrets = store.secrets_for_streams(list(algo_ids))
    key_set = set(key_ids)
    active = [s for s in secrets if s.status == "active" and s.expires_at > now]
    expired = tuple(s.secret_id for s in secrets if s.status == "active" and s.expires_at <= now)
    inactive = tuple(s.secret_id for s in secrets if s.status != "active")
    # Key-level secrets first (certainly exposed), then by sensitivity x remaining lifetime.
    active.sort(key=lambda s: (s.stream_id not in key_set, -priority(s, now), s.secret_id))
    return Exposure(key_ids, algo_ids, start, now, tuple(active), expired, inactive)
