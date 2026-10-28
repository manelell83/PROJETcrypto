"""Generator-side registry API: register a stream with its trap and synthetic secrets."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from canary_qday.common.redact import token_hash, token_id
from canary_qday.common.store import SecretRow, Store, StreamRow
from canary_qday.traffic.traps import SECRET_KINDS, new_fake_secret, new_token, trap_url

SECRET_LIFETIME_S = 7 * 24 * 3600


@dataclass
class IssuedStream:
    """Everything the generator needs to put into a stream's payload.

    Holds secret values in memory only; they are sent inside the encrypted
    channel and never written to the registry or logs.
    """

    stream_id: str
    token: str = field(repr=False)
    trap_url: str = field(repr=False)
    credentials: dict[str, str] = field(repr=False, default_factory=dict)


def register_stream(
    store: Store,
    *,
    profile: str,
    params_id: str,
    key_id: str,
    epoch: int,
    services: list[str],
    canary_base_url: str,
    now: float | None = None,
    kinds: tuple[str, ...] = ("api_key", "db_password"),
) -> IssuedStream:
    """Register a stream, one unique trap token and one fake secret per kind and service."""
    now = time.time() if now is None else now
    stream_id = str(uuid.uuid4())
    token = new_token()
    creds: dict[str, str] = {}
    secret_ids: list[str] = []
    rows: list[tuple[SecretRow, str]] = []
    for svc in services:
        for kind in kinds:
            value = new_fake_secret(kind)
            sid = str(uuid.uuid4())
            secret_ids.append(sid)
            creds[f"{svc}.{kind}"] = value
            rows.append(
                (
                    SecretRow(
                        sid,
                        stream_id,
                        svc,
                        kind,
                        SECRET_KINDS[kind],
                        now,
                        now + SECRET_LIFETIME_S,
                        "active",
                        None,
                    ),
                    value,
                )
            )
    store.add_stream(
        StreamRow(stream_id, profile, params_id, key_id, epoch, now, None, services, secret_ids)
    )
    for row, value in rows:
        store.add_secret(row, value)
    store.add_token(token_hash(token), token_id(token), stream_id, now)
    return IssuedStream(stream_id, token, trap_url(canary_base_url, token), creds)
