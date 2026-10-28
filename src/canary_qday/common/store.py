"""SQLite registry of streams, issued (fake) secrets and trap tokens.

Lives in `common` because both the generator (writer) and the response engine
(reader/rotator) need it, and the response engine must not depend on traffic/kem.
Secret *values* are never stored: only a SHA-256 hash, to let backend stubs
check whether a presented credential is still active.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS streams (
  stream_id TEXT PRIMARY KEY, profile TEXT NOT NULL, params_id TEXT NOT NULL,
  key_id TEXT NOT NULL, epoch INTEGER NOT NULL, started_at REAL NOT NULL,
  ended_at REAL, services TEXT NOT NULL, secrets_issued TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_streams_key ON streams(key_id);
CREATE INDEX IF NOT EXISTS ix_streams_params ON streams(params_id);
CREATE INDEX IF NOT EXISTS ix_streams_profile_epoch ON streams(profile, epoch);
CREATE TABLE IF NOT EXISTS secrets (
  secret_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL, service TEXT NOT NULL,
  kind TEXT NOT NULL, sensitivity INTEGER NOT NULL, value_hash TEXT NOT NULL,
  issued_at REAL NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL,
  replaced_by TEXT
);
CREATE INDEX IF NOT EXISTS ix_secrets_hash ON secrets(value_hash);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY, token_id TEXT NOT NULL, stream_id TEXT NOT NULL,
  created_at REAL NOT NULL, allowlisted INTEGER NOT NULL DEFAULT 0
);
"""


def value_hash(value: str) -> str:
    """SHA-256 of a secret value (never store the value itself)."""
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class StreamRow:
    """A registered stream."""

    stream_id: str
    profile: str
    params_id: str
    key_id: str
    epoch: int
    started_at: float
    ended_at: float | None
    services: list[str]
    secrets_issued: list[str]


@dataclass(frozen=True)
class SecretRow:
    """An issued synthetic secret (metadata only)."""

    secret_id: str
    stream_id: str
    service: str
    kind: str
    sensitivity: int
    issued_at: float
    expires_at: float
    status: str
    replaced_by: str | None


class Store:
    """Thin DAO over the registry database."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # -- writes -------------------------------------------------------------
    def add_stream(self, row: StreamRow) -> None:
        """Insert a stream."""
        with self._conn() as c:
            c.execute(
                "INSERT INTO streams VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    row.stream_id,
                    row.profile,
                    row.params_id,
                    row.key_id,
                    row.epoch,
                    row.started_at,
                    row.ended_at,
                    json.dumps(row.services),
                    json.dumps(row.secrets_issued),
                ),
            )

    def end_stream(self, stream_id: str, ended_at: float) -> None:
        """Set ended_at."""
        with self._conn() as c:
            c.execute("UPDATE streams SET ended_at=? WHERE stream_id=?", (ended_at, stream_id))

    def add_secret(self, row: SecretRow, value: str) -> None:
        """Insert a secret's metadata and hash."""
        with self._conn() as c:
            c.execute(
                "INSERT INTO secrets VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    row.secret_id,
                    row.stream_id,
                    row.service,
                    row.kind,
                    row.sensitivity,
                    value_hash(value),
                    row.issued_at,
                    row.expires_at,
                    row.status,
                    row.replaced_by,
                ),
            )

    def add_token(
        self, token_hash: str, token_id: str, stream_id: str, now: float, allowlisted: bool = False
    ) -> None:
        """Insert a trap token (hash only)."""
        with self._conn() as c:
            c.execute(
                "INSERT INTO tokens VALUES (?,?,?,?,?)",
                (token_hash, token_id, stream_id, now, int(allowlisted)),
            )

    def rotate_secret(self, secret_id: str, new: SecretRow, new_value: str) -> bool:
        """Revoke secret_id and insert its replacement atomically.

        Returns False (and changes nothing) if the secret is no longer active,
        which makes rotation idempotent.
        """
        with self._conn() as c:
            cur = c.execute(
                "UPDATE secrets SET status='revoked', replaced_by=? "
                "WHERE secret_id=? AND status='active'",
                (new.secret_id, secret_id),
            )
            if cur.rowcount == 0:
                return False
            c.execute(
                "INSERT INTO secrets VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    new.secret_id,
                    new.stream_id,
                    new.service,
                    new.kind,
                    new.sensitivity,
                    value_hash(new_value),
                    new.issued_at,
                    new.expires_at,
                    "active",
                    None,
                ),
            )
            return True

    # -- reads --------------------------------------------------------------
    @staticmethod
    def _stream(r: sqlite3.Row) -> StreamRow:
        return StreamRow(
            r["stream_id"],
            r["profile"],
            r["params_id"],
            r["key_id"],
            r["epoch"],
            r["started_at"],
            r["ended_at"],
            json.loads(r["services"]),
            json.loads(r["secrets_issued"]),
        )

    @staticmethod
    def _secret(r: sqlite3.Row) -> SecretRow:
        return SecretRow(
            r["secret_id"],
            r["stream_id"],
            r["service"],
            r["kind"],
            r["sensitivity"],
            r["issued_at"],
            r["expires_at"],
            r["status"],
            r["replaced_by"],
        )

    def streams(self, **where: Any) -> list[StreamRow]:
        """Streams filtered by equality on profile/params_id/key_id/epoch/stream_id."""
        allowed = {"profile", "params_id", "key_id", "epoch", "stream_id"}
        if not set(where) <= allowed:
            raise ValueError("unsupported filter")
        sql = "SELECT * FROM streams"
        if where:
            sql += " WHERE " + " AND ".join(f"{k}=?" for k in sorted(where))
        with self._conn() as c:
            rows = c.execute(sql + " ORDER BY started_at", [where[k] for k in sorted(where)])
            return [self._stream(r) for r in rows]

    def stream(self, stream_id: str) -> StreamRow | None:
        """One stream or None."""
        rows = self.streams(stream_id=stream_id)
        return rows[0] if rows else None

    def secrets_for_streams(self, stream_ids: list[str]) -> list[SecretRow]:
        """All secrets issued in the given streams (any status)."""
        if not stream_ids:
            return []
        # Justification (bandit B608): only "?" placeholders are interpolated; values are bound.
        marks = ",".join("?" * len(stream_ids))
        with self._conn() as c:
            rows = c.execute(
                f"SELECT * FROM secrets WHERE stream_id IN ({marks}) ORDER BY secret_id",  # noqa: S608  # nosec B608
                stream_ids,
            )
            return [self._secret(r) for r in rows]

    def secret_status_by_value(self, value: str) -> str | None:
        """Status of a presented credential, or None if unknown."""
        with self._conn() as c:
            r = c.execute(
                "SELECT status FROM secrets WHERE value_hash=?", (value_hash(value),)
            ).fetchone()
            return None if r is None else str(r["status"])

    def token(self, token_hash: str) -> tuple[str, str, bool] | None:
        """(token_id, stream_id, allowlisted) for a token hash, or None."""
        with self._conn() as c:
            r = c.execute(
                "SELECT token_id, stream_id, allowlisted FROM tokens WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
            return None if r is None else (r["token_id"], r["stream_id"], bool(r["allowlisted"]))

    def token_by_id(self, token_id: str, stream_id: str) -> tuple[bool] | None:
        """(allowlisted,) for the token of a stream matching token_id, or None."""
        with self._conn() as c:
            r = c.execute(
                "SELECT allowlisted FROM tokens WHERE token_id=? AND stream_id=?",
                (token_id, stream_id),
            ).fetchone()
            return None if r is None else (bool(r["allowlisted"]),)
