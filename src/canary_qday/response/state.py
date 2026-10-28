"""Response engine's own database (zone Z4): incidents, actions, seen alerts, rate limits.

Kept separate from the registry so that a dry-run, which still records the
incident and its planned actions, leaves the registry and lab policy untouched.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY, alert_id TEXT UNIQUE NOT NULL, created_at REAL NOT NULL,
  profile TEXT NOT NULL, status TEXT NOT NULL, dry_run INTEGER NOT NULL, report TEXT
);
CREATE TABLE IF NOT EXISTS actions (
  idem_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL, kind TEXT NOT NULL,
  mode TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL, ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS rate (
  scope TEXT PRIMARY KEY, last_ts REAL NOT NULL, incident_id TEXT NOT NULL
);
"""


class ResponseState:
    """DAO for the response database."""

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

    def create_incident(
        self, incident_id: str, alert_id: str, now: float, profile: str, dry_run: bool
    ) -> bool:
        """Insert; False if alert_id was already processed (replay)."""
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO incidents VALUES (?,?,?,?,?,?,NULL)",
                    (incident_id, alert_id, now, profile, "open", int(dry_run)),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def set_report(self, incident_id: str, status: str, report: dict[str, Any]) -> None:
        """Store the JSON report and status."""
        with self._conn() as c:
            c.execute(
                "UPDATE incidents SET status=?, report=? WHERE incident_id=?",
                (status, json.dumps(report, sort_keys=True), incident_id),
            )

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        """Incident row with parsed report."""
        with self._conn() as c:
            r = c.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["report"] = json.loads(d["report"]) if d["report"] else None
        return d

    def record_action(
        self,
        idem_key: str,
        incident_id: str,
        kind: str,
        mode: str,
        status: str,
        detail: dict[str, Any],
        now: float,
    ) -> bool:
        """Insert or update an action; returns False if already completed (idempotency)."""
        with self._conn() as c:
            r = c.execute("SELECT status FROM actions WHERE idem_key=?", (idem_key,)).fetchone()
            if r is not None and r["status"] in ("done", "noop"):
                return False
            c.execute(
                "INSERT OR REPLACE INTO actions VALUES (?,?,?,?,?,?,?)",
                (
                    idem_key,
                    incident_id,
                    kind,
                    mode,
                    status,
                    json.dumps(detail, sort_keys=True),
                    now,
                ),
            )
            return True

    def actions(self, incident_id: str) -> list[dict[str, Any]]:
        """All actions of an incident."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM actions WHERE incident_id=? ORDER BY ts, kind", (incident_id,)
            ).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]

    def rate_check(self, scope: str, now: float, window_s: float, incident_id: str) -> str | None:
        """If scope ran within window_s, return the incident that covered it; else claim it."""
        with self._conn() as c:
            r = c.execute(
                "SELECT last_ts, incident_id FROM rate WHERE scope=?", (scope,)
            ).fetchone()
            if r is not None and now - r["last_ts"] < window_s:
                return str(r["incident_id"])
            c.execute("INSERT OR REPLACE INTO rate VALUES (?,?,?)", (scope, now, incident_id))
            return None
