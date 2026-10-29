"""Mock SIEM for CI and the default demo: an HEC-compatible collector plus one correlation rule.

It is NOT Splunk. It reproduces the contract we rely on:
  * POST /services/collector/event with `Authorization: Splunk <token>`;
  * a rule equivalent to siem/splunk/savedsearches.conf
    (event=trap_triggered, throttled per token_id for THROTTLE_S seconds);
  * a webhook to the response engine, signed with HmacHeader
    (the real Splunk webhook cannot sign, see docs/decisions.md).

Run: uvicorn --factory canary_qday.siem.mock_hec:app_from_env --port 8088
"""

from __future__ import annotations

import hmac
import json
import os
import threading
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ValidationError

from canary_qday.common.config import env_secret
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.sig import sign_hmac
from canary_qday.siem.schemas import AccessAlert, Alert, HandshakeEvent, TrapEvent

THROTTLE_S = 60.0
Severity = Literal["low", "medium", "high", "critical"]
# Access detection (provisional thresholds, configurable; see docs). A legitimate
# client rarely gets several policy refusals in a short window; probing/retrying does.
REVOKED_THROTTLE_S = 60.0


def _access_burst_config() -> tuple[int, float]:
    """Burst threshold N and window T seconds, overridable via CQ_ACCESS_BURST_*."""
    n = int(os.environ.get("CQ_ACCESS_BURST_N", "5"))
    window = float(os.environ.get("CQ_ACCESS_BURST_WINDOW_S", "30"))
    return n, window


_log = get_logger("siem.mock")


class MockSiem:
    """Event store + correlation rule + webhook delivery."""

    def __init__(
        self,
        hec_token: str,
        webhook_url: str,
        webhook_secret: str,
        store_path: Path,
        *,
        deliver_async: bool = True,
        access_webhook_url: str | None = None,
    ) -> None:
        self._hec_token = hec_token
        self._webhook_url = webhook_url
        self._access_webhook_url = access_webhook_url or (webhook_url.rstrip("/") + "/access")
        self._webhook_secret = webhook_secret
        self._store = store_path
        self._store.parent.mkdir(parents=True, exist_ok=True)
        self._last_alert: dict[str, float] = {}
        self._burst_n, self._burst_window = _access_burst_config()
        self._refused: dict[str, deque[float]] = {}  # src_ip -> refusal timestamps
        self._burst_cooldown: dict[str, float] = {}  # src_ip -> suppress-until
        self._revoked_last: dict[tuple[str, str], float] = {}  # (src_ip, key_id) -> last alert
        self._lock = threading.Lock()
        self._async = deliver_async
        self.alerts: list[dict[str, Any]] = []
        self.access_alerts: list[dict[str, Any]] = []

    def authorised(self, header: str | None) -> bool:
        """Constant-time check of `Splunk <token>`."""
        expected = f"Splunk {self._hec_token}"
        return header is not None and hmac.compare_digest(header.encode(), expected.encode())

    def ingest(self, envelope: dict[str, Any]) -> Alert | AccessAlert | None:
        """Store an event and evaluate the rules; return the alert if one fires.

        The trap rule (trap_triggered) is unchanged. Handshake events are
        evaluated by the separate access rules and never affect the trap path.
        """
        received = time.time()
        with self._lock, self._store.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"_time": received, **envelope}, sort_keys=True) + "\n")
        ev = envelope.get("event")
        if not isinstance(ev, dict):
            return None
        kind = ev.get("event")
        if kind == "trap_triggered":
            return self._rule_trap(ev, received)
        if kind == "handshake":
            return self._rule_access(ev, received)
        return None

    def _rule_trap(self, ev: dict[str, Any], received: float) -> Alert | None:
        try:
            trap = TrapEvent.model_validate(ev)
        except ValidationError:
            return None
        with self._lock:
            last = self._last_alert.get(trap.token_id, 0.0)
            if received - last < THROTTLE_S:
                return None
            self._last_alert[trap.token_id] = received
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            ts=datetime.now(UTC).isoformat(),
            rule="canary_trap_triggered",
            severity="critical" if trap.profile == "GREEN" else "high",
            event=trap,
        )
        self.alerts.append({"alert_id": alert.alert_id, "fired_at": time.time()})
        self._dispatch(alert, self._webhook_url)
        return alert

    def _rule_access(self, ev: dict[str, Any], received: float) -> AccessAlert | None:
        """Two access rules on refused handshakes: revoked-key reuse and refusal bursts."""
        try:
            hs = HandshakeEvent.model_validate(ev)
        except ValidationError:
            return None
        if hs.outcome != "refused":
            return None
        rule, severity = self._access_match(hs, received)
        if rule is None:
            return None
        alert = AccessAlert(
            alert_id=str(uuid.uuid4()),
            ts=datetime.now(UTC).isoformat(),
            rule=rule,
            severity=severity,
            event=hs,
        )
        self.access_alerts.append(
            {"alert_id": alert.alert_id, "rule": rule, "fired_at": time.time()}
        )
        self._dispatch(alert, self._access_webhook_url)
        return alert

    def _access_match(self, hs: HandshakeEvent, received: float) -> tuple[str | None, Severity]:
        """Decide which access rule fires, applying throttle/burst/cooldown under lock."""
        with self._lock:
            if hs.reason == "revoked_key":
                key = (hs.src_ip, hs.key_id)
                if received - self._revoked_last.get(key, 0.0) >= REVOKED_THROTTLE_S:
                    self._revoked_last[key] = received
                    return "unauthorized_key_use", "high"
                return None, "high"
            # refused-handshake burst per src_ip (sliding window + cooldown)
            hits = self._refused.setdefault(hs.src_ip, deque())
            hits.append(received)
            while hits and received - hits[0] > self._burst_window:
                hits.popleft()
            if received < self._burst_cooldown.get(hs.src_ip, 0.0):
                return None, "medium"
            if len(hits) >= self._burst_n:
                self._burst_cooldown[hs.src_ip] = received + self._burst_window
                hits.clear()
                return "refused_handshake_burst", "medium"
            return None, "medium"

    def _dispatch(self, alert: BaseModel, url: str) -> None:
        if self._async:
            threading.Thread(target=self.deliver, args=(alert, url), daemon=True).start()
        else:
            self.deliver(alert, url)

    def deliver(self, alert: BaseModel, url: str | None = None) -> int:
        """POST a (trap or access) alert to the response engine, signed."""
        target = url or self._webhook_url
        alert_id = getattr(alert, "alert_id", "?")
        body = alert.model_dump_json().encode()
        ts = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "X-Timestamp": ts,
            "X-Signature": sign_hmac(self._webhook_secret.encode(), ts, body),
        }
        try:
            r = httpx.post(target, content=body, headers=headers, timeout=10)
        except httpx.HTTPError:
            log_event(_log, "webhook delivery failed", alert_id=alert_id)
            return 0
        log_event(_log, "webhook delivered", alert_id=alert_id, status=r.status_code)
        return r.status_code


def create_app(siem: MockSiem) -> FastAPI:
    """FastAPI app exposing the HEC endpoint."""
    app = FastAPI(title="mock-hec")

    @app.post("/services/collector/event")
    async def collect(
        request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        if not siem.authorised(authorization):
            raise HTTPException(status_code=401, detail="Invalid token")
        raw = await request.body()
        if len(raw) > 64 * 1024:
            raise HTTPException(status_code=413, detail="too large")
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid data format") from None
        if not isinstance(envelope, dict):
            raise HTTPException(status_code=400, detail="Invalid data format")
        siem.ingest(envelope)
        return {"text": "Success", "code": 0}

    @app.get("/alerts")
    async def alerts() -> list[dict[str, Any]]:
        return siem.alerts

    @app.get("/access_alerts")
    async def access_alerts() -> list[dict[str, Any]]:
        return siem.access_alerts

    return app


def app_from_env() -> FastAPI:
    """Factory used by uvicorn --factory (reads secrets from CQ_*_FILE or env)."""
    webhook_url = os.environ.get("CQ_WEBHOOK_URL", "http://127.0.0.1:8090/v1/alerts")
    siem = MockSiem(
        hec_token=env_secret("CQ_HEC_TOKEN", "CQ_HEC_TOKEN_FILE"),
        webhook_url=webhook_url,
        webhook_secret=env_secret("CQ_WEBHOOK_SECRET", "CQ_WEBHOOK_SECRET_FILE"),
        store_path=Path(os.environ.get("CQ_DATA_DIR", "var")) / "siem" / "events.jsonl",
        access_webhook_url=os.environ.get("CQ_ACCESS_WEBHOOK_URL"),
    )
    return create_app(siem)
