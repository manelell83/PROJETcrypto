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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import ValidationError

from canary_qday.common.config import env_secret
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.sig import sign_hmac
from canary_qday.siem.schemas import Alert, TrapEvent

THROTTLE_S = 60.0
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
    ) -> None:
        self._hec_token = hec_token
        self._webhook_url = webhook_url
        self._webhook_secret = webhook_secret
        self._store = store_path
        self._store.parent.mkdir(parents=True, exist_ok=True)
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()
        self._async = deliver_async
        self.alerts: list[dict[str, Any]] = []

    def authorised(self, header: str | None) -> bool:
        """Constant-time check of `Splunk <token>`."""
        expected = f"Splunk {self._hec_token}"
        return header is not None and hmac.compare_digest(header.encode(), expected.encode())

    def ingest(self, envelope: dict[str, Any]) -> Alert | None:
        """Store an event and evaluate the rule; return the alert if one fires."""
        received = time.time()
        with self._lock, self._store.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"_time": received, **envelope}, sort_keys=True) + "\n")
        ev = envelope.get("event")
        if not isinstance(ev, dict) or ev.get("event") != "trap_triggered":
            return None
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
        if self._async:
            threading.Thread(target=self.deliver, args=(alert,), daemon=True).start()
        else:
            self.deliver(alert)
        return alert

    def deliver(self, alert: Alert) -> int:
        """POST the alert to the response engine with X-Timestamp / X-Signature."""
        body = alert.model_dump_json().encode()
        ts = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "X-Timestamp": ts,
            "X-Signature": sign_hmac(self._webhook_secret.encode(), ts, body),
        }
        try:
            r = httpx.post(self._webhook_url, content=body, headers=headers, timeout=10)
        except httpx.HTTPError:
            log_event(_log, "webhook delivery failed", alert_id=alert.alert_id)
            return 0
        log_event(_log, "webhook delivered", alert_id=alert.alert_id, status=r.status_code)
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

    return app


def app_from_env() -> FastAPI:
    """Factory used by uvicorn --factory (reads secrets from CQ_*_FILE or env)."""
    siem = MockSiem(
        hec_token=env_secret("CQ_HEC_TOKEN", "CQ_HEC_TOKEN_FILE"),
        webhook_url=os.environ.get("CQ_WEBHOOK_URL", "http://127.0.0.1:8090/v1/alerts"),
        webhook_secret=env_secret("CQ_WEBHOOK_SECRET", "CQ_WEBHOOK_SECRET_FILE"),
        store_path=Path(os.environ.get("CQ_DATA_DIR", "var")) / "siem" / "events.jsonl",
    )
    return create_app(siem)
