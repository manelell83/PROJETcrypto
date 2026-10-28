"""Response Engine HTTP API (spec 7.2).

POST /v1/alerts                 HmacHeader mode (mock SIEM, custom alert action)
POST /v1/alerts/{path_secret}   SharedSecretPath mode (Splunk native webhook)
POST /v1/approvals/{incident}   admin token (X-Admin-Token)
GET  /v1/incidents/{incident}   admin token

Run: python -m canary_qday.response.webhook   (dry-run unless CQ_APPLY=1)
"""

from __future__ import annotations

import hmac
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from canary_qday.common.config import env_secret
from canary_qday.common.errors import CanaryError
from canary_qday.response.auth import (
    AlertAuthenticator,
    HmacHeader,
    SharedSecretPath,
    check_alert_ts,
)
from canary_qday.response.engine import EngineConfig, ResponseEngine
from canary_qday.siem.schemas import parse_alert

MAX_BODY = 64 * 1024
STATUS = {"E_SIG_INVALID": 401, "E_STALE": 400, "E_REPLAY": 409, "E_SCHEMA": 422,
          "E_NOT_FOUND": 404, "E_POLICY": 403, "E_RATE": 429}


class Approval(BaseModel):
    """Body of POST /v1/approvals/{incident_id}."""

    actions: list[str]


class RateLimiter:
    """Sliding-window limiter on accepted alert requests."""

    def __init__(self, limit: int, per_s: float) -> None:
        self.limit, self.per_s = limit, per_s
        self._hits: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self, now: float) -> bool:
        """True if one more request fits in the window."""
        with self._lock:
            while self._hits and now - self._hits[0] > self.per_s:
                self._hits.popleft()
            if len(self._hits) >= self.limit:
                return False
            self._hits.append(now)
            return True


def _err(code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=STATUS.get(code, 400))


def create_app(
    engine: ResponseEngine,
    authenticator: AlertAuthenticator,
    admin_token: str,
    *,
    path_mode: bool = False,
    rate: RateLimiter | None = None,
) -> FastAPI:
    """Build the API around an engine and one authenticator."""
    app = FastAPI(title="canary-qday response engine")
    limiter = rate or RateLimiter(30, 60.0)

    async def _alert(request: Request, path_secret: str | None) -> JSONResponse:
        now = time.time()
        body = await request.body()
        if len(body) > MAX_BODY:
            return _err("E_SCHEMA")
        try:
            authenticator.verify(dict(request.headers), body, path_secret, now)
            alert = parse_alert(body)
            check_alert_ts(alert.ts, now)
        except CanaryError as e:
            return _err(e.code)
        except (ValidationError, ValueError):
            return _err("E_SCHEMA")
        if not limiter.allow(now):
            return _err("E_RATE")
        try:
            rep = engine.handle(alert, now)
        except CanaryError as e:
            return _err(e.code)
        return JSONResponse({"incident_id": rep["incident_id"], "dry_run": rep["dry_run"],
                             "pending_approval": rep["pending_approval"]}, status_code=202)

    if path_mode:
        @app.post("/v1/alerts/{path_secret}")
        async def alert_path(path_secret: str, request: Request) -> JSONResponse:
            return await _alert(request, path_secret)
    else:
        @app.post("/v1/alerts")
        async def alert_hmac(request: Request) -> JSONResponse:
            return await _alert(request, None)

    def _admin(tok: str | None) -> bool:
        return tok is not None and hmac.compare_digest(tok.encode(), admin_token.encode())

    @app.post("/v1/approvals/{incident_id}")
    async def approve(incident_id: str, body: Approval,
                      x_admin_token: str | None = Header(default=None)) -> Any:
        if not _admin(x_admin_token):
            return _err("E_SIG_INVALID")
        try:
            rep = engine.approve(incident_id, body.actions)
        except CanaryError as e:
            return _err(e.code)
        return {"incident_id": incident_id, "pending_approval": rep["pending_approval"]}

    @app.get("/v1/incidents/{incident_id}")
    async def incident(incident_id: str,
                       x_admin_token: str | None = Header(default=None)) -> Any:
        if not _admin(x_admin_token):
            return _err("E_SIG_INVALID")
        inc = engine.state.incident(incident_id)
        if inc is None:
            return _err("E_NOT_FOUND")
        return {"incident_id": incident_id, "status": inc["status"], "report": inc["report"]}

    return app


def app_from_env() -> FastAPI:
    """Build the app from CQ_* environment variables and Docker secrets."""
    data = Path(os.environ.get("CQ_DATA_DIR", "var"))
    cfg = EngineConfig(
        registry_db=Path(os.environ.get("CQ_REGISTRY_DB", str(data / "registry.db"))),
        response_db=Path(os.environ.get("CQ_RESPONSE_DB", str(data / "response.db"))),
        policy_file=Path(os.environ.get("CQ_POLICY_FILE", str(data / "policy.json"))),
        reports_dir=Path(os.environ.get("CQ_REPORTS_DIR", str(data / "reports"))),
        notify_file=data / "notifications.jsonl",
        apply=os.environ.get("CQ_APPLY") == "1",
        auto_lab=os.environ.get("CQ_AUTO_LAB") == "1",
    )
    mode = os.environ.get("CQ_WEBHOOK_AUTH", "hmac")
    secret = env_secret("CQ_WEBHOOK_SECRET", "CQ_WEBHOOK_SECRET_FILE")
    auth: AlertAuthenticator = (
        SharedSecretPath(secret) if mode == "path" else HmacHeader(secret.encode())
    )
    admin = env_secret("CQ_ADMIN_TOKEN", "CQ_ADMIN_TOKEN_FILE")
    return create_app(ResponseEngine(cfg), auth, admin, path_mode=(mode == "path"))


def main() -> None:
    """Entry point."""
    import uvicorn

    uvicorn.run(app_from_env(), host=os.environ.get("CQ_BIND", "127.0.0.1"),
                port=int(os.environ.get("CQ_PORT", "8090")), log_level="warning")


if __name__ == "__main__":
    main()
