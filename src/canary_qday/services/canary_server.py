"""Canary server: GET /t/{token}.

Every request gets the *same* response (status, headers, body) whether the
token is valid, unknown or malformed, so the server is not a token oracle.
Only a registered token produces a `trap_triggered` event, emitted after the
response is sent (background task) to keep the response path uniform.

Run: uvicorn --factory canary_qday.services.canary_server:app_from_env --port 8081
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import HTMLResponse

from canary_qday.common.config import env_secret
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.redact import token_hash
from canary_qday.common.store import Store
from canary_qday.siem.base import SiemSink, make_sink
from canary_qday.siem.schemas import TrapEvent
from canary_qday.traffic.traps import is_token

BODY = (
    "<!doctype html><html><head><title>Password reset</title></head>"
    "<body><p>This password reset link has expired. Please contact your administrator.</p>"
    "</body></html>"
)
_log = get_logger("canary")


def create_app(store: Store, sink: SiemSink) -> FastAPI:
    """Build the canary app."""
    app = FastAPI(title="canary", docs_url=None, redoc_url=None, openapi_url=None)

    def emit(token: str, src_ip: str, user_agent: str) -> None:
        row = store.token(token_hash(token))
        if row is None:
            return
        tid, stream_id, _allow = row
        stream = store.stream(stream_id)
        if stream is None:
            return
        ev = TrapEvent(
            event_id=str(uuid.uuid4()),
            ts=datetime.now(UTC).isoformat(),
            token_id=tid,
            stream_id=stream_id,
            profile=stream.profile,  # type: ignore[arg-type]
            params_id=stream.params_id,
            key_id=stream.key_id,
            epoch=stream.epoch,
            src_ip=src_ip[:64],
            user_agent=user_agent[:256],
        )
        sink.send(ev)
        log_event(_log, "trap_triggered", token_id=tid, stream_id=stream_id)

    @app.get("/t/{token}")
    async def trap(token: str, request: Request, tasks: BackgroundTasks) -> HTMLResponse:
        if len(token) == 32 and is_token(token):
            ip = request.client.host if request.client else "unknown"
            tasks.add_task(emit, token, ip, request.headers.get("user-agent", ""))
        return HTMLResponse(BODY, status_code=200, headers={"Cache-Control": "no-store"})

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def app_from_env() -> FastAPI:
    """Factory used by uvicorn --factory."""
    data = Path(os.environ.get("CQ_DATA_DIR", "var"))
    store = Store(os.environ.get("CQ_REGISTRY_DB", str(data / "registry.db")))
    kind = os.environ.get("CQ_SIEM_SINK", "file")
    sink: SiemSink
    if kind == "hec":
        sink = make_sink(
            "hec",
            hec_url=os.environ.get("CQ_HEC_URL", "http://127.0.0.1:8088"),
            token=env_secret("CQ_HEC_TOKEN", "CQ_HEC_TOKEN_FILE"),
            buffer_path=data / "siem" / "canary-buffer.jsonl",
        )
    else:
        sink = make_sink("file", path=data / "siem" / "canary-events.jsonl")
    return create_app(store, sink)
