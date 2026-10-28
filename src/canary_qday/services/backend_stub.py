"""Backend stub services (billing, hr, crm, files). They only check synthetic credentials.

A presented credential is accepted only while its registry status is `active`,
so the effect of rotation is observable: stolen credentials stop working.

Run: uvicorn --factory canary_qday.services.backend_stub:app_from_env --port 8000
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from canary_qday.common import labpolicy
from canary_qday.common.store import Store

SERVICES = ("billing", "hr", "crm", "files")


class BackendRequest(BaseModel):
    """Request forwarded by the proxy."""

    service: str = Field(max_length=32)
    action: str = Field(max_length=64)
    credential: str = Field(max_length=128)


def handle(store: Store, policy_file: Path, req: BackendRequest) -> dict[str, Any]:
    """Pure handler, shared by the HTTP app and the proxy's in-process mode."""
    if req.service not in SERVICES:
        return {"status": 404, "error": "unknown service"}
    if req.service in labpolicy.load(policy_file).stopped_services:
        return {"status": 503, "error": "service stopped by incident response"}
    st = store.secret_status_by_value(req.credential)
    if st != "active":
        return {"status": 401, "error": "invalid credential"}
    return {"status": 200, "service": req.service, "result": f"{req.action}: ok (synthetic)"}


def create_app(store: Store, policy_file: Path) -> FastAPI:
    """HTTP wrapper."""
    app = FastAPI(title="backend-stub")

    @app.post("/api")
    async def api(req: BackendRequest) -> dict[str, Any]:
        return handle(store, policy_file, req)

    return app


def app_from_env() -> FastAPI:
    """Factory used by uvicorn --factory."""
    data = Path(os.environ.get("CQ_DATA_DIR", "var"))
    return create_app(
        Store(os.environ.get("CQ_REGISTRY_DB", str(data / "registry.db"))),
        Path(os.environ.get("CQ_POLICY_FILE", str(data / "policy.json"))),
    )
