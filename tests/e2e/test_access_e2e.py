"""Dedicated end-to-end: refused handshake (revoked key) -> mock SIEM access rule ->
signed webhook -> response engine /v1/alerts/access -> access incident.

Distinct from the trap path and from the default M9 scenario (which is NOT touched).
Uses the real MockSiem and the real response app via TestClient (httpx.post routed
into the client), so no subprocess or Docker is needed.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from canary_qday.response.auth import HmacHeader
from canary_qday.response.engine import ResponseEngine
from canary_qday.response.webhook import create_app
from canary_qday.siem import mock_hec

SECRET = "s" * 32
ADMIN = "a" * 32


def _handshake(reason: str, key_id: str = "a" * 16) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {
        "event": {
            "event": "handshake", "event_id": str(uuid.uuid4()), "ts": now,
            "stream_id": str(uuid.uuid4()), "profile": "RED", "key_id": key_id, "epoch": 1,
            "src_ip": "10.0.0.66", "outcome": "refused", "reason": reason,
        }
    }


def test_access_alert_end_to_end(
    tmp_path: Path, engine_factory: Callable[..., ResponseEngine], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = engine_factory()
    client = TestClient(create_app(engine, HmacHeader(SECRET.encode()), ADMIN))
    delivered: list[dict[str, Any]] = []

    def fake_post(url: str, content: bytes, headers: dict[str, str], timeout: float) -> Any:
        path = url.split("http://resp", 1)[1]
        r = client.post(path, content=content, headers=headers)
        delivered.append({"path": path, "status": r.status_code, "json": r.json()})
        return httpx.Response(r.status_code)

    monkeypatch.setattr(mock_hec.httpx, "post", fake_post)
    siem = mock_hec.MockSiem(
        "hec", "http://resp/v1/alerts", SECRET, tmp_path / "events.jsonl",
        deliver_async=False, access_webhook_url="http://resp/v1/alerts/access",
    )

    alert = siem.ingest(_handshake("revoked_key"))
    assert alert is not None

    # The alert reached the access route (not the trap route) and created an incident.
    assert len(delivered) == 1
    assert delivered[0]["path"] == "/v1/alerts/access"
    assert delivered[0]["status"] == 202
    body = delivered[0]["json"]
    assert body["classification"] == "unauthorized-access-attempt"
    assert body["dry_run"] is True

    inc = engine.state.incident(body["incident_id"])
    assert inc is not None and inc["status"] == "reported"
    # Access incident does nothing but create_incident: no containment action recorded.
    kinds = {a["kind"] for a in engine.state.actions(body["incident_id"])}
    assert kinds == {"create_incident"}
    assert not ({"rotate_secrets", "switch_profile", "firewall_block", "service_stop"} & kinds)
