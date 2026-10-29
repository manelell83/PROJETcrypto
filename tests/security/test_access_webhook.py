"""Security of the /v1/alerts/access route: reuses HMAC auth, freshness, replay, rate-limit.

Also checks that the dedicated access rate limiter does not consume the trap budget.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from canary_qday.common.sig import sign_hmac
from canary_qday.response.auth import HmacHeader
from canary_qday.response.engine import ResponseEngine
from canary_qday.response.webhook import RateLimiter, create_app
from canary_qday.siem.schemas import AccessAlert, HandshakeEvent

SECRET = b"s" * 32
ADMIN = "a" * 32


def _signed(body: bytes, ts: int | None = None) -> dict[str, str]:
    t = str(int(time.time()) if ts is None else ts)
    return {"X-Timestamp": t, "X-Signature": sign_hmac(SECRET, t, body)}


def _access_body(reason: str = "revoked_key") -> bytes:
    now = datetime.now(UTC).isoformat()
    return AccessAlert(
        alert_id=str(uuid.uuid4()), ts=now, rule="unauthorized_key_use", severity="high",
        event=HandshakeEvent(
            event_id=str(uuid.uuid4()), ts=now, stream_id=str(uuid.uuid4()), profile="RED",
            key_id="a" * 16, epoch=1, src_ip="10.0.0.66", outcome="refused", reason=reason,
        ),
    ).model_dump_json().encode()


@pytest.fixture
def client(engine_factory: Callable[..., ResponseEngine]) -> TestClient:
    app = create_app(
        engine_factory(), HmacHeader(SECRET), ADMIN,
        rate=RateLimiter(5, 60), access_rate=RateLimiter(3, 60),
    )
    return TestClient(app)


def test_valid_access_alert_accepted(client: TestClient) -> None:
    body = _access_body()
    r = client.post("/v1/alerts/access", content=body, headers=_signed(body))
    assert r.status_code == 202
    assert r.json()["classification"] == "unauthorized-access-attempt"


def test_forged_signature_rejected(client: TestClient) -> None:
    body = _access_body()
    r = client.post("/v1/alerts/access", content=body,
                    headers={"X-Timestamp": str(int(time.time())), "X-Signature": "0" * 64})
    assert r.status_code == 401


def test_stale_timestamp_rejected(client: TestClient) -> None:
    body = _access_body()
    stale = _signed(body, int(time.time()) - 600)
    r = client.post("/v1/alerts/access", content=body, headers=stale)
    assert r.status_code == 400


def test_replayed_signature_rejected(client: TestClient) -> None:
    body = _access_body()
    hdr = _signed(body)
    assert client.post("/v1/alerts/access", content=body, headers=hdr).status_code == 202
    assert client.post("/v1/alerts/access", content=body, headers=hdr).status_code == 409


def test_schema_rejected(client: TestClient) -> None:
    # A trap alert body is not a valid access alert (missing handshake fields / extra fields).
    junk = b'{"alert_id":"x","ts":"t"}'
    assert client.post("/v1/alerts/access", content=junk, headers=_signed(junk)).status_code == 422
    big = b"x" * (70 * 1024)
    assert client.post("/v1/alerts/access", content=big, headers=_signed(big)).status_code == 422


def test_access_rate_limit_is_independent_of_trap(client: TestClient) -> None:
    codes = []
    for _ in range(4):  # access limiter allows 3
        b = _access_body()
        codes.append(client.post("/v1/alerts/access", content=b, headers=_signed(b)).status_code)
    assert codes == [202, 202, 202, 429]
