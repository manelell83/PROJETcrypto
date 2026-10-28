"""SEC-001 / SEC-007: webhook authentication, freshness, replay, schema and rate limiting."""

from __future__ import annotations

import json
import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from canary_qday.common.errors import AuthError, ReplayError, StaleError
from canary_qday.common.sig import sign_hmac
from canary_qday.response.auth import HmacHeader, SharedSecretPath, check_alert_ts
from canary_qday.response.engine import ResponseEngine
from canary_qday.response.webhook import RateLimiter, create_app
from canary_qday.traffic.registry import IssuedStream
from tests.conftest import KEY_RED_A, make_alert

SECRET = b"s" * 32
ADMIN = "a" * 32


def _signed(body: bytes, ts: int | None = None) -> dict[str, str]:
    t = str(int(time.time()) if ts is None else ts)
    return {"X-Timestamp": t, "X-Signature": sign_hmac(SECRET, t, body)}


def test_hmac_header_accepts_valid_and_rejects_bad() -> None:
    auth = HmacHeader(SECRET)
    body = b'{"x":1}'
    now = time.time()
    auth.verify(_signed(body), body, None, now)
    with pytest.raises(AuthError):
        auth.verify({"X-Timestamp": str(int(now)), "X-Signature": "0" * 64}, body, None, now)
    with pytest.raises(AuthError):
        auth.verify({}, body, None, now)
    with pytest.raises(AuthError):
        auth.verify(_signed(body), body + b" ", None, now)  # body tampered
    with pytest.raises(StaleError):
        auth.verify(_signed(body, int(now) - 500), body, None, now)


def test_hmac_header_rejects_replayed_signature() -> None:
    auth = HmacHeader(SECRET)
    body, hdr, now = b"{}", _signed(b"{}"), time.time()
    auth.verify(hdr, body, None, now)
    with pytest.raises(ReplayError):
        auth.verify(hdr, body, None, now)


def test_short_secrets_refused() -> None:
    with pytest.raises(ValueError):
        HmacHeader(b"short")
    with pytest.raises(ValueError):
        SharedSecretPath("short")


def test_shared_secret_path() -> None:
    auth = SharedSecretPath("p" * 40)
    auth.verify({}, b"", "p" * 40, time.time())
    for wrong in (None, "p" * 39, "q" * 40):
        with pytest.raises(AuthError):
            auth.verify({}, b"", wrong, time.time())


def test_alert_timestamp_window() -> None:
    check_alert_ts("2026-01-01T00:00:00+00:00", now=1767225600.0)
    with pytest.raises(StaleError):
        check_alert_ts("2026-01-01T00:00:00+00:00", now=1767225600.0 + 3600)
    with pytest.raises(StaleError):
        check_alert_ts("not-a-date")


@pytest.fixture
def client(
    registry: dict[str, IssuedStream], engine_factory: Callable[..., ResponseEngine]
) -> TestClient:
    app = create_app(engine_factory(), HmacHeader(SECRET), ADMIN, rate=RateLimiter(3, 60))
    return TestClient(app)


def _body(registry: dict[str, IssuedStream]) -> bytes:
    return make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A).model_dump_json().encode()


def test_api_accepts_signed_alert_then_rejects_replay(
    client: TestClient, registry: dict[str, IssuedStream]
) -> None:
    body = _body(registry)
    r = client.post("/v1/alerts", content=body, headers=_signed(body))
    assert r.status_code == 202 and r.json()["dry_run"] is True
    inc = r.json()["incident_id"]
    # Same alert, fresh signature: rejected by alert_id (engine-level replay protection).
    time.sleep(1.1)
    again = client.post("/v1/alerts", content=body, headers=_signed(body))
    assert again.status_code == 409 and again.json() == {"error": "E_REPLAY"}
    got = client.get(f"/v1/incidents/{inc}", headers={"X-Admin-Token": ADMIN})
    assert got.status_code == 200 and got.json()["status"] == "awaiting-approval"


def test_api_error_codes(client: TestClient, registry: dict[str, IssuedStream]) -> None:
    body = _body(registry)
    forged = client.post("/v1/alerts", content=body,
                         headers={"X-Timestamp": str(int(time.time())), "X-Signature": "0" * 64})
    assert forged.status_code == 401
    stale = client.post("/v1/alerts", content=body, headers=_signed(body, int(time.time()) - 600))
    assert stale.status_code == 400 and stale.json() == {"error": "E_STALE"}
    junk = b'{"alert_id": "x"}'
    assert client.post("/v1/alerts", content=junk, headers=_signed(junk)).status_code == 422
    extra = json.loads(body)
    extra["unexpected"] = 1
    eb = json.dumps(extra).encode()
    assert client.post("/v1/alerts", content=eb, headers=_signed(eb)).status_code == 422
    big = b"x" * (70 * 1024)
    assert client.post("/v1/alerts", content=big, headers=_signed(big)).status_code == 422


def test_api_rate_limit(client: TestClient, registry: dict[str, IssuedStream]) -> None:
    codes = []
    for key in ("red_a1", "red_a2", "red_b", "red_a1"):
        b = make_alert(registry[key], "RED", "toy-n64-k1", KEY_RED_A).model_dump_json().encode()
        codes.append(client.post("/v1/alerts", content=b, headers=_signed(b)).status_code)
    assert codes == [202, 202, 202, 429]


def test_admin_endpoints_require_token(client: TestClient) -> None:
    assert client.get("/v1/incidents/x").status_code == 401
    assert client.get("/v1/incidents/x", headers={"X-Admin-Token": "b" * 32}).status_code == 401
    assert client.get("/v1/incidents/x", headers={"X-Admin-Token": ADMIN}).status_code == 404
    r = client.post("/v1/approvals/x", json={"actions": ["firewall_block"]},
                    headers={"X-Admin-Token": ADMIN})
    assert r.status_code == 404


def test_path_mode_route(
    registry: dict[str, IssuedStream], engine_factory: Callable[..., ResponseEngine]
) -> None:
    secret = "z" * 40
    c = TestClient(create_app(engine_factory(), SharedSecretPath(secret), ADMIN, path_mode=True))
    body = _body(registry)
    assert c.post(f"/v1/alerts/{'y' * 40}", content=body).status_code == 401
    assert c.post(f"/v1/alerts/{secret}", content=body).status_code == 202
    assert c.post("/v1/alerts", content=body).status_code in (404, 405)
