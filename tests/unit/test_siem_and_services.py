"""FR-006/007/008: traps and registry, canary server, backend stubs, mock SIEM, lab oracle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from canary_qday.common import labpolicy
from canary_qday.common.sig import sign_hmac
from canary_qday.common.store import Store
from canary_qday.services import backend_stub, canary_server
from canary_qday.siem import mock_hec
from canary_qday.siem.file_sink import FileSink
from canary_qday.siem.schemas import Alert, TrapEvent
from canary_qday.traffic import lab_oracle, traps
from canary_qday.traffic.registry import IssuedStream
from tests.conftest import KEY_RED_A, add_stream, make_alert


class ListSink:
    """In-memory SiemSink."""

    def __init__(self) -> None:
        self.events: list[BaseModel] = []

    def send(self, event: BaseModel) -> None:
        self.events.append(event)

    def flush(self) -> int:
        return 0


# -- traps and registry -----------------------------------------------------------
def test_tokens_and_fake_secrets() -> None:
    toks = {traps.new_token() for _ in range(1000)}
    assert len(toks) == 1000 and all(traps.is_token(t) for t in toks)
    assert not traps.is_token("G" * 32) and not traps.is_token("a" * 31)
    assert traps.new_fake_secret("api_key").startswith("FAKE-api_key-")
    with pytest.raises(ValueError):
        traps.new_fake_secret("root_password")


def test_registry_queryable_and_stores_no_secret_values(
    store: Store, registry: dict[str, IssuedStream]
) -> None:
    assert len(store.streams(profile="RED")) == 3
    assert len(store.streams(key_id=KEY_RED_A)) == 2
    assert len(store.streams(params_id="toy-n64-k2")) == 1
    assert len(store.streams(profile="RED", epoch=1)) == 3
    with pytest.raises(ValueError):
        store.streams(secret="x")
    raw = store.path.read_bytes()
    for issued in registry.values():
        assert issued.token.encode() not in raw
        for value in issued.credentials.values():
            assert value.encode() not in raw
            assert store.secret_status_by_value(value) == "active"
    assert "token" not in repr(registry["red_a1"])


# -- canary server -----------------------------------------------------------------
def test_canary_identical_responses_and_event_only_for_valid_token(
    store: Store, registry: dict[str, IssuedStream]
) -> None:
    sink = ListSink()
    c = TestClient(canary_server.create_app(store, sink))
    tok = registry["red_a1"].token
    responses = [c.get(f"/t/{t}") for t in (tok, "0" * 32, "not-a-token", tok.upper())]
    shapes = {(r.status_code, r.text, r.headers["content-type"]) for r in responses}
    assert len(shapes) == 1
    assert len(sink.events) == 1
    ev = sink.events[0]
    assert isinstance(ev, TrapEvent)
    assert ev.stream_id == registry["red_a1"].stream_id and ev.key_id == KEY_RED_A
    assert tok not in ev.model_dump_json()
    assert c.get("/healthz").json() == {"status": "ok"}


def test_canary_event_neutralises_log_injection(store: Store) -> None:
    issued = add_stream(store, "RED", "toy-n64-k1", KEY_RED_A)
    sink = ListSink()
    c = TestClient(canary_server.create_app(store, sink))
    c.get(f"/t/{issued.token}", headers={"User-Agent": "evil\x1b[31m"})
    ev = sink.events[0]
    assert isinstance(ev, TrapEvent) and "\x1b" not in ev.user_agent


# -- backend stub -------------------------------------------------------------------
def test_backend_stub_checks_credentials_and_stopped_services(
    tmp_path: Path, store: Store, registry: dict[str, IssuedStream]
) -> None:
    pol = tmp_path / "policy.json"
    cred = registry["red_a1"].credentials["billing.api_key"]

    def call(service: str, credential: str) -> int:
        req = backend_stub.BackendRequest(service=service, action="list", credential=credential)
        return int(backend_stub.handle(store, pol, req)["status"])

    assert call("billing", cred) == 200
    assert call("billing", "FAKE-api_key-unknown") == 401
    assert call("payroll", cred) == 404
    labpolicy.save(pol, labpolicy.LabPolicy(stopped_services=["billing"]))
    assert call("billing", cred) == 503


# -- lab oracle ---------------------------------------------------------------------
def test_lab_oracle_only_for_toy_profiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CQ_LAB_SIM", raising=False)
    assert not lab_oracle.enabled()
    common = {"key_id": "k", "trap_url": "u", "service": "s", "credential": "c"}
    assert lab_oracle.record(tmp_path, stream_id="g", profile="GREEN", **common) is None
    p = lab_oracle.record(tmp_path, stream_id="r", profile="RED", **common)
    assert p is not None and json.loads(p.read_text())["banner"] == lab_oracle.BANNER


# -- mock SIEM ----------------------------------------------------------------------
@pytest.fixture
def siem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[mock_hec.MockSiem, list[Any]]:
    sent: list[Any] = []

    def fake_post(url: str, content: bytes, headers: dict[str, str], timeout: float) -> Any:
        sent.append((url, content, headers))
        return httpx.Response(202)

    monkeypatch.setattr(mock_hec.httpx, "post", fake_post)
    s = mock_hec.MockSiem("hec-token-value", "http://response/v1/alerts", "w" * 32,
                          tmp_path / "events.jsonl", deliver_async=False)
    return s, sent


def _envelope(alert: Alert) -> dict[str, Any]:
    return {"event": alert.event.model_dump(), "index": "canary", "sourcetype": "canary:event"}


def test_mock_siem_rule_fires_once_per_token_and_signs(
    siem: tuple[mock_hec.MockSiem, list[Any]], registry: dict[str, IssuedStream]
) -> None:
    s, sent = siem
    env = _envelope(make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A))
    assert s.ingest(env) is not None
    assert s.ingest(env) is None  # throttled for the same token_id
    assert s.ingest({"event": {"event": "handshake"}}) is None
    assert s.ingest({"event": {"event": "trap_triggered", "token_id": "bad"}}) is None
    assert len(sent) == 1
    _url, body, headers = sent[0]
    assert headers["X-Signature"] == sign_hmac(b"w" * 32, headers["X-Timestamp"], body)
    assert Alert.model_validate_json(body).event.stream_id == registry["red_a1"].stream_id


def test_mock_siem_green_alert_is_critical(
    siem: tuple[mock_hec.MockSiem, list[Any]], registry: dict[str, IssuedStream]
) -> None:
    s, _ = siem
    alert = s.ingest(_envelope(make_alert(registry["green"], "GREEN", "xwing-mlkem768-x25519",
                                          "dddddddddddddddd")))
    assert alert is not None and alert.severity == "critical"


def test_mock_siem_http_endpoint(siem: tuple[mock_hec.MockSiem, list[Any]]) -> None:
    s, _ = siem
    c = TestClient(mock_hec.create_app(s))
    url = "/services/collector/event"
    assert c.post(url, json={"event": {}}).status_code == 401
    assert c.post(url, json={"event": {}},
                  headers={"Authorization": "Splunk wrong"}).status_code == 401
    ok = {"Authorization": "Splunk hec-token-value"}
    assert c.post(url, content=b"{not json", headers=ok).status_code == 400
    assert c.post(url, json=[1, 2], headers=ok).status_code == 400
    assert c.post(url, json={"event": {"event": "x"}}, headers=ok).json()["code"] == 0
    assert c.get("/alerts").json() == []


def test_file_sink_writes_sorted_json(tmp_path: Path, registry: dict[str, IssuedStream]) -> None:
    sink = FileSink(tmp_path / "e.jsonl")
    alert = make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A)
    sink.send(alert.event)
    line = (tmp_path / "e.jsonl").read_text(encoding="utf-8").strip()
    assert list(json.loads(line)) == sorted(json.loads(line))
    assert sink.flush() == 0
