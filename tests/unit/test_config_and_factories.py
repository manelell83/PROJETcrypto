"""Configuration from the environment and the app factories used by tools/lab.py.

Secrets here are random test values generated per test; nothing real is used.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from canary_qday.common.config import ConfigError, Settings, env_secret, write_secret
from canary_qday.common.sig import sign_hmac
from canary_qday.response import webhook
from canary_qday.services import backend_stub, canary_server
from canary_qday.siem import mock_hec
from canary_qday.siem.base import make_sink
from canary_qday.siem.file_sink import FileSink
from canary_qday.siem.splunk_hec import SplunkHecSink


@pytest.fixture
def lab_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """A per-test data dir and secrets passed as *_FILE, like tools/lab.py does."""
    values = {n: secrets.token_hex(32) for n in ("hec", "webhook", "admin")}
    names = {"hec": "CQ_HEC_TOKEN", "webhook": "CQ_WEBHOOK_SECRET", "admin": "CQ_ADMIN_TOKEN"}
    for key, var in names.items():
        p = tmp_path / "secrets" / f"{key}.txt"
        write_secret(p, values[key].encode())
        monkeypatch.setenv(f"{var}_FILE", str(p))
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CQ_DATA_DIR", str(tmp_path))
    for var in (
        "CQ_REGISTRY_DB",
        "CQ_RESPONSE_DB",
        "CQ_POLICY_FILE",
        "CQ_REPORTS_DIR",
        "CQ_SIEM_SINK",
        "CQ_WEBHOOK_AUTH",
        "CQ_APPLY",
        "CQ_AUTO_LAB",
    ):
        monkeypatch.delenv(var, raising=False)
    return values


def test_settings_defaults_and_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("CQ_SECRETS_DIR", "CQ_REGISTRY_DB", "CQ_PROXY_PORT", "CQ_SIEM_SINK"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CQ_DATA_DIR", str(tmp_path))
    s = Settings.from_env()
    assert s.secrets_dir == tmp_path / "secrets" and s.registry_db == tmp_path / "registry.db"
    assert (s.proxy_port, s.siem_sink) == (9443, "file")
    monkeypatch.setenv("CQ_PROXY_PORT", "10443")
    monkeypatch.setenv("CQ_SIEM_SINK", "hec")
    s = Settings.from_env()
    assert (s.proxy_port, s.siem_sink) == (10443, "hec")


def test_env_secret_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CQ_X_FILE", raising=False)
    monkeypatch.delenv("CQ_X", raising=False)
    with pytest.raises(ConfigError) as err:
        env_secret("CQ_X", "CQ_X_FILE")
    assert "CQ_X" in str(err.value)
    monkeypatch.setenv("CQ_X", "from-env")
    assert env_secret("CQ_X", "CQ_X_FILE") == "from-env"
    p = tmp_path / "x.txt"
    write_secret(p, b"from-file\n")
    monkeypatch.setenv("CQ_X_FILE", str(p))
    assert env_secret("CQ_X", "CQ_X_FILE") == "from-file"  # file wins, newline stripped
    monkeypatch.setenv("CQ_X_FILE", str(tmp_path / "missing.txt"))
    with pytest.raises(ConfigError):
        env_secret("CQ_X", "CQ_X_FILE")


def test_make_sink(tmp_path: Path) -> None:
    assert isinstance(make_sink("file", path=tmp_path / "e.jsonl"), FileSink)
    hec = make_sink("hec", hec_url="http://127.0.0.1:9", token="t", buffer_path=tmp_path / "b")
    assert isinstance(hec, SplunkHecSink)
    with pytest.raises(ValueError):
        make_sink("syslog")


def test_hec_flush_with_empty_buffer(tmp_path: Path) -> None:
    sink = SplunkHecSink("http://127.0.0.1:9", "t", tmp_path / "none.jsonl", timeout=0.2)
    assert sink.flush() == 0


@pytest.mark.usefixtures("lab_env")
def test_canary_app_from_env_file_and_hec(monkeypatch: pytest.MonkeyPatch) -> None:
    c = TestClient(canary_server.app_from_env())
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get(f"/t/{'a' * 32}").status_code == 200
    monkeypatch.setenv("CQ_SIEM_SINK", "hec")
    monkeypatch.setenv("CQ_HEC_URL", "http://127.0.0.1:9")
    assert TestClient(canary_server.app_from_env()).get("/healthz").status_code == 200


@pytest.mark.usefixtures("lab_env")
def test_backend_app_from_env() -> None:
    c = TestClient(backend_stub.app_from_env())
    r = c.post("/api", json={"service": "billing", "action": "list", "credential": "FAKE-x"})
    assert r.json() == {"status": 401, "error": "invalid credential"}
    too_long = {"service": "billing", "action": "list", "credential": "x" * 200}
    assert c.post("/api", json=too_long).status_code == 422


def test_mock_siem_app_from_env(lab_env: dict[str, str]) -> None:
    c = TestClient(mock_hec.app_from_env())
    url = "/services/collector/event"
    assert c.post(url, json={"event": {}}).status_code == 401
    ok = c.post(
        url,
        json={"event": {"event": "handshake"}},
        headers={"Authorization": f"Splunk {lab_env['hec']}"},
    )
    assert ok.status_code == 200 and ok.json()["code"] == 0


def test_mock_siem_rejects_oversized_body(lab_env: dict[str, str]) -> None:
    c = TestClient(mock_hec.app_from_env())
    r = c.post(
        "/services/collector/event",
        content=b"x" * (65 * 1024),
        headers={"Authorization": f"Splunk {lab_env['hec']}"},
    )
    assert r.status_code == 413


def test_response_app_from_env_hmac_mode(lab_env: dict[str, str]) -> None:
    c = TestClient(webhook.app_from_env())
    body = b"{}"
    ts = str(int(time.time()))
    bad = c.post("/v1/alerts", content=body, headers={"X-Timestamp": ts, "X-Signature": "0" * 64})
    assert bad.status_code == 401
    good_sig = sign_hmac(lab_env["webhook"].encode(), ts, body)
    schema = c.post(
        "/v1/alerts", content=body, headers={"X-Timestamp": ts, "X-Signature": good_sig}
    )
    assert schema.status_code == 422  # authenticated, but not an Alert
    assert c.get("/v1/incidents/x", headers={"X-Admin-Token": lab_env["admin"]}).status_code == 404


def test_response_app_from_env_path_mode(
    lab_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CQ_WEBHOOK_AUTH", "path")
    c = TestClient(webhook.app_from_env())
    assert c.post(f"/v1/alerts/{'0' * 64}", content=b"{}").status_code == 401
    assert c.post(f"/v1/alerts/{lab_env['webhook']}", content=b"{}").status_code == 422


@pytest.mark.usefixtures("lab_env")
def test_response_app_from_env_requires_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CQ_ADMIN_TOKEN_FILE")
    with pytest.raises(ConfigError):
        webhook.app_from_env()
