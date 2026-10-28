"""SEC-003 (guard), SEC-004 (no secrets in logs), SEC-006 (secret files)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from canary_qday.common.config import ConfigError, read_secret, write_secret
from canary_qday.common.logging import JsonFormatter
from canary_qday.common.redact import REDACTED, redact, token_id
from canary_qday.siem.splunk_hec import SplunkHecSink
from lab.attacker import guard


@pytest.fixture
def lab_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CQ_LAB", "1")


def test_guard_requires_lab_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CQ_LAB", raising=False)
    with pytest.raises(guard.GuardError):
        guard.require_lab("RED")


@pytest.mark.usefixtures("lab_on")
@pytest.mark.parametrize("profile", ["GREEN", "ML-KEM-768", "BLUE", ""])
def test_guard_refuses_non_toy_profiles(profile: str) -> None:
    with pytest.raises(guard.GuardError):
        guard.require_lab(profile)


@pytest.mark.usefixtures("lab_on")
@pytest.mark.parametrize("target", ["http://127.0.0.1:8081/t/x", "localhost", "canary", "::1",
                                    "http://proxy:9443"])
def test_guard_accepts_lab_hosts(target: str) -> None:
    guard.require_lab("RED", target)


@pytest.mark.usefixtures("lab_on")
@pytest.mark.parametrize("target", ["https://example.com/t/x", "8.8.8.8", "10.1.2.3", "http:///x"])
def test_guard_refuses_other_hosts(target: str) -> None:
    with pytest.raises(guard.GuardError):
        guard.require_lab("ORANGE", target)


@pytest.mark.usefixtures("lab_on")
def test_guard_extra_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CQ_LAB_HOSTS", "lab-vm-1")
    guard.require_lab("RED", "http://lab-vm-1:8081")


def test_redact_masks_sensitive_fields_and_strings() -> None:
    token = "0123456789abcdef0123456789abcdef"
    data = {
        "token": token, "Authorization": "Splunk abc", "dk": b"\x01",
        "note": f"see http://canary/t/{token} with FAKE-api_key-ABCDEFGHIJKL",
        "nested": [{"password": "x", "ok": 1}],
    }
    out = redact(data)
    dumped = json.dumps(out)
    assert token not in dumped and "FAKE-api_key-ABCDEFGHIJKL" not in dumped
    assert out["token"] == REDACTED and out["Authorization"] == REDACTED
    assert out["nested"][0] == {"password": REDACTED, "ok": 1}
    assert len(token_id(token)) == 8


def test_json_formatter_redacts_extra_fields() -> None:
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "msg /t/%s", ("a" * 32,), None)
    rec.fields = {"credential": "FAKE-db_password-SECRETSECRET", "api_key": "k"}  # type: ignore[attr-defined]
    line = JsonFormatter().format(rec)
    assert "SECRETSECRET" not in line and "a" * 32 not in line
    assert json.loads(line)["api_key"] == REDACTED


def test_hec_sink_never_shows_token_and_buffers_when_down(tmp_path: Path) -> None:
    from canary_qday.siem.schemas import HandshakeEvent

    sink = SplunkHecSink("http://127.0.0.1:9", "HEC-TOKEN-VALUE", tmp_path / "buf.jsonl",
                         timeout=0.5)
    assert "HEC-TOKEN-VALUE" not in repr(sink)
    ev = HandshakeEvent(event_id="e", ts="t", stream_id="s", profile="RED", key_id="k",
                        epoch=1, src_ip="127.0.0.1", outcome="accepted")
    sink.send(ev)
    buffered = (tmp_path / "buf.jsonl").read_text(encoding="utf-8")
    assert '"stream_id": "s"' in buffered and "HEC-TOKEN-VALUE" not in buffered
    assert sink.flush() == 1  # still down: event kept


def test_secret_files(tmp_path: Path) -> None:
    p = tmp_path / "k.dk"
    write_secret(p, b"secret")
    assert read_secret(p) == b"secret"
    if os.name != "nt":
        assert (p.stat().st_mode & 0o777) == 0o600
        p.chmod(0o644)
        with pytest.raises(ConfigError):
            read_secret(p)
    with pytest.raises(ConfigError):
        read_secret(tmp_path / "missing")
