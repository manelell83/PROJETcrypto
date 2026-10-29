"""Access detection rules in the mock SIEM (unauthorized_key_use, refused_handshake_burst).

Threshold/window/cooldown/throttle behaviour, plus proof the trap path is untouched.
Webhook delivery is captured by monkeypatching httpx.post (no real network).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from canary_qday.siem import mock_hec
from canary_qday.siem.schemas import AccessAlert, Alert


def _handshake(
    src_ip: str, reason: str, *, outcome: str = "refused", key_id: str = "a" * 16
) -> dict:
    return {
        "event": "handshake",
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "stream_id": str(uuid.uuid4()),
        "profile": "RED",
        "key_id": key_id,
        "epoch": 1,
        "src_ip": src_ip,
        "outcome": outcome,
        "reason": reason,
    }


def _envelope(ev: dict[str, Any]) -> dict[str, Any]:
    return {"event": ev, "index": "canary", "sourcetype": "canary:event"}


@pytest.fixture
def siem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[mock_hec.MockSiem, list[Any]]:
    sent: list[Any] = []

    def fake_post(url: str, content: bytes, headers: dict[str, str], timeout: float) -> Any:
        sent.append((url, content, headers))
        return httpx.Response(202)

    monkeypatch.setattr(mock_hec.httpx, "post", fake_post)
    monkeypatch.setenv("CQ_ACCESS_BURST_N", "5")
    monkeypatch.setenv("CQ_ACCESS_BURST_WINDOW_S", "30")
    s = mock_hec.MockSiem(
        "hec-token", "http://resp/v1/alerts", "w" * 32, tmp_path / "events.jsonl",
        deliver_async=False, access_webhook_url="http://resp/v1/alerts/access",
    )
    return s, sent


def test_revoked_key_fires_one_high_access_alert(
    siem: tuple[mock_hec.MockSiem, list[Any]]
) -> None:
    s, sent = siem
    alert = s.ingest(_envelope(_handshake("10.0.0.9", "revoked_key")))
    assert isinstance(alert, AccessAlert)
    assert alert.rule == "unauthorized_key_use" and alert.severity == "high"
    assert len(sent) == 1
    url, body, _headers = sent[0]
    assert url == "http://resp/v1/alerts/access"
    assert AccessAlert.model_validate_json(body).event.reason == "revoked_key"


def test_revoked_key_throttled_per_src_and_key(
    siem: tuple[mock_hec.MockSiem, list[Any]]
) -> None:
    s, _ = siem
    ev = _envelope(_handshake("10.0.0.9", "revoked_key", key_id="b" * 16))
    assert s.ingest(ev) is not None
    assert s.ingest(_envelope(_handshake("10.0.0.9", "revoked_key", key_id="b" * 16))) is None
    # A different key_id from the same ip is a distinct alert.
    assert s.ingest(_envelope(_handshake("10.0.0.9", "revoked_key", key_id="c" * 16))) is not None


def test_burst_fires_once_at_threshold_then_cooldown(
    siem: tuple[mock_hec.MockSiem, list[Any]]
) -> None:
    s, _ = siem
    fired = [s.ingest(_envelope(_handshake("10.0.0.7", "E_POLICY"))) for _ in range(5)]
    assert [f for f in fired if f is not None]  # exactly the 5th fires
    kinds = [f for f in fired if isinstance(f, AccessAlert)]
    assert len(kinds) == 1 and kinds[0].rule == "refused_handshake_burst"
    assert kinds[0].severity == "medium"
    # cooldown: immediate further refusals do not re-alert
    assert s.ingest(_envelope(_handshake("10.0.0.7", "E_POLICY"))) is None


def test_below_threshold_does_not_fire(siem: tuple[mock_hec.MockSiem, list[Any]]) -> None:
    s, _ = siem
    fired = [s.ingest(_envelope(_handshake("10.0.0.8", "E_POLICY"))) for _ in range(4)]
    assert all(f is None for f in fired)


def test_burst_window_expiry_resets_counter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mock_hec.httpx, "post", lambda *a, **k: httpx.Response(202))
    monkeypatch.setenv("CQ_ACCESS_BURST_N", "3")
    monkeypatch.setenv("CQ_ACCESS_BURST_WINDOW_S", "10")
    s = mock_hec.MockSiem("t", "http://r/v1/alerts", "w" * 32, tmp_path / "e.jsonl",
                          deliver_async=False)
    # Feed events spaced beyond the window via the internal clock parameter.
    assert s._rule_access(_handshake("ip", "E_POLICY"), received=0.0) is None
    assert s._rule_access(_handshake("ip", "E_POLICY"), received=1.0) is None
    assert s._rule_access(_handshake("ip", "E_POLICY"), received=100.0) is None  # old ones expired
    assert s._rule_access(_handshake("ip", "E_POLICY"), received=101.0) is None
    # three within the window now fire
    assert s._rule_access(_handshake("ip", "E_POLICY"), received=102.0) is not None


def test_accepted_handshake_never_alerts(siem: tuple[mock_hec.MockSiem, list[Any]]) -> None:
    s, sent = siem
    for _ in range(10):
        assert s.ingest(_envelope(_handshake("10.0.0.1", "", outcome="accepted"))) is None
    assert sent == []


def test_non_revoked_single_refusal_does_not_alert(
    siem: tuple[mock_hec.MockSiem, list[Any]]
) -> None:
    s, _ = siem
    assert s.ingest(_envelope(_handshake("10.0.0.2", "E_FRAME"))) is None


def test_trap_path_unchanged(siem: tuple[mock_hec.MockSiem, list[Any]]) -> None:
    """A trap_triggered event still produces a trap Alert, delivered to the trap URL."""
    s, sent = siem
    trap = {
        "event": "trap_triggered", "event_id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(), "token_id": "abcdef12",
        "stream_id": str(uuid.uuid4()), "profile": "RED", "params_id": "toy-n64-k1",
        "key_id": "a" * 16, "epoch": 1, "src_ip": "10.0.0.5", "user_agent": "x",
    }
    alert = s.ingest(_envelope(trap))
    assert isinstance(alert, Alert) and alert.rule == "canary_trap_triggered"
    assert sent and sent[-1][0] == "http://resp/v1/alerts"  # trap URL, not /access
