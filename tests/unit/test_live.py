"""Tests for the shared live-attack helper (lab/attacker/live.py).

These run the capture against an in-process proxy in a single event loop (fast,
deterministic). The full subprocess lab is NOT started here: `run.py attack` and
the scenario `--real-attack` flag reuse `capture_and_attack`, whose capture path
is exactly `capture_stream` tested below; a full-lab test would be slow and flaky
and is intentionally omitted.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from canary_qday.common import labpolicy
from canary_qday.common.config import Settings
from canary_qday.common.store import Store
from canary_qday.kem.profiles import params_for
from canary_qday.services.proxy import KeyManager, Proxy
from lab.attacker.guard import GuardError
from lab.attacker.live import capture_and_attack, capture_stream
from lab.attacker.recover import run_attack


def _settings(tmp: Path, proxy_port: int) -> Settings:
    return Settings(
        data_dir=tmp,
        secrets_dir=tmp / "secrets",
        registry_db=tmp / "registry.db",
        response_db=tmp / "response.db",
        policy_file=tmp / "policy.json",
        reports_dir=tmp / "reports",
        canary_base_url="http://canary",
        proxy_host="127.0.0.1",
        proxy_port=proxy_port,
        siem_sink="file",
        hec_url="http://127.0.0.1:1",
        response_url="http://127.0.0.1:1",
    )


def test_capture_stream_then_attack_is_honest_on_red(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    labpolicy.save(tmp_path / "policy.json", labpolicy.LabPolicy(allowed_profiles=["RED"]))
    cap = tmp_path / "capture.jsonl"

    async def main() -> None:
        store = Store(tmp_path / "registry.db")
        proxy = Proxy(KeyManager(tmp_path / "secrets"), tmp_path / "policy.json", store, None)
        server = await asyncio.start_server(proxy.serve_conn, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            await capture_stream(_settings(tmp_path, port), cap, "RED")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(main())

    assert cap.exists() and cap.stat().st_size > 0  # capture is non-empty
    result = run_attack(cap, params_for("RED"))
    assert result.status == "key-not-recovered"  # honest: LLL cannot break RED
    assert "BKZ" in result.detail
    assert result.http_status is None


def test_capture_and_attack_refuses_green(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    cap = tmp_path / "c.jsonl"
    with pytest.raises(GuardError):
        capture_and_attack(_settings(tmp_path, 9), cap, "GREEN")
    assert not cap.exists()  # guard ran before any socket or capture file


def test_capture_and_attack_requires_lab_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CQ_LAB", raising=False)
    with pytest.raises(GuardError):
        capture_and_attack(_settings(tmp_path, 9), tmp_path / "c.jsonl", "RED")


def test_via_relay_settings_only_changes_port(tmp_path: Path) -> None:
    base = _settings(tmp_path, 9443)
    via = replace(base, proxy_port=55000)
    assert via.proxy_port == 55000
    assert via.registry_db == base.registry_db and via.proxy_host == base.proxy_host
