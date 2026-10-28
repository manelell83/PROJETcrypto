"""Tests for the full attacker chain (lab/attacker/recover.py).

What is proven here, and what is deliberately NOT:
- `solve_within_budget` recovers a planted secret on a tiny synthetic instance,
  and refuses an over-budget dimension without running LLL.
- `recover_secret`/`run_attack` on the real RED profile stop cleanly with
  `key-not-recovered` (BKZ required) -- never a false success.
- `test_decrypt_chain_with_known_secret` checks the POST-RECOVERY steps (shared
  secret, AEAD decryption of real captured traffic). It feeds the secret read
  from dk, NOT a secret broken by LLL; it is not evidence that LLL broke RED.
- `trigger_trap` reaches a real in-process canary, refuses a non-lab host, and
  does not follow redirects.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from canary_qday.common import labpolicy
from canary_qday.common.config import Settings
from canary_qday.common.errors import CanaryError
from canary_qday.common.store import Store
from canary_qday.kem.codec import byte_decode_vec
from canary_qday.kem.profiles import params_for
from canary_qday.services import canary_server
from canary_qday.services.proxy import KeyManager, Proxy
from canary_qday.siem.schemas import TrapEvent
from canary_qday.traffic import generator
from canary_qday.traffic.registry import register_stream
from lab.attacker.capture import Relay
from lab.attacker.extract import extract
from lab.attacker.guard import GuardError
from lab.attacker.recover import (
    DEFAULT_MAX_DIM,
    decrypt_stream,
    embedding_dimension,
    find_trap,
    recover_secret,
    recover_shared_secret,
    run_attack,
    solve_within_budget,
    trigger_trap,
)


class ListSink:
    def __init__(self) -> None:
        self.events: list[BaseModel] = []

    def send(self, event: BaseModel) -> None:
        self.events.append(event)

    def flush(self) -> int:
        return 0


@contextlib.contextmanager
def _serve(app: FastAPI) -> Iterator[str]:
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        if not server.started:
            raise RuntimeError("server did not start")
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _settings(tmp: Path, proxy_port: int, canary_base: str) -> Settings:
    return Settings(
        data_dir=tmp,
        secrets_dir=tmp / "secrets",
        registry_db=tmp / "registry.db",
        response_db=tmp / "response.db",
        policy_file=tmp / "policy.json",
        reports_dir=tmp / "reports",
        canary_base_url=canary_base,
        proxy_host="127.0.0.1",
        proxy_port=proxy_port,
        siem_sink="file",
        hec_url="http://127.0.0.1:1",
        response_url="http://127.0.0.1:1",
    )


def _capture_red(tmp: Path, canary_base: str = "http://canary") -> Path:
    """Capture one real RED stream through the lab relay; return the capture path."""
    labpolicy.save(tmp / "policy.json", labpolicy.LabPolicy(allowed_profiles=["RED"]))
    cap_path = tmp / "capture.jsonl"

    async def main() -> None:
        store = Store(tmp / "registry.db")
        proxy = Proxy(KeyManager(tmp / "secrets"), tmp / "policy.json", store, None)
        proxy_server = await asyncio.start_server(proxy.serve_conn, "127.0.0.1", 0)
        proxy_port = proxy_server.sockets[0].getsockname()[1]
        relay = Relay("127.0.0.1", proxy_port, cap_path, "RED")
        relay_server, cap = await relay.start("127.0.0.1", 0)
        relay_port = relay_server.sockets[0].getsockname()[1]
        try:
            res = await generator.run_stream(
                store, _settings(tmp, relay_port, canary_base), "RED", ["billing"]
            )
            assert res.responses == [200, 200]
        finally:
            relay_server.close()
            await relay_server.wait_closed()
            proxy_server.close()
            await proxy_server.wait_closed()
            cap.close()

    asyncio.run(main())
    return cap_path


def _secret_from_dk(params: object, dk: bytes) -> list[int]:  # type: ignore[no-untyped-def]
    polys = byte_decode_vec(dk[: params.dk_pke_bytes], 12, params.n, params.k)  # type: ignore[attr-defined]
    return [c for poly in polys for c in poly]


# --- dimension budget -------------------------------------------------------------


def test_solve_within_budget_recovers_tiny_synthetic() -> None:
    import random

    n, q, eta = 4, 257, 1
    rng = random.Random("recover:tiny")
    a = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]
    s = [rng.randint(-eta, eta) for _ in range(n)]
    e = [rng.randint(-eta, eta) for _ in range(n)]
    t = [(sum(a[i][j] * s[j] for j in range(n)) + e[i]) % q for i in range(n)]
    recovered = solve_within_budget(a, t, q, eta, max_dim=2 * n + 1)
    assert recovered == s  # planted s is already in (-eta, eta), i.e. centred


def test_budget_boundary() -> None:
    import random

    n, q, eta = 4, 257, 1
    dim = 2 * n + 1  # 9
    rng = random.Random("recover:boundary")
    a = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]
    s = [rng.randint(-eta, eta) for _ in range(n)]
    e = [rng.randint(-eta, eta) for _ in range(n)]
    t = [(sum(a[i][j] * s[j] for j in range(n)) + e[i]) % q for i in range(n)]
    assert solve_within_budget(a, t, q, eta, max_dim=dim) is not None  # exactly at budget
    assert solve_within_budget(a, t, q, eta, max_dim=dim - 1) is None  # one over: refused


def test_embedding_dimension_of_real_profiles() -> None:
    assert embedding_dimension(params_for("RED")) == 129
    assert embedding_dimension(params_for("ORANGE")) == 257
    assert embedding_dimension(params_for("RED")) > DEFAULT_MAX_DIM


# --- post-recovery chain on real captured traffic (known secret) ------------------


def test_decrypt_chain_with_known_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies shared-secret recovery and AEAD decryption of REAL captured RED
    traffic, using the secret read from dk. This exercises the steps AFTER key
    recovery; it is NOT a demonstration that LLL broke RED."""
    monkeypatch.setenv("CQ_LAB", "1")
    cap_path = _capture_red(tmp_path)
    captured = extract(cap_path)
    params = params_for("RED")

    dk = KeyManager(tmp_path / "secrets").get("RED", 1).dk
    ss = recover_shared_secret(params, captured.ek, _secret_from_dk(params, dk), captured.ct)
    plaintexts = decrypt_stream(captured, ss)

    assert plaintexts, "no client DATA record decrypted"
    payload = json.loads(plaintexts[0])
    assert payload["stream_id"].replace("-", "") == captured.stream_id.hex()
    assert find_trap(plaintexts) is not None


def test_decrypt_with_wrong_secret_yields_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    cap_path = _capture_red(tmp_path)
    captured = extract(cap_path)
    wrong_ss = b"\x00" * 32
    assert decrypt_stream(captured, wrong_ss) == []  # AEAD rejects every record


# --- trap trigger -----------------------------------------------------------------


def test_trigger_trap_hits_real_canary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    store = Store(tmp_path / "registry.db")
    sink = ListSink()
    with _serve(canary_server.create_app(store, sink)) as base:
        issued = register_stream(
            store, profile="RED", params_id="toy-n64-k1", key_id="aa" * 8, epoch=1,
            services=["billing"], canary_base_url=base, now=time.time(),
        )
        code = trigger_trap(issued.trap_url, timeout=5.0)
    assert code == 200
    assert any(isinstance(ev, TrapEvent) for ev in sink.events)


def test_trigger_trap_refuses_non_lab_host() -> None:
    with pytest.raises(GuardError):
        trigger_trap("http://8.8.8.8/t/" + "a" * 32)


def test_trigger_trap_rejects_non_http_scheme() -> None:
    with pytest.raises(CanaryError):
        trigger_trap("file:///etc/passwd")


def test_trigger_trap_does_not_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()

    @app.get("/t/{token}")
    async def redirect(token: str) -> RedirectResponse:
        return RedirectResponse("http://8.8.8.8/stolen", status_code=307)

    with _serve(app) as base:
        code = trigger_trap(f"{base}/t/{'a' * 32}", timeout=5.0)
    assert code == 307  # the 3xx is returned, the external target is never fetched


# --- whole chain on the real RED profile stops cleanly ----------------------------


def test_run_attack_on_red_is_key_not_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    cap_path = _capture_red(tmp_path)
    result = run_attack(cap_path, params_for("RED"))
    assert result.status == "key-not-recovered"
    assert "BKZ" in result.detail
    assert result.http_status is None


def test_recover_secret_on_red_refuses_without_running_lll() -> None:
    params = params_for("RED")

    class _Cap:
        ek = b""  # never parsed: the budget check returns before touching ek

    result = recover_secret(_Cap(), params)  # type: ignore[arg-type]
    assert result.status == "key-not-recovered" and result.secret is None
    assert str(embedding_dimension(params)) in result.detail


@pytest.mark.skip(
    reason="A full key recovery on the real RED profile needs BKZ (deferred increment); "
    "LLL-only cannot reach the 129-dim embedding. See docs/m8-status.md."
)
def test_full_real_red_recovery() -> None:  # pragma: no cover
    pass
