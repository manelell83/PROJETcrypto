"""Proxy and generator in one process (no subprocess, no Docker).

The proxy listens on an ephemeral 127.0.0.1 port; the real generator talks to it.
This exercises the proxy's policy handling (allow-list, revocation, IP block,
stopped services, malformed frames) through the public channel API.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from pydantic import BaseModel

from canary_qday.channel import framing
from canary_qday.common import labpolicy
from canary_qday.common.config import Settings
from canary_qday.common.errors import PolicyError
from canary_qday.common.store import Store
from canary_qday.services.proxy import KeyManager, Proxy
from canary_qday.siem.schemas import HandshakeEvent
from canary_qday.traffic import generator


class ListSink:
    """In-memory SiemSink."""

    def __init__(self) -> None:
        self.events: list[BaseModel] = []

    def send(self, event: BaseModel) -> None:
        self.events.append(event)

    def flush(self) -> int:
        return 0


def _settings(tmp: Path, port: int) -> Settings:
    return Settings(
        data_dir=tmp,
        secrets_dir=tmp / "secrets",
        registry_db=tmp / "registry.db",
        response_db=tmp / "response.db",
        policy_file=tmp / "policy.json",
        reports_dir=tmp / "reports",
        canary_base_url="http://127.0.0.1:1",
        proxy_host="127.0.0.1",
        proxy_port=port,
        siem_sink="file",
        hec_url="http://127.0.0.1:1",
        response_url="http://127.0.0.1:1",
    )


def _with_proxy[T](
    tmp: Path,
    body: Callable[[Proxy, Settings], Awaitable[T]],
    policy: labpolicy.LabPolicy | None = None,
) -> tuple[T, ListSink]:
    """Start a proxy on an ephemeral port, run body(proxy, settings), stop the proxy."""
    if policy is not None:
        labpolicy.save(tmp / "policy.json", policy)
    sink = ListSink()
    proxy = Proxy(
        KeyManager(tmp / "secrets"), tmp / "policy.json", Store(tmp / "registry.db"), sink
    )

    async def main() -> T:
        server = await asyncio.start_server(proxy.serve_conn, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            return await body(proxy, _settings(tmp, port))
        finally:
            server.close()
            await server.wait_closed()

    return asyncio.run(main()), sink


def _handshakes(sink: ListSink) -> list[HandshakeEvent]:
    return [e for e in sink.events if isinstance(e, HandshakeEvent)]


ONLY_TOY = labpolicy.LabPolicy(allowed_profiles=["RED", "ORANGE"])


@pytest.mark.parametrize("profile", ["RED", "ORANGE"])
def test_toy_stream_round_trip(tmp_path: Path, profile: str) -> None:
    async def body(_p: Proxy, s: Settings) -> generator.StreamResult:
        return await generator.run_stream(Store(s.registry_db), s, profile)

    res, sink = _with_proxy(tmp_path, body, ONLY_TOY)
    assert res.profile == profile and res.responses == [200, 200]
    rows = Store(tmp_path / "registry.db").streams(stream_id=res.stream_id)
    assert rows and rows[0].key_id == res.key_id and rows[0].ended_at is not None
    ev = _handshakes(sink)
    assert [e.outcome for e in ev] == ["accepted"] and ev[0].key_id == res.key_id
    assert (tmp_path / "secrets" / f"{profile}-e1.dk").exists()


def test_green_stream_round_trip(tmp_path: Path) -> None:
    async def body(_p: Proxy, s: Settings) -> generator.StreamResult:
        return await generator.run_stream(Store(s.registry_db), s, "GREEN", ["billing"])

    res, _ = _with_proxy(tmp_path, body, labpolicy.LabPolicy(allowed_profiles=["GREEN"]))
    assert res.responses == [200, 200]
    row = Store(tmp_path / "registry.db").stream(res.stream_id)
    assert row is not None and row.params_id == "xwing-mlkem768-x25519"


def test_keys_are_reused_across_proxy_restarts(tmp_path: Path) -> None:
    labpolicy.save(tmp_path / "policy.json", ONLY_TOY)
    first = KeyManager(tmp_path / "secrets").get("RED", 1)
    again = KeyManager(tmp_path / "secrets").get("RED", 1)
    assert first.ek == again.ek and first.key_id == again.key_id
    assert KeyManager(tmp_path / "secrets").get("RED", 2).ek != first.ek


def test_disallowed_profile_is_refused(tmp_path: Path) -> None:
    async def body(_p: Proxy, s: Settings) -> None:
        with pytest.raises(PolicyError):
            await generator.run_stream(Store(s.registry_db), s, "RED")

    _with_proxy(tmp_path, body, labpolicy.LabPolicy(allowed_profiles=["ORANGE"]))
    assert Store(tmp_path / "registry.db").streams() == []


def test_run_many_skips_refused_streams(tmp_path: Path) -> None:
    async def body(_p: Proxy, s: Settings) -> list[generator.StreamResult]:
        return await generator.run_many("RED", 2, s)

    res, _ = _with_proxy(tmp_path, body, labpolicy.LabPolicy(allowed_profiles=["ORANGE"]))
    assert res == []


def test_revoked_key_is_refused_and_logged(tmp_path: Path) -> None:
    labpolicy.save(tmp_path / "policy.json", ONLY_TOY)
    kid = KeyManager(tmp_path / "secrets").get("RED", 1).key_id.hex()
    pol = labpolicy.LabPolicy(allowed_profiles=["RED"], revoked_key_ids=[kid])

    async def body(_p: Proxy, s: Settings) -> None:
        with pytest.raises(PolicyError):
            await generator.run_stream(Store(s.registry_db), s, "RED")

    _, sink = _with_proxy(tmp_path, body, pol)
    ev = _handshakes(sink)
    # A revoked key is reported precisely (D2), distinct from other policy refusals.
    assert [(e.outcome, e.reason) for e in ev] == [("refused", "revoked_key")]
    assert ev[0].key_id == kid


def test_policy_change_applies_to_next_connection(tmp_path: Path) -> None:
    async def body(p: Proxy, s: Settings) -> None:
        ok = await generator.run_stream(Store(s.registry_db), s, "RED")
        assert ok.responses == [200, 200]
        await asyncio.sleep(0.05)  # distinct mtime on coarse filesystems
        labpolicy.save(p.policy_file, labpolicy.LabPolicy(allowed_profiles=["ORANGE"]))
        with pytest.raises(PolicyError):
            await generator.run_stream(Store(s.registry_db), s, "RED")

    _with_proxy(tmp_path, body, ONLY_TOY)


def test_blocked_ip_gets_an_error_frame(tmp_path: Path) -> None:
    pol = labpolicy.LabPolicy(allowed_profiles=["RED"], blocked_ips=["127.0.0.1"])

    async def body(_p: Proxy, s: Settings) -> None:
        with pytest.raises(PolicyError):
            await generator.run_stream(Store(s.registry_db), s, "RED")

    _with_proxy(tmp_path, body, pol)


def test_stopped_service_answers_503(tmp_path: Path) -> None:
    pol = labpolicy.LabPolicy(allowed_profiles=["RED"], stopped_services=["billing"])

    async def body(_p: Proxy, s: Settings) -> generator.StreamResult:
        return await generator.run_stream(Store(s.registry_db), s, "RED", ["billing", "hr"])

    res, _ = _with_proxy(tmp_path, body, pol)
    assert res.responses == [503, 200]


async def _raw(s: Settings, payload: bytes) -> framing.Frame | None:
    reader, writer = await asyncio.open_connection(s.proxy_host, s.proxy_port)
    try:
        writer.write(payload)
        await writer.drain()
        try:
            return await asyncio.wait_for(framing.read_frame(reader), timeout=5)
        except Exception:
            return None
    finally:
        writer.close()


@pytest.mark.parametrize(
    ("label", "payload", "code"),
    [
        ("data before hello", framing.encode(framing.FrameType.DATA, b"\x00" * 24), b"E_INTERNAL"),
        (
            "unknown profile id",
            framing.encode(framing.FrameType.KEY_REQUEST, b"\x09"),
            b"E_INTERNAL",
        ),
        (
            "long key request",
            framing.encode(framing.FrameType.KEY_REQUEST, b"\x01\x01"),
            b"E_INTERNAL",
        ),
        ("truncated hello", framing.encode(framing.FrameType.HELLO, b"\x01"), b"E_FRAME"),
    ],
)
def test_malformed_frames_get_an_error_frame(
    tmp_path: Path, label: str, payload: bytes, code: bytes
) -> None:
    async def body(_p: Proxy, s: Settings) -> framing.Frame | None:
        return await _raw(s, payload)

    frame, _ = _with_proxy(tmp_path, body, ONLY_TOY)
    assert frame is not None, label
    assert frame.type == framing.FrameType.ERROR and frame.payload == code


def test_oversized_length_prefix_closes_the_connection(tmp_path: Path) -> None:
    async def body(_p: Proxy, s: Settings) -> framing.Frame | None:
        return await _raw(s, struct.pack(">I", 10_000_000) + b"\x01\x01")

    frame, _ = _with_proxy(tmp_path, body, ONLY_TOY)
    assert frame is None  # read_frame refuses before allocating; the proxy just closes
