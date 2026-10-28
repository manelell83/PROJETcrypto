"""Tests for the lab capture relay and the extractor (lab/attacker/capture, extract).

Three groups: deterministic extraction from a synthetic capture built with the
real channel functions; hostile-input cases that must raise ExtractError (never
crash, never a partial result); and one in-process end-to-end capture with the
real proxy and generator (no Docker). The guard is checked to run before any
socket opens.
"""

from __future__ import annotations

import asyncio
import json
import os
import struct
from pathlib import Path

import pytest

from canary_qday.channel import framing, handshake
from canary_qday.channel.framing import FrameType
from canary_qday.channel.handshake import PROFILE_IDS, parse_hello, suite_for
from canary_qday.common import labpolicy
from canary_qday.common.config import Settings
from canary_qday.common.store import Store
from canary_qday.kem import kem
from canary_qday.kem.profiles import params_for
from canary_qday.services.proxy import KeyManager, Proxy
from canary_qday.traffic import generator
from lab.attacker.capture import CaptureWriter, Relay
from lab.attacker.extract import CapturedStream, ExtractError, extract
from lab.attacker.guard import GuardError


def _write_capture(path: Path, frames: list[tuple[str, bytes]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for direction, raw in frames:
            fh.write(json.dumps({"dir": direction, "frame_hex": raw.hex()}) + "\n")


def _red_handshake_frames() -> tuple[bytes, bytes, bytes, handshake.Session, bytes]:
    """Build a real RED KEY_RESPONSE and HELLO; return their raw bytes and the session."""
    params = params_for("RED")
    ek, _dk = kem.keygen(params)
    kid = handshake.key_id(ek)
    kr_payload = struct.pack(">BI8s", PROFILE_IDS["RED"], 1, kid) + ek
    kr_raw = framing.encode(FrameType.KEY_RESPONSE, kr_payload)
    hello_frame, session = handshake.client_hello("RED", 1, ek, b"\x11" * 16)
    hello_raw = framing.encode(hello_frame.type, hello_frame.payload)
    return ek, kr_raw, hello_raw, session, parse_hello(hello_frame).ct


# --- deterministic extraction -----------------------------------------------------


def test_extract_recovers_public_fields(tmp_path: Path) -> None:
    ek, kr_raw, hello_raw, session, ct = _red_handshake_frames()
    d1 = session.seal(b"request-1")
    d2 = session.seal(b"request-2")
    cap = tmp_path / "c.jsonl"
    _write_capture(
        cap,
        [
            ("c2s", framing.encode(FrameType.KEY_REQUEST, bytes([PROFILE_IDS["RED"]]))),
            ("s2c", kr_raw),
            ("c2s", hello_raw),
            ("c2s", framing.encode(d1.type, d1.payload)),
            ("s2c", framing.encode(d2.type, d2.payload)),
        ],
    )
    result = extract(cap)
    assert isinstance(result, CapturedStream)
    assert result.profile == "RED"
    assert result.epoch == 1
    assert result.ek == ek
    assert result.key_id == handshake.key_id(ek)
    assert result.stream_id == b"\x11" * 16
    assert result.ct == ct
    assert len(result.data_records) == 2
    seqs = [seq for seq, _ in result.data_records]
    assert seqs == sorted(set(seqs))  # distinct, increasing; exact values not asserted
    # The extractor exposes only public/encrypted material, never a secret.
    assert all(len(payload) > 0 for _, payload in result.data_records)


def test_capture_writer_is_restrictive_and_roundtrips(tmp_path: Path) -> None:
    cap = tmp_path / "w.jsonl"
    writer = CaptureWriter(cap)
    writer.record("s2c", framing.Frame(FrameType.ERROR, b"E_X"))
    writer.close()
    line = json.loads(cap.read_text(encoding="utf-8").strip())
    assert line["dir"] == "s2c"
    frame, rest = framing.decode(bytes.fromhex(line["frame_hex"]))
    assert rest == b"" and frame.type is FrameType.ERROR and frame.payload == b"E_X"
    if os.name != "nt":
        assert (cap.stat().st_mode & 0o777) == 0o600


# --- hostile input ----------------------------------------------------------------


def _one_line_capture(tmp_path: Path, raw_hex: str) -> Path:
    cap = tmp_path / "bad.jsonl"
    cap.write_text(json.dumps({"dir": "c2s", "frame_hex": raw_hex}) + "\n", encoding="utf-8")
    return cap


def test_hostile_truncated_length(tmp_path: Path) -> None:
    with pytest.raises(ExtractError):
        extract(_one_line_capture(tmp_path, "00"))


def test_hostile_bad_version(tmp_path: Path) -> None:
    raw = struct.pack(">I", 3) + bytes([2, int(FrameType.KEY_RESPONSE), 0])  # version 2
    with pytest.raises(ExtractError):
        extract(_one_line_capture(tmp_path, raw.hex()))


def test_hostile_oversized_length(tmp_path: Path) -> None:
    raw = struct.pack(">I", framing.MAX_BODY + 1) + bytes([1, int(FrameType.KEY_RESPONSE)])
    with pytest.raises(ExtractError):
        extract(_one_line_capture(tmp_path, raw.hex()))


def test_hostile_unknown_frame_type(tmp_path: Path) -> None:
    raw = struct.pack(">I", 3) + bytes([1, 99, 0])
    with pytest.raises(ExtractError):
        extract(_one_line_capture(tmp_path, raw.hex()))


def test_hostile_trailing_bytes(tmp_path: Path) -> None:
    good = framing.encode(FrameType.KEY_REQUEST, bytes([PROFILE_IDS["RED"]]))
    with pytest.raises(ExtractError):
        extract(_one_line_capture(tmp_path, (good + b"\x00").hex()))


def test_hostile_not_json(tmp_path: Path) -> None:
    cap = tmp_path / "x.jsonl"
    cap.write_text("not json at all\n", encoding="utf-8")
    with pytest.raises(ExtractError):
        extract(cap)


def test_hostile_bad_hex(tmp_path: Path) -> None:
    with pytest.raises(ExtractError):
        extract(_one_line_capture(tmp_path, "zz"))


def test_key_response_without_hello_is_incomplete(tmp_path: Path) -> None:
    _ek, kr_raw, _hello, _session, _ct = _red_handshake_frames()
    cap = tmp_path / "kr.jsonl"
    _write_capture(cap, [("s2c", kr_raw)])
    with pytest.raises(ExtractError, match="HELLO"):
        extract(cap)


def test_hello_without_key_response_is_incomplete(tmp_path: Path) -> None:
    _ek, _kr, hello_raw, _session, _ct = _red_handshake_frames()
    cap = tmp_path / "h.jsonl"
    _write_capture(cap, [("c2s", hello_raw)])
    with pytest.raises(ExtractError, match="KEY_RESPONSE"):
        extract(cap)


def test_empty_capture(tmp_path: Path) -> None:
    cap = tmp_path / "empty.jsonl"
    cap.write_text("", encoding="utf-8")
    with pytest.raises(ExtractError):
        extract(cap)


# --- end-to-end capture through the real proxy (no Docker) ------------------------


def _settings(tmp: Path, proxy_port: int) -> Settings:
    return Settings(
        data_dir=tmp,
        secrets_dir=tmp / "secrets",
        registry_db=tmp / "registry.db",
        response_db=tmp / "response.db",
        policy_file=tmp / "policy.json",
        reports_dir=tmp / "reports",
        canary_base_url="http://127.0.0.1:1",
        proxy_host="127.0.0.1",
        proxy_port=proxy_port,
        siem_sink="file",
        hec_url="http://127.0.0.1:1",
        response_url="http://127.0.0.1:1",
    )


def test_end_to_end_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CQ_LAB", "1")
    labpolicy.save(tmp_path / "policy.json", labpolicy.LabPolicy(allowed_profiles=["RED"]))
    cap_path = tmp_path / "capture.jsonl"

    async def main() -> generator.StreamResult:
        store = Store(tmp_path / "registry.db")
        proxy = Proxy(KeyManager(tmp_path / "secrets"), tmp_path / "policy.json", store, None)
        proxy_server = await asyncio.start_server(proxy.serve_conn, "127.0.0.1", 0)
        proxy_port = proxy_server.sockets[0].getsockname()[1]
        relay = Relay("127.0.0.1", proxy_port, cap_path, "RED")
        relay_server, cap = await relay.start("127.0.0.1", 0)
        relay_port = relay_server.sockets[0].getsockname()[1]
        try:
            return await generator.run_stream(
                store, _settings(tmp_path, relay_port), "RED", ["billing"]
            )
        finally:
            relay_server.close()
            await relay_server.wait_closed()
            proxy_server.close()
            await proxy_server.wait_closed()
            cap.close()

    result = asyncio.run(main())
    assert result.responses == [200, 200]

    expected_ek = KeyManager(tmp_path / "secrets").get("RED", 1).ek
    captured = extract(cap_path)
    assert captured.profile == "RED"
    assert captured.ek == expected_ek
    assert len(captured.ct) == suite_for("RED").ct_len
    assert captured.stream_id.hex() == result.stream_id.replace("-", "")
    assert captured.data_records  # at least the client's DATA requests were captured


def test_relay_guard_refuses_green_nonlab_and_without_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = tmp_path / "c.jsonl"
    monkeypatch.setenv("CQ_LAB", "1")
    with pytest.raises(GuardError):
        asyncio.run(Relay("127.0.0.1", 9, cap, "GREEN").start("127.0.0.1", 0))
    with pytest.raises(GuardError):
        asyncio.run(Relay("8.8.8.8", 9, cap, "RED").start("127.0.0.1", 0))
    monkeypatch.delenv("CQ_LAB", raising=False)
    with pytest.raises(GuardError):
        asyncio.run(Relay("127.0.0.1", 9, cap, "RED").start("127.0.0.1", 0))
    assert not cap.exists()  # guard ran before the capture file was created
