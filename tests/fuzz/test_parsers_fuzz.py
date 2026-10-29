"""SEC-005: property-based and fuzz tests for the parsers (Hypothesis).

Each parser is fed arbitrary bytes and must either return a well-formed value or
raise a *typed* exception from the project's own hierarchy -- never a raw crash
and never a leak. Round-trip properties check the encoders against the decoders.

Scope note (honest): Hypothesis runs a bounded number of examples per property
(derandomised for reproducibility, NFR-004), not the 10^5 inputs named in
SEC-005. This exercises the parsers broadly and deterministically; a 10^5-input
campaign is not run here.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from canary_qday.channel import framing
from canary_qday.channel.framing import FrameType
from canary_qday.common.errors import CanaryError, FrameError
from canary_qday.kem import kem
from canary_qday.kem.codec import byte_decode, byte_decode_vec, byte_encode, byte_encode_vec
from canary_qday.kem.ntt import intt, ntt
from canary_qday.kem.params import Q
from canary_qday.kem.profiles import params_for
from lab.attacker.extract import ExtractError, extract

FUZZ = settings(max_examples=300, deadline=None, derandomize=True)
PROP = settings(max_examples=200, deadline=None, derandomize=True)

blobs = st.binary(min_size=0, max_size=4 * 1024)


# --- framing --------------------------------------------------------------------


@FUZZ
@given(blobs)
def test_framing_decode_never_crashes(data: bytes) -> None:
    try:
        frame, rest = framing.decode(data)
    except FrameError:
        return
    assert isinstance(frame.type, FrameType)
    assert isinstance(rest, bytes)


@FUZZ
@given(blobs)
def test_framing_decode_body_never_crashes(data: bytes) -> None:
    try:
        frame = framing.decode_body(data)
    except FrameError:
        return
    assert isinstance(frame.type, FrameType)


@PROP
@given(st.sampled_from(list(FrameType)), st.binary(min_size=0, max_size=4096))
def test_framing_round_trip(ftype: FrameType, payload: bytes) -> None:
    frame, rest = framing.decode(framing.encode(ftype, payload))
    assert frame.type is ftype and frame.payload == payload and rest == b""


@PROP
@given(st.integers(min_value=0, max_value=(1 << 64) - 1), st.binary(min_size=0, max_size=256))
def test_data_pack_round_trip(seq: int, ct: bytes) -> None:
    got_seq, got_ct = framing.unpack_data(framing.pack_data(seq, ct + b"\x00" * 24))
    assert got_seq == seq and got_ct == ct + b"\x00" * 24


# --- codec ----------------------------------------------------------------------


@PROP
@given(st.lists(st.integers(min_value=0, max_value=Q - 1), min_size=256, max_size=256))
def test_byte_encode_decode_round_trip(coeffs: list[int]) -> None:
    assert byte_decode(byte_encode(coeffs, 12), 12, 256) == coeffs


@PROP
@given(st.lists(st.integers(min_value=0, max_value=Q - 1), min_size=256, max_size=256))
def test_ntt_round_trip(coeffs: list[int]) -> None:
    assert intt(ntt(coeffs)) == coeffs


@FUZZ
@given(st.binary(min_size=0, max_size=2048))
def test_byte_decode_arbitrary_bytes(data: bytes) -> None:
    try:
        poly = byte_decode(data, 12, 256)
    except ValueError:
        return
    assert len(poly) == 256


@FUZZ
@given(st.binary(min_size=0, max_size=4096))
def test_byte_decode_vec_arbitrary_bytes(data: bytes) -> None:
    try:
        vec = byte_decode_vec(data, 12, 64, 1)
    except ValueError:
        return
    assert len(vec) == 1 and byte_encode_vec(vec, 12) == data


# --- KEM input checks (FIPS 203 7.2/7.3) ----------------------------------------


@FUZZ
@given(st.binary(min_size=0, max_size=2048))
def test_check_ek_raises_only_typed(data: bytes) -> None:
    params = params_for("RED")
    try:
        kem.check_ek(params, data)
    except ValueError:  # KemInputError is a ValueError
        return
    assert len(data) == params.ek_bytes


@FUZZ
@given(st.binary(min_size=0, max_size=2048))
def test_check_ct_raises_only_typed(data: bytes) -> None:
    params = params_for("RED")
    try:
        kem.check_ct(params, data)
    except ValueError:
        return
    assert len(data) == params.ct_bytes


# --- capture extractor ----------------------------------------------------------


@FUZZ
@given(st.binary(min_size=0, max_size=1024))
def test_extract_on_arbitrary_frame_hex_never_crashes(raw: bytes) -> None:
    cap = _tmp_capture(json.dumps({"dir": "c2s", "frame_hex": raw.hex()}))
    try:
        extract(cap)
    except ExtractError:
        return
    finally:
        cap.unlink(missing_ok=True)
    # If it did not raise, extract returned a CapturedStream: acceptable only if the
    # random bytes happened to form a valid KEY_RESPONSE+HELLO, which is astronomically
    # unlikely; either way no uncaught exception escaped.


@FUZZ
@given(st.text(max_size=256))
def test_extract_on_arbitrary_text_lines(line: str) -> None:
    cap = _tmp_capture(line)
    try:
        extract(cap)
    except (ExtractError, CanaryError):
        return
    finally:
        cap.unlink(missing_ok=True)


def _tmp_capture(line: str) -> Path:
    path = Path("var") / f"fuzz-capture-{uuid.uuid4().hex}.jsonl"
    path.write_text(line + "\n", encoding="utf-8")
    return path
