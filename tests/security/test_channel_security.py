"""FR-005: channel security guarantees, tested only against mechanisms that exist.

Real guarantees in the code:
- `aead.Opener.open` raises `AuthError` on a bad tag and `ReplayError` on a
  sequence number that is not the next expected one (replay or reorder).
- `handshake.ServerState.accept` raises `ReplayError` on a repeated HELLO
  (transcript cache) and `PolicyError` on a profile not on the allow-list, a
  revoked key_id, or an epoch/key_id mismatch.
- The profile is bound into the HELLO header and the transcript; a flipped
  profile id is rejected (the ciphertext length no longer matches the profile,
  or the profile is not allowed).

No anti-replay window or guarantee beyond the above is assumed.
"""

from __future__ import annotations

import pytest

from canary_qday.channel.framing import Frame, FrameType, pack_data, unpack_data
from canary_qday.channel.handshake import (
    PROFILE_IDS,
    ServerKey,
    ServerState,
    Session,
    client_hello,
)
from canary_qday.common.errors import AuthError, CanaryError, PolicyError, ReplayError
from canary_qday.kem import kem
from canary_qday.kem.profiles import params_for

STREAM_ID = b"\x11" * 16


def _pair(
    *, allowed: set[str] | None = None, profile: str = "RED", epoch: int = 1, install_epoch: int = 1
) -> tuple[ServerKey, ServerState, Frame, Session]:
    """A fresh (server key, server state, client HELLO, client session) tuple."""
    ek, dk = kem.keygen(params_for(profile))
    key = ServerKey(profile, install_epoch, ek, dk)
    state = ServerState({profile} if allowed is None else allowed)
    state.install(key)
    hello, client = client_hello(profile, epoch, ek, STREAM_ID)
    return key, state, hello, client


def test_round_trip_baseline() -> None:
    _key, state, hello, client = _pair()
    server = state.accept(hello)
    frame = client.seal(b'{"service":"billing"}')
    assert server.open(frame) == b'{"service":"billing"}'


def test_aead_tamper_is_rejected() -> None:
    _key, state, hello, client = _pair()
    server = state.accept(hello)
    seq, ct = unpack_data(client.seal(b"payload").payload)
    tampered = bytearray(ct)
    tampered[-1] ^= 1  # flip a tag byte
    with pytest.raises(AuthError):
        server.open(Frame(FrameType.DATA, pack_data(seq, bytes(tampered))))


def test_data_replay_is_rejected() -> None:
    _key, state, hello, client = _pair()
    server = state.accept(hello)
    frame = client.seal(b"once")
    assert server.open(frame) == b"once"
    with pytest.raises(ReplayError):
        server.open(frame)  # same record again


def test_data_reorder_is_rejected() -> None:
    _key, state, hello, client = _pair()
    server = state.accept(hello)
    client.seal(b"first")  # seq 0, not delivered
    second = client.seal(b"second")  # seq 1
    with pytest.raises(ReplayError):
        server.open(second)  # expected seq 0, got 1


def test_hello_replay_is_rejected() -> None:
    _key, state, hello, _client = _pair()
    state.accept(hello)
    with pytest.raises(ReplayError):
        state.accept(hello)  # identical transcript seen before


def test_profile_not_on_allow_list_is_rejected() -> None:
    _key, state, hello, _client = _pair(allowed={"ORANGE"})
    with pytest.raises(PolicyError):
        state.accept(hello)


def test_revoked_key_is_rejected() -> None:
    key, state, hello, _client = _pair()
    state.revoked.add(key.key_id)
    with pytest.raises(PolicyError):
        state.accept(hello)


def test_epoch_mismatch_is_rejected() -> None:
    # Client speaks epoch 1; the server's current key is epoch 2.
    _key, state, hello, _client = _pair(epoch=1, install_epoch=2)
    with pytest.raises(PolicyError):
        state.accept(hello)


def test_downgraded_profile_id_is_rejected() -> None:
    _key, state, hello, _client = _pair(allowed={"RED"})
    head = bytearray(hello.payload)
    head[0] = PROFILE_IDS["ORANGE"]  # claim ORANGE over a RED handshake
    tampered = Frame(FrameType.HELLO, bytes(head))
    # Rejected: the profile is bound to the ciphertext length (and the allow-list).
    with pytest.raises(CanaryError):
        state.accept(tampered)
