"""One-shot KEM handshake binding profile, epoch, key and stream into the session keys.

Message flow (all frames from channel.framing):
  C -> S  KEY_REQUEST(profile_id)
  S -> C  KEY_RESPONSE(profile_id, epoch, key_id, ek)      (public, like a certificate)
  C -> S  HELLO(profile_id, epoch, key_id, stream_id, ct)
  both    K = HKDF(ss, info = label || profile_id || H(transcript))
  C <-> S DATA(seq, AEAD(K_dir, nonce = seq, aad = header || seq))

Downgrade protection: the server only accepts profiles on its allow-list and only
the current, non-revoked key for that profile; the profile id is also bound in
the KDF info and in the transcript, so flipping it on the wire breaks the keys.
"""

from __future__ import annotations

import hashlib
import struct
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from canary_qday.channel.aead import Opener, Sealer
from canary_qday.channel.framing import Frame, FrameType, pack_data, unpack_data
from canary_qday.channel.kdf import derive_session_keys, transcript_hash
from canary_qday.common.errors import FrameError, PolicyError, ReplayError
from canary_qday.hybrid import xwing
from canary_qday.kem import kem
from canary_qday.kem.profiles import PROFILE_IDS, params_for

PROFILE_BY_ID = {v: k for k, v in PROFILE_IDS.items()}
_HELLO_HEAD = struct.Struct(">BI8s16s")  # profile_id, epoch, key_id, stream_id


@dataclass(frozen=True)
class KemSuite:
    """KEM used by a profile: toy K-PKE+FO for RED/ORANGE, X-Wing for GREEN."""

    profile: str
    keygen: Callable[[], tuple[bytes, bytes]]  # -> (ek, dk)
    encaps: Callable[[bytes], tuple[bytes, bytes]]  # ek -> (ss, ct)
    decaps: Callable[[bytes, bytes], bytes]  # (dk, ct) -> ss
    ek_len: int
    ct_len: int


def suite_for(profile: str) -> KemSuite:
    """Return the KEM suite for a profile name."""
    if profile == "GREEN":

        def g_keygen() -> tuple[bytes, bytes]:
            sk, pk = xwing.generate_key_pair()
            return pk, sk

        return KemSuite(
            "GREEN",
            g_keygen,
            xwing.encapsulate,
            lambda dk, ct: xwing.decapsulate(ct, dk),
            xwing.PK_BYTES,
            xwing.CT_BYTES,
        )
    p = params_for(profile)

    def t_encaps(ek: bytes) -> tuple[bytes, bytes]:
        return kem.encaps(p, ek)

    return KemSuite(
        profile,
        lambda: kem.keygen(p),
        t_encaps,
        lambda dk, ct: kem.decaps(p, dk, ct),
        p.ek_bytes,
        p.ct_bytes,
    )


def params_id_for(profile: str) -> str:
    """Identifier of the parameter set behind a profile (used for algorithmic exposure)."""
    return "xwing-mlkem768-x25519" if profile == "GREEN" else params_for(profile).name


def key_id(ek: bytes) -> bytes:
    """key_id = first 8 bytes of SHA3-256(ek) (16 hex chars)."""
    return hashlib.sha3_256(ek).digest()[:8]


@dataclass
class ServerKey:
    """A static server KEM key for (profile, epoch). dk must stay in zone Z4."""

    profile: str
    epoch: int
    ek: bytes
    dk: bytes = field(repr=False)

    @property
    def key_id(self) -> bytes:
        """Identifier derived from the public key."""
        return key_id(self.ek)


class Session:
    """An established channel endpoint."""

    def __init__(
        self, profile: str, stream_id: bytes, transcript: bytes, ss: bytes, *, is_client: bool
    ) -> None:
        self.profile = profile
        self.stream_id = stream_id
        self.transcript = transcript
        keys = derive_session_keys(ss, PROFILE_IDS[profile], transcript)
        send, recv = (keys.c2s, keys.s2c) if is_client else (keys.s2c, keys.c2s)
        self._sealer = Sealer(send)
        self._opener = Opener(recv)

    def seal(self, plaintext: bytes) -> Frame:
        """Encrypt a record into a DATA frame."""
        hdr = Frame(FrameType.DATA, b"").header()
        seq, ct = self._sealer.seal(plaintext, hdr + self.transcript)
        return Frame(FrameType.DATA, pack_data(seq, ct))

    def open(self, frame: Frame) -> bytes:
        """Verify and decrypt a DATA frame."""
        if frame.type != FrameType.DATA:
            raise FrameError("expected DATA frame")
        seq, ct = unpack_data(frame.payload)
        return self._opener.open(seq, ct, frame.header() + self.transcript)


def key_request(profile: str) -> Frame:
    """Build KEY_REQUEST."""
    return Frame(FrameType.KEY_REQUEST, bytes([PROFILE_IDS[profile]]))


def key_response(key: ServerKey) -> Frame:
    """Build KEY_RESPONSE (public data only)."""
    head = struct.pack(">BI8s", PROFILE_IDS[key.profile], key.epoch, key.key_id)
    return Frame(FrameType.KEY_RESPONSE, head + key.ek)


def parse_key_response(frame: Frame) -> tuple[str, int, bytes, bytes]:
    """Return (profile, epoch, key_id, ek) after validating lengths and key_id."""
    if frame.type != FrameType.KEY_RESPONSE or len(frame.payload) < 13:
        raise FrameError("bad KEY_RESPONSE")
    pid, epoch, kid = struct.unpack(">BI8s", frame.payload[:13])
    profile = PROFILE_BY_ID.get(pid)
    if profile is None:
        raise PolicyError("unknown profile")
    ek = frame.payload[13:]
    if len(ek) != suite_for(profile).ek_len or key_id(ek) != kid:
        raise FrameError("KEY_RESPONSE key mismatch")
    return profile, epoch, kid, ek


def client_hello(
    profile: str, epoch: int, ek: bytes, stream_id: bytes
) -> tuple[Frame, Session]:
    """Encapsulate to the server key, return the HELLO frame and the client session."""
    if len(stream_id) != 16:
        raise ValueError("stream_id must be 16 bytes")
    suite = suite_for(profile)
    ss, ct = suite.encaps(ek)
    head = _HELLO_HEAD.pack(PROFILE_IDS[profile], epoch, key_id(ek), stream_id)
    tr = transcript_hash(head, ek, ct)
    return Frame(FrameType.HELLO, head + ct), Session(
        profile, stream_id, tr, ss, is_client=True
    )


@dataclass(frozen=True)
class HelloInfo:
    """Public fields of a HELLO frame."""

    profile: str
    epoch: int
    key_id: bytes
    stream_id: bytes
    ct: bytes


def parse_hello(frame: Frame) -> HelloInfo:
    """Validate and split a HELLO frame (no secrets involved)."""
    if frame.type != FrameType.HELLO or len(frame.payload) < _HELLO_HEAD.size:
        raise FrameError("bad HELLO")
    pid, epoch, kid, sid = _HELLO_HEAD.unpack(frame.payload[: _HELLO_HEAD.size])
    profile = PROFILE_BY_ID.get(pid)
    if profile is None:
        raise PolicyError("unknown profile")
    ct = frame.payload[_HELLO_HEAD.size :]
    if len(ct) != suite_for(profile).ct_len:
        raise FrameError("ciphertext has wrong length")
    return HelloInfo(profile, epoch, kid, sid, ct)


class ServerState:
    """Server-side key store, profile allow-list, revocation list and replay cache."""

    def __init__(self, allowed: set[str], replay_cache_size: int = 100_000) -> None:
        self.allowed = set(allowed)
        self.keys: dict[str, ServerKey] = {}
        self.revoked: set[bytes] = set()
        self._seen: OrderedDict[bytes, None] = OrderedDict()
        self._cache_size = replay_cache_size

    def install(self, key: ServerKey) -> None:
        """Make key the current key for its profile."""
        self.keys[key.profile] = key

    def current(self, profile: str) -> ServerKey:
        """Current key for an allowed profile."""
        if profile not in self.allowed or profile not in self.keys:
            raise PolicyError("profile not allowed")
        return self.keys[profile]

    def accept(self, frame: Frame) -> Session:
        """Validate a HELLO and derive the server session."""
        info = parse_hello(frame)
        key = self.current(info.profile)
        if info.key_id in self.revoked or info.key_id != key.key_id or info.epoch != key.epoch:
            raise PolicyError("stale or revoked key")
        head = frame.payload[: _HELLO_HEAD.size]
        tr = transcript_hash(head, key.ek, info.ct)
        if tr in self._seen:
            raise ReplayError("handshake replay")
        self._seen[tr] = None
        if len(self._seen) > self._cache_size:
            self._seen.popitem(last=False)
        ss = suite_for(info.profile).decaps(key.dk, info.ct)
        return Session(info.profile, info.stream_id, tr, ss, is_client=False)
