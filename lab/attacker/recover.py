"""Full attacker chain on a captured toy stream (M8 increment 4).

Orchestrates: extract -> recover the LWE secret with LLL -> recover the shared
secret -> decrypt the client DATA records -> find and trigger the trap. Each
step is real; nothing is simulated.

Honest limitation: `solve_lwe` uses LLL only, whose approximation factor grows
exponentially with the dimension. The primal embedding has dimension 2*N+1
(N = n*k), so the real toy profiles (RED N=64 -> 129, ORANGE N=128 -> 257) are
far above what LLL can solve. `recover_secret` therefore refuses any instance
whose embedding dimension exceeds a documented budget and returns the explicit
status ``key-not-recovered`` (BKZ required) **without** launching a doomed
reduction. A real RED/ORANGE break needs the deferred BKZ increment.

`trigger_trap` only ever reaches a lab host (guard) and never follows redirects,
so it cannot be turned into an arbitrary HTTP client.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

import httpx

from canary_qday.channel.framing import Frame, FrameType, pack_data
from canary_qday.channel.handshake import Session
from canary_qday.channel.kdf import transcript_hash
from canary_qday.common.errors import CanaryError
from canary_qday.kem.params import Params
from canary_qday.kem.profiles import PROFILE_IDS, public_instance, shared_secret_from_secret
from lab.attacker.extract import CapturedStream
from lab.attacker.guard import require_lab_host
from lab.attacker.lattice import solve_lwe

#: LLL budget: the primal embedding has dimension 2*N+1. Above this, LLL cannot
#: reach the planted vector in practice, so the attack reports failure instead of
#: running for hours. Tiny instances (N up to ~19) stay solvable; RED (129) and
#: ORANGE (257) are refused. Raising this does not make LLL succeed on RED.
DEFAULT_MAX_DIM = 40

#: Mirrors channel.handshake._HELLO_HEAD; the known-secret decrypt test fails loudly
#: if this ever drifts from the real header, so the duplication is self-checking.
_HELLO_HEAD = struct.Struct(">BI8s16s")

_TRAP_URL = re.compile(r"https?://[^\s\"']+/t/[0-9a-f]{32}")


@dataclass(frozen=True)
class SecretResult:
    """Outcome of the LWE step. ``secret`` is None unless ``status == 'recovered'``."""

    status: str
    secret: list[int] | None
    detail: str


@dataclass(frozen=True)
class AttackResult:
    """Outcome of the whole chain, with the real status of each step."""

    status: str
    detail: str
    stream_id: str
    http_status: int | None = None
    trap_url: str | None = None


def embedding_dimension(params: Params) -> int:
    """Dimension of the primal (Kannan) embedding for this parameter set."""
    return 2 * params.n * params.k + 1


def solve_within_budget(
    a_matrix: list[list[int]], t: list[int], q: int, bound: int, max_dim: int
) -> list[int] | None:
    """Run LLL-based solve only when the embedding dimension is within budget."""
    if 2 * len(a_matrix) + 1 > max_dim:
        return None  # over budget: refuse before running LLL
    return solve_lwe(a_matrix, t, q, bound)


def recover_secret(
    captured: CapturedStream, params: Params, *, max_dim: int = DEFAULT_MAX_DIM
) -> SecretResult:
    """Recover the toy secret from the captured ek, or report why not."""
    dim = embedding_dimension(params)
    if dim > max_dim:
        return SecretResult(
            "key-not-recovered",
            None,
            f"embedding dimension {dim} exceeds the LLL budget {max_dim}; BKZ required",
        )
    a_matrix, t = public_instance(params, captured.ek)
    secret = solve_lwe(a_matrix, t, params.q, bound=params.eta1)
    if secret is None:
        return SecretResult("key-not-recovered", None, "LLL did not reach the planted vector")
    return SecretResult("recovered", secret, "secret recovered by LLL")


def recover_shared_secret(
    params: Params, ek: bytes, secret: list[int], ct: bytes
) -> bytes:
    """Reconstruct the KEM shared secret from a recovered secret key."""
    return shared_secret_from_secret(params, ek, secret, ct)


def decrypt_stream(captured: CapturedStream, shared_secret: bytes) -> list[bytes]:
    """Decrypt the client->server DATA records using the recovered shared secret.

    Rebuilds the transcript the client bound into the key schedule and opens the
    DATA frames as the server endpoint. Server->client records use the other
    direction key and are skipped.
    """
    head = _HELLO_HEAD.pack(
        PROFILE_IDS[captured.profile], captured.epoch, captured.key_id, captured.stream_id
    )
    transcript = transcript_hash(head, captured.ek, captured.ct)
    session = Session(
        captured.profile, captured.stream_id, transcript, shared_secret, is_client=False
    )
    plaintexts: list[bytes] = []
    for seq, ciphertext in captured.data_records:
        try:
            plaintexts.append(session.open(Frame(FrameType.DATA, pack_data(seq, ciphertext))))
        except CanaryError:
            continue  # wrong-direction record (server->client): not openable here
    return plaintexts


def find_trap(plaintexts: list[bytes]) -> str | None:
    """Return the first canary trap URL found in the decrypted payloads."""
    for raw in plaintexts:
        match = _TRAP_URL.search(raw.decode("utf-8", errors="replace"))
        if match:
            return match.group(0)
    return None


def trigger_trap(url: str, *, timeout: float = 5.0) -> int:
    """GET the trap URL, restricted to a lab host and never following redirects.

    The guard refuses any host that is not loopback or a known lab service, so
    this cannot be used as a general HTTP client. Redirects are not followed, so
    a lab endpoint cannot bounce the request to an external host.
    """
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in ("http", "https"):
        raise CanaryError("trap URL must be http(s)")
    require_lab_host(url)
    response = httpx.get(url, follow_redirects=False, timeout=timeout)
    return response.status_code


def run_attack(
    capture_path: Path, params: Params, *, max_dim: int = DEFAULT_MAX_DIM, timeout: float = 5.0
) -> AttackResult:
    """Run the whole chain on a capture and return the real status of each step."""
    from lab.attacker.extract import extract

    captured = extract(capture_path)
    sid = captured.stream_id.hex()
    secret = recover_secret(captured, params, max_dim=max_dim)
    if secret.secret is None:
        return AttackResult("key-not-recovered", secret.detail, sid)
    shared = recover_shared_secret(params, captured.ek, secret.secret, captured.ct)
    plaintexts = decrypt_stream(captured, shared)
    url = find_trap(plaintexts)
    if url is None:
        return AttackResult("decrypted-no-trap", "no trap URL in the decrypted payloads", sid)
    code = trigger_trap(url, timeout=timeout)
    return AttackResult("trap-triggered", "trap used through the proxy", sid, code, url)
