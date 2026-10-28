"""Crypto profiles (RED / ORANGE / GREEN) and toy parameter candidates.

Toy sets keep q = 3329 and the full ML-KEM structure (K-PKE + FO transform with
implicit rejection) but use a small ring degree n and schoolbook multiplication.
They are deliberately weak and exist only to be broken inside the lab.

Which candidate backs RED and ORANGE is decided by measurement (DFR, experiment
E4; attack cost, experiment E3) and recorded in docs/calibration.md.

The helpers at the bottom expose the *public* LWE instance hidden in a toy
encapsulation key. They are what lab/attacker is allowed to import.
"""

from __future__ import annotations

from canary_qday.kem import kpke
from canary_qday.kem.codec import byte_decode_vec, byte_encode_vec
from canary_qday.kem.params import ML_KEM_768, Params
from canary_qday.kem.sampling import G, H

# Candidate family used by calibration (E3/E4). n >= 64 keeps the K-PKE message
# at >= 64 bits, so brute-forcing m is not a shortcut around the lattice attack.
TOY_CANDIDATES: dict[str, Params] = {
    p.name: p
    for p in (
        Params("toy-n64-k1", 64, 1, 2, 2, 10, 4),
        Params("toy-n64-k2", 64, 2, 2, 2, 10, 4),
        Params("toy-n64-k3", 64, 3, 2, 2, 10, 4),
        Params("toy-n128-k2", 128, 2, 2, 2, 10, 4),
        Params("toy-n64-k1-du4dv2", 64, 1, 2, 2, 4, 2),
        Params("toy-n64-k2-du4dv2", 64, 2, 2, 2, 4, 2),
    )
}

# Calibrated choice (see docs/calibration.md for the measurements behind it).
PROFILE_PARAMS: dict[str, Params] = {
    "RED": TOY_CANDIDATES["toy-n64-k1"],
    "ORANGE": TOY_CANDIDATES["toy-n64-k2"],
    "GREEN": ML_KEM_768,  # used inside X-Wing, never attacked
}

PROFILE_IDS: dict[str, int] = {"RED": 1, "ORANGE": 2, "GREEN": 3}
TOY_PROFILES = frozenset({"RED", "ORANGE"})


def params_for(profile: str) -> Params:
    """Return the KEM parameters backing a profile name."""
    try:
        return PROFILE_PARAMS[profile]
    except KeyError:
        raise ValueError("unknown profile") from None


def is_toy(params: Params) -> bool:
    """True when params are a toy set (never a FIPS 203 set)."""
    return not params.is_standard and params.n < 256


def rot_matrix(a: list[int], q: int) -> list[list[int]]:
    """Integer matrix M with M @ s == a * s mod (X^n + 1) (column j = a * X^j)."""
    n = len(a)
    cols = []
    for j in range(n):
        col = [0] * n
        for i, c in enumerate(a):
            idx = i + j
            if idx < n:
                col[idx] = c % q
            else:
                col[idx - n] = (-c) % q
        cols.append(col)
    return [[cols[j][i] for j in range(n)] for i in range(n)]


def public_instance(params: Params, ek: bytes) -> tuple[list[list[int]], list[int]]:
    """Flatten a toy ek into plain LWE form: t = A s + e (mod q), A of size kn x kn."""
    if not is_toy(params):
        raise ValueError("public_instance is only defined for toy parameters")
    n, k = params.n, params.k
    t_vec = byte_decode_vec(ek[: params.dk_pke_bytes], 12, n, k)
    a_mod = kpke.expand_a(params, ek[params.dk_pke_bytes :])
    big = [[0] * (n * k) for _ in range(n * k)]
    for i in range(k):
        for j in range(k):
            blk = rot_matrix(a_mod[i][j], params.q)
            for r in range(n):
                big[i * n + r][j * n : (j + 1) * n] = blk[r]
    return big, [c for p in t_vec for c in p]


def shared_secret_from_secret(
    params: Params, ek: bytes, s: list[int], ct: bytes
) -> bytes:
    """Given a recovered secret s (flattened, centred or mod q), recover K from ct.

    Mirrors Decaps without the re-encryption check: decrypt m, then K = G(m || H(ek)).
    """
    n, k = params.n, params.k
    polys = [[x % params.q for x in s[i * n : (i + 1) * n]] for i in range(k)]
    m = kpke.decrypt(params, byte_encode_vec(polys, 12), ct)
    return G(m + H(ek))[0]
