"""Sampling algorithms (FIPS 203, Algorithms 7-8) and the hash/XOF wrappers (4.1)."""

from __future__ import annotations

import hashlib

from canary_qday.kem.codec import bytes_to_bits
from canary_qday.kem.params import Q

Poly = list[int]


def H(data: bytes) -> bytes:  # noqa: N802 - FIPS 203 naming
    """H = SHA3-256."""
    return hashlib.sha3_256(data).digest()


def J(data: bytes) -> bytes:  # noqa: N802
    """J = SHAKE256(., 32 bytes), used for implicit rejection."""
    return hashlib.shake_256(data).digest(32)


def G(data: bytes) -> tuple[bytes, bytes]:  # noqa: N802
    """G = SHA3-512, split into two 32-byte halves."""
    out = hashlib.sha3_512(data).digest()
    return out[:32], out[32:]


def prf(eta: int, seed: bytes, b: int, n: int = 256) -> bytes:
    """PRF_eta(s, b) = SHAKE256(s || b), 64*eta bytes for n = 256 (scaled for toy n)."""
    return hashlib.shake_256(seed + bytes([b])).digest(eta * n // 4)


def sample_ntt(seed: bytes, n: int = 256, q: int = Q) -> Poly:
    """Algorithm 7: rejection-sample n coefficients uniform in [0, q) from SHAKE128(seed).

    For n = 256 the result is interpreted in the NTT domain (FIPS 203); toy
    profiles use the same procedure but interpret the result as coefficients.
    """
    if len(seed) != 34:
        raise ValueError("SampleNTT seed must be 34 bytes")
    xof_len = 3 * n * 2
    while True:
        stream = hashlib.shake_128(seed).digest(xof_len)
        a: Poly = []
        pos = 0
        while len(a) < n and pos + 3 <= len(stream):
            c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
            pos += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = c1 // 16 + 16 * c2
            if d1 < q:
                a.append(d1)
            if d2 < q and len(a) < n:
                a.append(d2)
        if len(a) == n:
            return a
        xof_len *= 2  # SHAKE output is a prefix-stable stream: just read further


def sample_poly_cbd(data: bytes, eta: int, q: int = Q) -> Poly:
    """Algorithm 8: centered binomial distribution D_eta; n = len(data) * 4 / eta."""
    bits = bytes_to_bits(data)
    n = len(bits) // (2 * eta)
    out: Poly = []
    for i in range(n):
        base = 2 * i * eta
        x = sum(bits[base : base + eta])
        y = sum(bits[base + eta : base + 2 * eta])
        out.append((x - y) % q)
    return out
