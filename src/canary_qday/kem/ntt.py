"""Number-theoretic transform for n = 256 (FIPS 203, Algorithms 9-12)."""

from __future__ import annotations

from canary_qday.kem.field import GAMMAS, ZETAS
from canary_qday.kem.params import Q

Poly = list[int]


def ntt(f: Poly) -> Poly:
    """Algorithm 9: NTT(f) in the 128 degree-1 residue representation."""
    a = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * a[j + length] % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
        length //= 2
    return a


def intt(f_hat: Poly) -> Poly:
    """Algorithm 10: NTT^-1."""
    a = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = zeta * (a[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in a]


def multiply_ntts(f: Poly, g: Poly) -> Poly:
    """Algorithm 11: product of two polynomials in the NTT domain."""
    h = [0] * 256
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q  # Algorithm 12
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h
