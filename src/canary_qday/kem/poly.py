"""Polynomial arithmetic in R_q = Z_q[X]/(X^n + 1), coefficient representation."""

from __future__ import annotations

from canary_qday.kem.params import Q

Poly = list[int]


def add(f: Poly, g: Poly, q: int = Q) -> Poly:
    """Coefficient-wise f + g mod q."""
    return [(a + b) % q for a, b in zip(f, g, strict=True)]


def sub(f: Poly, g: Poly, q: int = Q) -> Poly:
    """Coefficient-wise f - g mod q."""
    return [(a - b) % q for a, b in zip(f, g, strict=True)]


def schoolbook_mul(f: Poly, g: Poly, q: int = Q) -> Poly:
    """Negacyclic product f * g mod (X^n + 1, q) in O(n^2); used by toy profiles."""
    n = len(f)
    if len(g) != n:
        raise ValueError("length mismatch")
    acc = [0] * (2 * n)
    for i, a in enumerate(f):
        if a:
            for j, b in enumerate(g):
                acc[i + j] += a * b
    return [(acc[i] - acc[i + n]) % q for i in range(n)]


def zero(n: int) -> Poly:
    """The zero polynomial of length n."""
    return [0] * n
