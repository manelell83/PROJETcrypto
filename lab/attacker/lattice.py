"""Integer LLL lattice reduction with rational Gram-Schmidt (lab attacker, M8).

Scope of this increment: **LLL only**. BKZ is *not* implemented here. A correct
BKZ needs an SVP oracle on projected blocks (enumeration or sieving); presenting
a "progressive" loop without that oracle would not be a real BKZ, so it is
deferred to a later increment (see docs/m8-status.md).

The implementation keeps the basis in exact integers and the Gram-Schmidt data
in exact rationals (`fractions.Fraction`), so there is no floating-point error:
the Lovász and size conditions are decided exactly. It targets small lattices
(toy profiles and tiny deterministic instances), not performance.

This module imports only the standard library. It performs no I/O and touches no
network or crypto material, so it is safe to import anywhere; the attacker
entry points that *use* it still call `guard.require_lab()` first.
"""

from __future__ import annotations

from fractions import Fraction

Vector = list[int]
Basis = list[Vector]
RationalVector = list[Fraction]

#: Standard Lovász parameter. Must lie in (1/4, 1). 3/4 is Lenstra-Lenstra-Lovász.
DEFAULT_DELTA = Fraction(3, 4)


def dot(u: list[Fraction], v: list[Fraction]) -> Fraction:
    """Exact inner product of two equal-length rational vectors."""
    return sum((a * b for a, b in zip(u, v, strict=True)), Fraction(0))


def _as_rational(v: Vector) -> RationalVector:
    return [Fraction(x) for x in v]


def gram_schmidt(basis: Basis) -> tuple[list[RationalVector], list[list[Fraction]]]:
    """Exact Gram-Schmidt of an integer basis.

    Returns ``(gs, mu)`` where ``gs[i]`` is the i-th orthogonal vector and
    ``mu[i][j]`` (for j < i) is the projection coefficient
    ``<b_i, gs_j> / <gs_j, gs_j>``. All values are exact ``Fraction``s.
    """
    n = len(basis)
    gs: list[RationalVector] = []
    mu: list[list[Fraction]] = [[Fraction(0)] * n for _ in range(n)]
    for i, b_int in enumerate(basis):
        b = _as_rational(b_int)
        ortho = list(b)
        for j in range(i):
            denom = dot(gs[j], gs[j])
            m = dot(b, gs[j]) / denom if denom != 0 else Fraction(0)
            mu[i][j] = m
            ortho = [ortho[t] - m * gs[j][t] for t in range(len(b))]
        gs.append(ortho)
    return gs, mu


def _nearest_int(x: Fraction) -> int:
    """Closest integer to x, rounding a tie to the nearest even integer."""
    return round(x)


def lll(basis: Basis, delta: Fraction = DEFAULT_DELTA) -> Basis:
    """Return an LLL-reduced basis of the same lattice as ``basis``.

    The input is copied, never mutated. The output spans exactly the same
    integer lattice (the transformation is unimodular) and satisfies the size
    condition (|mu[i][j]| <= 1/2) and the Lovász condition for the given delta.

    Gram-Schmidt is recomputed from scratch after every size reduction and swap.
    That is O(n^4) overall and deliberately simple; it is correct for the small
    bases this module targets, not tuned for large ones.
    """
    if not 4 * delta > 1 or not delta < 1:
        raise ValueError("delta must lie in (1/4, 1)")
    if not basis:
        return []
    width = len(basis[0])
    if any(len(v) != width for v in basis):
        raise ValueError("all basis vectors must have the same length")

    b: Basis = [list(v) for v in basis]
    n = len(b)
    gs, mu = gram_schmidt(b)
    norms = [dot(g, g) for g in gs]

    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = _nearest_int(mu[k][j])
                b[k] = [b[k][t] - q * b[j][t] for t in range(width)]
                gs, mu = gram_schmidt(b)
                norms = [dot(g, g) for g in gs]
        if norms[k] >= (delta - mu[k][k - 1] ** 2) * norms[k - 1]:
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            gs, mu = gram_schmidt(b)
            norms = [dot(g, g) for g in gs]
            k = max(k - 1, 1)
    return b


def is_lll_reduced(basis: Basis, delta: Fraction = DEFAULT_DELTA) -> bool:
    """True iff ``basis`` satisfies the size and Lovász conditions for ``delta``."""
    if len(basis) < 2:
        return True
    gs, mu = gram_schmidt(basis)
    norms = [dot(g, g) for g in gs]
    for i in range(len(basis)):
        for j in range(i):
            if abs(mu[i][j]) > Fraction(1, 2):
                return False
    return all(
        norms[i] >= (delta - mu[i][i - 1] ** 2) * norms[i - 1]
        for i in range(1, len(basis))
    )
