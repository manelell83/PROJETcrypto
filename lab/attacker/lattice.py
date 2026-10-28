"""Integer LLL lattice reduction with rational Gram-Schmidt (lab attacker, M8).

Reduction engine: **LLL only**. BKZ is *not* implemented here. A correct BKZ
needs an SVP oracle on projected blocks (enumeration or sieving); presenting a
"progressive" loop without that oracle would not be a real BKZ, so it is
deferred to a later increment (see docs/m8-status.md).

On top of LLL this module also builds the primal (Kannan) embedding of a toy
LWE instance and recovers the secret with `solve_lwe`. Because LLL's
approximation factor grows exponentially with the dimension, `solve_lwe` only
succeeds on small instances (tiny deterministic cases, not the full RED/ORANGE
dimension); it returns ``None`` rather than a wrong answer when LLL does not
reach the planted vector.

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


def _centered(value: int, q: int) -> int:
    """Representative of ``value`` mod q in (-q/2, q/2]."""
    value %= q
    return value - q if value > q // 2 else value


def kannan_embedding(a_matrix: Basis, t: Vector, q: int) -> Basis:
    """Primal (Kannan) embedding of the LWE instance ``A s + e == t (mod q)``.

    ``a_matrix`` is the square N x N matrix A, ``t`` the length-N target. The
    returned (2N+1)-dimensional integer basis (rows) generates the lattice

        L = { (x, y, c) in Z^N x Z^N x Z : A x + y == c t (mod q) },

    which contains the short vector ``(s, e, 1)``: with coefficients ``s`` on the
    rows ``(e_j, -A[:,j], 0)``, ``1`` on ``(0, t, 1)`` and integer ``w`` on the
    ``(0, q e_i, 0)`` rows, the combination is ``(s, t - A s + q w, 1) = (s, e, 1)``.
    All other generators have norm >= q, so for a small instance ``(s, e, 1)`` is
    the unique shortest vector up to sign.
    """
    n = len(a_matrix)
    if n == 0:
        raise ValueError("A must be non-empty")
    if any(len(row) != n for row in a_matrix):
        raise ValueError("A must be square")
    if len(t) != n:
        raise ValueError("t must have the same length as A")
    if q <= 0:
        raise ValueError("q must be positive")
    rows: Basis = []
    for j in range(n):
        s_part = [1 if i == j else 0 for i in range(n)]
        e_part = [-a_matrix[i][j] for i in range(n)]
        rows.append(s_part + e_part + [0])
    rows.append([0] * n + [x % q for x in t] + [1])
    for i in range(n):
        e_part = [q if r == i else 0 for r in range(n)]
        rows.append([0] * n + e_part + [0])
    return rows


def solve_lwe(a_matrix: Basis, t: Vector, q: int, bound: int) -> Vector | None:
    """Recover the LWE secret ``s`` with ``A s + e == t (mod q)`` and ``|e| <= bound``.

    Builds the Kannan embedding, runs LLL, and inspects every reduced row whose
    last coordinate is +-1 (the embedding coefficient). A candidate is accepted
    **only** after an independent check: the residual ``A s + e - t`` is zero
    modulo q and ``|e|_inf <= bound``. The recovered ``s`` is returned centred in
    (-q/2, q/2]. Returns ``None`` when no reduced vector passes the check -- it
    never reports an unverified secret.
    """
    n = len(a_matrix)
    if any(len(row) != n for row in a_matrix):
        raise ValueError("A must be square")
    if len(t) != n:
        raise ValueError("t must have the same length as A")
    if q <= 0:
        raise ValueError("q must be positive")
    if bound < 0:
        raise ValueError("bound must be non-negative")
    if n == 0:
        return None

    reduced = lll(kannan_embedding(a_matrix, t, q))
    for row in reduced:
        sign = row[-1]
        if sign not in (1, -1):
            continue
        cand_s = [sign * row[j] for j in range(n)]
        cand_e = [sign * row[n + j] for j in range(n)]
        if cand_e and max(abs(x) for x in cand_e) > bound:
            continue
        residual_ok = all(
            (sum(a_matrix[i][j] * cand_s[j] for j in range(n)) + cand_e[i] - t[i]) % q == 0
            for i in range(n)
        )
        if residual_ok:
            return [_centered(x, q) for x in cand_s]
    return None
