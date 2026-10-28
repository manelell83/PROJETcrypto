"""Tests for the integer LLL implementation (lab/attacker/lattice.py).

The assertions check mathematical properties of LLL, not a specific reduced
basis, so they do not depend on implementation details (pivot order, tie
breaking): the size and Lovász conditions, exact lattice preservation
(unimodular change of basis), covolume preservation, and that the shortest
output vector attains the lattice minimum found by brute force.
"""

from __future__ import annotations

import itertools
from fractions import Fraction

import pytest

from lab.attacker.lattice import DEFAULT_DELTA, Basis, dot, gram_schmidt, is_lll_reduced, lll

# --- exact-rational helpers used only by the tests (Fraction Gaussian elimination) ---


def _det(matrix: Basis) -> Fraction:
    """Exact determinant of a square integer matrix via fraction-free elimination."""
    n = len(matrix)
    a = [[Fraction(x) for x in row] for row in matrix]
    det = Fraction(1)
    for col in range(n):
        pivot = next((r for r in range(col, n) if a[r][col] != 0), None)
        if pivot is None:
            return Fraction(0)
        if pivot != col:
            a[col], a[pivot] = a[pivot], a[col]
            det = -det
        det *= a[col][col]
        inv = a[col][col]
        for r in range(col + 1, n):
            factor = a[r][col] / inv
            a[r] = [a[r][c] - factor * a[col][c] for c in range(n)]
    return det


def _solve_transform(out_basis: Basis, in_basis: Basis) -> list[list[Fraction]]:
    """Return U such that out = U @ in, by solving in^T @ U[i] = out[i] exactly."""
    n = len(in_basis)
    at = [[Fraction(in_basis[r][c]) for r in range(n)] for c in range(n)]  # transpose
    u: list[list[Fraction]] = []
    for target in out_basis:
        # Solve at @ x = target by Gaussian elimination (augmented).
        m = [[*row, Fraction(target[r])] for r, row in enumerate(at)]
        for col in range(n):
            piv = next(r for r in range(col, n) if m[r][col] != 0)
            m[col], m[piv] = m[piv], m[col]
            p = m[col][col]
            m[col] = [v / p for v in m[col]]
            for r in range(n):
                if r != col and m[r][col] != 0:
                    f = m[r][col]
                    m[r] = [m[r][c] - f * m[col][c] for c in range(n + 1)]
        u.append([m[r][n] for r in range(n)])
    return u


def _covolume_sq(basis: Basis) -> Fraction:
    gs, _ = gram_schmidt(basis)
    out = Fraction(1)
    for g in gs:
        out *= dot(g, g)
    return out


def _shortest_sq_norm(basis: Basis, span: int = 6) -> int:
    """Brute-force minimum squared norm of a non-zero lattice vector over a box."""
    n = len(basis)
    width = len(basis[0])
    best: int | None = None
    for coeffs in itertools.product(range(-span, span + 1), repeat=n):
        if all(c == 0 for c in coeffs):
            continue
        vec = [sum(coeffs[i] * basis[i][c] for i in range(n)) for c in range(width)]
        norm = sum(x * x for x in vec)
        if best is None or norm < best:
            best = norm
    assert best is not None
    return best


# --- deterministic bases ---

IDENTITY_3 = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
# Classic LLL example (Wikipedia): a clearly non-reduced full-rank 3D basis.
WIKI = [[1, 1, 1], [-1, 0, 2], [3, 5, 6]]
SKEW_2D = [[17, 0], [13, 1]]
SKEW_4D = [[13, 1, 0, 0], [0, 11, 1, 0], [0, 0, 7, 1], [1, 0, 0, 5]]
ALL_BASES = {"wiki": WIKI, "skew2d": SKEW_2D, "skew4d": SKEW_4D, "identity": IDENTITY_3}


@pytest.mark.parametrize("name", list(ALL_BASES))
def test_output_satisfies_size_and_lovasz(name: str) -> None:
    reduced = lll(ALL_BASES[name])
    assert is_lll_reduced(reduced)
    # Decide the two conditions directly as well, not only via the helper.
    gs, mu = gram_schmidt(reduced)
    norms = [dot(g, g) for g in gs]
    for i in range(len(reduced)):
        for j in range(i):
            assert abs(mu[i][j]) <= Fraction(1, 2)
    for i in range(1, len(reduced)):
        assert norms[i] >= (DEFAULT_DELTA - mu[i][i - 1] ** 2) * norms[i - 1]


@pytest.mark.parametrize("name", list(ALL_BASES))
def test_lattice_is_preserved_by_unimodular_transform(name: str) -> None:
    base = ALL_BASES[name]
    reduced = lll(base)
    u = _solve_transform(reduced, base)
    for row in u:
        for entry in row:
            assert entry.denominator == 1  # U is an integer matrix
    assert abs(_det(u)) == 1  # ... and unimodular -> same lattice


@pytest.mark.parametrize("name", list(ALL_BASES))
def test_covolume_is_preserved(name: str) -> None:
    base = ALL_BASES[name]
    assert _covolume_sq(lll(base)) == _covolume_sq(base)


@pytest.mark.parametrize("name", ["wiki", "skew2d", "skew4d"])
def test_first_vector_reaches_lattice_minimum(name: str) -> None:
    base = ALL_BASES[name]
    reduced = lll(base)
    shortest_in_output = min(sum(x * x for x in v) for v in reduced)
    assert shortest_in_output == _shortest_sq_norm(base)


def test_input_is_not_mutated() -> None:
    base = [row[:] for row in WIKI]
    snapshot = [row[:] for row in base]
    lll(base)
    assert base == snapshot


def test_already_reduced_basis_is_stable() -> None:
    assert lll(IDENTITY_3) == IDENTITY_3


def test_delta_out_of_range_is_rejected() -> None:
    for bad in (Fraction(1, 4), Fraction(1), Fraction(2)):
        with pytest.raises(ValueError):
            lll(WIKI, delta=bad)


def test_ragged_basis_is_rejected() -> None:
    with pytest.raises(ValueError):
        lll([[1, 0], [0, 1, 2]])


def test_empty_basis() -> None:
    assert lll([]) == []
    assert is_lll_reduced([]) is True


def test_is_lll_reduced_detects_unreduced_basis() -> None:
    assert is_lll_reduced(WIKI) is False
    assert is_lll_reduced(SKEW_2D) is False
