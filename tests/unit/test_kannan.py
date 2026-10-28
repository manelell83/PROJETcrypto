"""Tests for the primal (Kannan) embedding and solve_lwe (lab/attacker/lattice.py).

Instances are deterministic (fixed seeds). The checks are independent of the
reduced basis: a planted secret is recovered and the LWE equation is verified
modulo q with the error bound, the embedding generators are checked to lie in
the lattice, and a high-noise case must return None (an LLL run alone can never
be declared a success without the modular verification).
"""

from __future__ import annotations

import random

import pytest

from canary_qday.kem.profiles import rot_matrix
from lab.attacker.lattice import kannan_embedding, solve_lwe

Instance = tuple[list[list[int]], list[int], list[int], list[int]]


def _centered(x: int, q: int) -> int:
    x %= q
    return x - q if x > q // 2 else x


def _random_instance(n: int, q: int, eta: int, seed: int) -> Instance:
    rng = random.Random(f"kannan:{n}:{q}:{eta}:{seed}")
    a = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]
    s = [rng.randint(-eta, eta) for _ in range(n)]
    e = [rng.randint(-eta, eta) for _ in range(n)]
    t = [(sum(a[i][j] * s[j] for j in range(n)) + e[i]) % q for i in range(n)]
    return a, t, s, e


def _structured_instance(n: int, q: int, eta: int, seed: int) -> Instance:
    """A negacyclic instance built with the real rot_matrix, like public_instance (k=1)."""
    rng = random.Random(f"struct:{n}:{q}:{eta}:{seed}")
    poly_a = [rng.randrange(q) for _ in range(n)]
    a = rot_matrix(poly_a, q)
    s = [rng.randint(-eta, eta) for _ in range(n)]
    e = [rng.randint(-eta, eta) for _ in range(n)]
    t = [(sum(a[i][j] * s[j] for j in range(n)) + e[i]) % q for i in range(n)]
    return a, t, s, e


def _verify(a: list[list[int]], t: list[int], s: list[int], e_bound: int, q: int) -> None:
    """Independent check: s is a valid secret for (A, t, q) with bounded error."""
    n = len(a)
    e = [_centered(t[i] - sum(a[i][j] * s[j] for j in range(n)), q) for i in range(n)]
    assert all((sum(a[i][j] * s[j] for j in range(n)) + e[i] - t[i]) % q == 0 for i in range(n))
    assert max(abs(x) for x in e) <= e_bound


# Parameter sets where LLL alone solves the uSVP (confirmed before implementing).
SOLVABLE = [(2, 97, 1), (3, 97, 1), (4, 97, 1), (4, 257, 1), (6, 257, 1), (4, 3329, 2)]


@pytest.mark.parametrize(("n", "q", "eta"), SOLVABLE)
@pytest.mark.parametrize("seed", range(5))
def test_solve_lwe_recovers_planted_secret(n: int, q: int, eta: int, seed: int) -> None:
    a, t, s, _ = _random_instance(n, q, eta, seed)
    recovered = solve_lwe(a, t, q, bound=eta)
    assert recovered == [_centered(x, q) for x in s]
    _verify(a, t, recovered, eta, q)


@pytest.mark.parametrize("seed", range(5))
def test_solve_lwe_on_rot_matrix_structure(seed: int) -> None:
    a, t, s, _ = _structured_instance(4, 257, 1, seed)
    recovered = solve_lwe(a, t, 257, bound=1)
    assert recovered == [_centered(x, 257) for x in s]
    _verify(a, t, recovered, 1, 257)


def test_embedding_generators_are_in_the_lattice() -> None:
    a, t, _, _ = _random_instance(3, 97, 1, 0)
    n, q = 3, 97
    for row in kannan_embedding(a, t, q):
        x, y, c = row[:n], row[n : 2 * n], row[-1]
        residual = [(sum(a[i][j] * x[j] for j in range(n)) + y[i] - c * t[i]) % q for i in range(n)]
        assert residual == [0] * n


def test_planted_vector_is_in_the_lattice_and_short() -> None:
    a, t, s, e = _random_instance(4, 257, 1, 1)
    n, q = 4, 257
    residual = [(sum(a[i][j] * s[j] for j in range(n)) + e[i] - t[i]) % q for i in range(n)]
    assert residual == [0] * n  # (s, e, 1) satisfies the congruence
    norm_sq = sum(x * x for x in s) + sum(x * x for x in e) + 1
    assert norm_sq < q * q  # ... and is far shorter than the q-scaled generators


def test_high_noise_is_not_falsely_solved() -> None:
    """Error far above the bound: no short (s,e,1) exists, so solve_lwe returns None."""
    n, q = 4, 97
    rng = random.Random("noise")
    a = [[rng.randrange(q) for _ in range(n)] for _ in range(n)]
    s = [rng.randint(-1, 1) for _ in range(n)]
    big_e = [rng.randrange(q) for _ in range(n)]  # full-range noise, not small
    t = [(sum(a[i][j] * s[j] for j in range(n)) + big_e[i]) % q for i in range(n)]
    assert solve_lwe(a, t, q, bound=1) is None


def test_wrong_bound_rejects_a_real_instance() -> None:
    """With bound 0 the true error (|e|=1) fails the check, so None is returned."""
    a, t, _, _ = _random_instance(4, 97, 1, 2)
    assert solve_lwe(a, t, 97, bound=0) is None


def test_validation() -> None:
    a, t, _, _ = _random_instance(3, 97, 1, 0)
    with pytest.raises(ValueError):
        kannan_embedding([[1, 2], [3, 4]], [1], 97)  # t length mismatch
    with pytest.raises(ValueError):
        kannan_embedding([[1, 2, 3], [4, 5, 6]], [1, 2, 3], 97)  # non-square
    with pytest.raises(ValueError):
        solve_lwe(a, t, 0, bound=1)  # q <= 0
    with pytest.raises(ValueError):
        solve_lwe(a, t, 97, bound=-1)  # negative bound
    assert solve_lwe([], [], 97, bound=1) is None


@pytest.mark.skip(
    reason="LLL-only cannot reach the planted vector at the real RED dimension "
    "(N=64 -> 129-dim embedding; LLL's approximation factor is exponential). "
    "A full-RED attack needs BKZ, which is the deferred next increment "
    "(see docs/m8-status.md). solve_lwe would return None here, not a wrong secret."
)
def test_real_red_profile_is_out_of_reach_for_lll_only() -> None:  # pragma: no cover
    pass
