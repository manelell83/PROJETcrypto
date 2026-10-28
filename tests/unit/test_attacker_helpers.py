"""Tests for the toy-only LWE helpers in kem/profiles.py that M8 relies on.

These exercise the real contracts of `public_instance` and
`shared_secret_from_secret` (verified against the source, signatures not
invented): the public instance is the LWE form t = A s + e with small e, and a
recovered secret yields the same shared secret as encapsulation. GREEN (a
standard set) must be refused. No lattice reduction happens here.
"""

from __future__ import annotations

import pytest

from canary_qday.kem import kem
from canary_qday.kem.codec import byte_decode_vec
from canary_qday.kem.profiles import (
    is_toy,
    params_for,
    public_instance,
    shared_secret_from_secret,
)

TOY_PROFILES = ["RED", "ORANGE"]


def _centered(value: int, q: int) -> int:
    """Representative of value mod q in (-q/2, q/2]."""
    value %= q
    return value - q if value > q // 2 else value


def _secret_from_dk(params, dk: bytes) -> list[int]:  # type: ignore[no-untyped-def]
    """Flatten the K-PKE secret s stored in dk into one integer vector."""
    polys = byte_decode_vec(dk[: params.dk_pke_bytes], 12, params.n, params.k)
    return [c for poly in polys for c in poly]


@pytest.mark.parametrize("profile", TOY_PROFILES)
def test_public_instance_shape(profile: str) -> None:
    params = params_for(profile)
    ek, _ = kem.keygen(params)
    a_matrix, t = public_instance(params, ek)
    dim = params.n * params.k
    assert len(a_matrix) == dim
    assert all(len(row) == dim for row in a_matrix)
    assert len(t) == dim
    assert all(0 <= x < params.q for row in a_matrix for x in row)


@pytest.mark.parametrize("profile", TOY_PROFILES)
def test_public_instance_is_lwe_with_small_error(profile: str) -> None:
    params = params_for(profile)
    ek, dk = kem.keygen(params)
    a_matrix, t = public_instance(params, ek)
    s = _secret_from_dk(params, dk)
    dim = params.n * params.k

    # e = t - A s (mod q), centered. For a genuine LWE instance it must be small.
    e = [
        _centered(t[i] - sum(a_matrix[i][j] * s[j] for j in range(dim)), params.q)
        for i in range(dim)
    ]
    s_centered = [_centered(x, params.q) for x in s]
    assert max(abs(x) for x in e) <= params.eta1
    assert max(abs(x) for x in s_centered) <= params.eta1
    # Sanity: a random wrong secret does not give a small residual.
    wrong = [s[0] + 1, *s[1:]]
    e_wrong = [
        _centered(t[i] - sum(a_matrix[i][j] * wrong[j] for j in range(dim)), params.q)
        for i in range(dim)
    ]
    assert max(abs(x) for x in e_wrong) > params.eta1


@pytest.mark.parametrize("profile", TOY_PROFILES)
def test_recovered_secret_yields_the_shared_secret(profile: str) -> None:
    params = params_for(profile)
    ek, dk = kem.keygen(params)
    ss, ct = kem.encaps(params, ek)
    s_centered = [_centered(x, params.q) for x in _secret_from_dk(params, dk)]
    assert shared_secret_from_secret(params, ek, s_centered, ct) == ss


def test_green_is_refused_by_public_instance() -> None:
    params = params_for("GREEN")
    assert not is_toy(params)
    with pytest.raises(ValueError):
        public_instance(params, b"")  # refused before ek is even parsed


def test_params_for_unknown_profile() -> None:
    with pytest.raises(ValueError):
        params_for("PURPLE")
