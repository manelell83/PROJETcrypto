"""Arithmetic in Z_q and the Compress/Decompress maps (FIPS 203, section 4.2.1)."""

from __future__ import annotations

from canary_qday.kem.params import Q


def bitrev7(i: int) -> int:
    """Reverse the 7 low bits of i."""
    return int(f"{i:07b}"[::-1], 2)


ZETAS: tuple[int, ...] = tuple(pow(17, bitrev7(i), Q) for i in range(128))
"""17^BitRev7(i) mod q, used by NTT and NTT^-1."""

GAMMAS: tuple[int, ...] = tuple(pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128))
"""17^(2 BitRev7(i) + 1) mod q, used by BaseCaseMultiply."""


def compress(x: int, d: int, q: int = Q) -> int:
    """Compress_d(x) = round(2^d / q * x) mod 2^d, with exact integer rounding."""
    return (((x % q) << (d + 1)) + q) // (2 * q) % (1 << d)


def decompress(y: int, d: int, q: int = Q) -> int:
    """Decompress_d(y) = round(q / 2^d * y)."""
    return (q * y + (1 << (d - 1))) >> d


def centered(x: int, q: int = Q) -> int:
    """Representative of x mod q in (-q/2, q/2]."""
    x %= q
    return x - q if x > q // 2 else x
