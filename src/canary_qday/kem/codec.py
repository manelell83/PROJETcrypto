"""Bit/byte conversions and ByteEncode/ByteDecode (FIPS 203, Algorithms 3-6)."""

from __future__ import annotations

from canary_qday.kem.params import Q

Poly = list[int]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Algorithm 3: little-endian bit array to bytes (len(bits) multiple of 8)."""
    if len(bits) % 8:
        raise ValueError("bit length must be a multiple of 8")
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        out[i // 8] |= (b & 1) << (i % 8)
    return bytes(out)


def bytes_to_bits(data: bytes) -> list[int]:
    """Algorithm 4: bytes to little-endian bit array."""
    return [(byte >> j) & 1 for byte in data for j in range(8)]


def byte_encode(f: Poly, d: int) -> bytes:
    """Algorithm 5: ByteEncode_d, packing d bits per coefficient."""
    acc = 0
    for i, a in enumerate(f):
        acc |= (a % (1 << d) if d < 12 else a % Q) << (i * d)
    return acc.to_bytes(len(f) * d // 8, "little")


def byte_decode(data: bytes, d: int, n: int) -> Poly:
    """Algorithm 6: ByteDecode_d. For d = 12 coefficients are reduced mod q."""
    if len(data) != n * d // 8:
        raise ValueError("encoded polynomial has wrong length")
    acc = int.from_bytes(data, "little")
    mask = (1 << d) - 1
    m = Q if d == 12 else 1 << d
    return [((acc >> (i * d)) & mask) % m for i in range(n)]


def byte_encode_vec(v: list[Poly], d: int) -> bytes:
    """ByteEncode_d applied to each polynomial of a vector, concatenated."""
    return b"".join(byte_encode(p, d) for p in v)


def byte_decode_vec(data: bytes, d: int, n: int, k: int) -> list[Poly]:
    """Inverse of byte_encode_vec for a vector of k polynomials."""
    size = n * d // 8
    if len(data) != k * size:
        raise ValueError("encoded vector has wrong length")
    return [byte_decode(data[i * size : (i + 1) * size], d, n) for i in range(k)]
