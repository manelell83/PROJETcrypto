"""K-PKE (FIPS 203, Algorithms 13-15), generalised to toy parameter sets.

For n = 256 the FIPS 203 NTT path is used and keys are stored in the NTT
domain. For toy n < 256 the same algorithms run with schoolbook
multiplication and keys stored in the coefficient domain.
"""

from __future__ import annotations

from canary_qday.kem import poly
from canary_qday.kem.codec import byte_decode, byte_decode_vec, byte_encode, byte_encode_vec
from canary_qday.kem.field import compress, decompress
from canary_qday.kem.ntt import intt, multiply_ntts, ntt
from canary_qday.kem.params import Params
from canary_qday.kem.sampling import G, prf, sample_ntt, sample_poly_cbd

Poly = list[int]
Matrix = list[list[Poly]]


def expand_a(params: Params, rho: bytes) -> Matrix:
    """A[i][j] = SampleNTT(rho || j || i) (NTT domain for n=256, coefficients for toy)."""
    return [
        [sample_ntt(rho + bytes([j, i]), params.n) for j in range(params.k)]
        for i in range(params.k)
    ]


def _mul(params: Params, f: Poly, g: Poly) -> Poly:
    return multiply_ntts(f, g) if params.uses_ntt else poly.schoolbook_mul(f, g)


def _to_dom(params: Params, f: Poly) -> Poly:
    return ntt(f) if params.uses_ntt else f


def _from_dom(params: Params, f: Poly) -> Poly:
    return intt(f) if params.uses_ntt else f


def _dot(params: Params, a: list[Poly], b: list[Poly]) -> Poly:
    acc = poly.zero(params.n)
    for x, y in zip(a, b, strict=True):
        acc = poly.add(acc, _mul(params, x, y))
    return acc


def _cbd_vec(params: Params, eta: int, seed: bytes, start: int) -> list[Poly]:
    return [
        sample_poly_cbd(prf(eta, seed, start + i, params.n), eta) for i in range(params.k)
    ]


def keygen(params: Params, d: bytes) -> tuple[bytes, bytes]:
    """Algorithm 13: K-PKE.KeyGen(d) -> (ek_pke, dk_pke)."""
    if len(d) != 32:
        raise ValueError("d must be 32 bytes")
    rho, sigma = G(d + bytes([params.k]))
    a = expand_a(params, rho)
    s = [_to_dom(params, p) for p in _cbd_vec(params, params.eta1, sigma, 0)]
    e = [_to_dom(params, p) for p in _cbd_vec(params, params.eta1, sigma, params.k)]
    t = [poly.add(_dot(params, a[i], s), e[i]) for i in range(params.k)]
    return byte_encode_vec(t, 12) + rho, byte_encode_vec(s, 12)


def encrypt(params: Params, ek: bytes, m: bytes, r: bytes) -> bytes:
    """Algorithm 14: K-PKE.Encrypt(ek, m, r)."""
    k, n = params.k, params.n
    t = byte_decode_vec(ek[: params.dk_pke_bytes], 12, n, k)
    rho = ek[params.dk_pke_bytes :]
    a = expand_a(params, rho)
    y = [_to_dom(params, p) for p in _cbd_vec(params, params.eta1, r, 0)]
    e1 = _cbd_vec(params, params.eta2, r, k)
    e2 = sample_poly_cbd(prf(params.eta2, r, 2 * k, n), params.eta2)
    u = [
        poly.add(_from_dom(params, _dot(params, [a[j][i] for j in range(k)], y)), e1[i])
        for i in range(k)
    ]
    mu = [decompress(b, 1) for b in byte_decode(m, 1, n)]
    v = poly.add(poly.add(_from_dom(params, _dot(params, t, y)), e2), mu)
    c1 = b"".join(byte_encode([compress(x, params.du) for x in p], params.du) for p in u)
    c2 = byte_encode([compress(x, params.dv) for x in v], params.dv)
    return c1 + c2


def decrypt(params: Params, dk: bytes, c: bytes) -> bytes:
    """Algorithm 15: K-PKE.Decrypt(dk, c)."""
    k, n = params.k, params.n
    split = k * params.du * n // 8
    u = [
        [decompress(x, params.du) for x in p]
        for p in byte_decode_vec(c[:split], params.du, n, k)
    ]
    v = [decompress(x, params.dv) for x in byte_decode(c[split:], params.dv, n)]
    s = byte_decode_vec(dk, 12, n, k)
    w = poly.sub(v, _from_dom(params, _dot(params, s, [_to_dom(params, p) for p in u])))
    return byte_encode([compress(x, 1) for x in w], 1)
