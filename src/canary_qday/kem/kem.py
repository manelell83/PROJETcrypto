"""ML-KEM (FIPS 203, Algorithms 16-21) with input checks (section 7).

STUDY ARTEFACT: pure Python, NOT constant-time, NOT for production use.
The comparison in decapsulation uses hmac.compare_digest, but the
surrounding arithmetic leaks timing; no side-channel claim is made.
"""

from __future__ import annotations

import hmac
import os

from canary_qday.kem import kpke
from canary_qday.kem.codec import byte_decode_vec, byte_encode_vec
from canary_qday.kem.params import Params
from canary_qday.kem.sampling import G, H, J


class KemInputError(ValueError):
    """Raised when an encapsulation key, decapsulation key or ciphertext fails validation.

    Messages never contain key or ciphertext material.
    """


def check_ek(params: Params, ek: bytes) -> None:
    """Encapsulation key check (FIPS 203, 7.2): length and modulus check."""
    if len(ek) != params.ek_bytes:
        raise KemInputError("encapsulation key has wrong length")
    head = ek[: params.dk_pke_bytes]
    if byte_encode_vec(byte_decode_vec(head, 12, params.n, params.k), 12) != head:
        raise KemInputError("encapsulation key is not canonically encoded")


def check_dk(params: Params, dk: bytes) -> None:
    """Decapsulation key check (FIPS 203, 7.3): length and hash check."""
    if len(dk) != params.dk_bytes:
        raise KemInputError("decapsulation key has wrong length")
    lo = params.dk_pke_bytes
    ek = dk[lo : lo + params.ek_bytes]
    h = dk[lo + params.ek_bytes : lo + params.ek_bytes + 32]
    if not hmac.compare_digest(H(ek), h):
        raise KemInputError("decapsulation key hash check failed")


def check_ct(params: Params, c: bytes) -> None:
    """Ciphertext type check (FIPS 203, 7.3): length."""
    if len(c) != params.ct_bytes:
        raise KemInputError("ciphertext has wrong length")


def keygen_internal(params: Params, d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """Algorithm 16: ML-KEM.KeyGen_internal(d, z) -> (ek, dk)."""
    if len(z) != 32:
        raise KemInputError("z must be 32 bytes")
    ek, dk_pke = kpke.keygen(params, d)
    return ek, dk_pke + ek + H(ek) + z


def encaps_internal(params: Params, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Algorithm 17: ML-KEM.Encaps_internal(ek, m) -> (K, c)."""
    if len(m) != params.msg_bytes:
        raise KemInputError("message has wrong length")
    key, r = G(m + H(ek))
    return key, kpke.encrypt(params, ek, m, r)


def decaps_internal(params: Params, dk: bytes, c: bytes) -> bytes:
    """Algorithm 18: ML-KEM.Decaps_internal(dk, c) -> K, with implicit rejection."""
    lo = params.dk_pke_bytes
    dk_pke = dk[:lo]
    ek = dk[lo : lo + params.ek_bytes]
    h = dk[lo + params.ek_bytes : lo + params.ek_bytes + 32]
    z = dk[lo + params.ek_bytes + 32 :]
    m_prime = kpke.decrypt(params, dk_pke, c)
    key_prime, r_prime = G(m_prime + h)
    key_bar = J(z + c)
    c_prime = kpke.encrypt(params, ek, m_prime, r_prime)
    return key_prime if hmac.compare_digest(c, c_prime) else key_bar


def keygen(params: Params) -> tuple[bytes, bytes]:
    """Algorithm 19: ML-KEM.KeyGen with fresh randomness from os.urandom."""
    return keygen_internal(params, os.urandom(32), os.urandom(32))


def encaps(params: Params, ek: bytes) -> tuple[bytes, bytes]:
    """Algorithm 20: ML-KEM.Encaps(ek) -> (K, c), after the encapsulation key check."""
    check_ek(params, ek)
    return encaps_internal(params, ek, os.urandom(params.msg_bytes))


def decaps(params: Params, dk: bytes, c: bytes) -> bytes:
    """Algorithm 21: ML-KEM.Decaps(dk, c) -> K, after ciphertext and key checks."""
    check_ct(params, c)
    check_dk(params, dk)
    return decaps_internal(params, dk, c)
