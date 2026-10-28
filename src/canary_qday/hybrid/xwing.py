"""X-Wing hybrid KEM (X25519 + ML-KEM-768), draft-connolly-cfrg-xwing-kem-11.

ML-KEM-768 is the study implementation from canary_qday.kem; X25519 comes from
the `cryptography` package. Sizes: sk 32 B, pk 1216 B, ct 1120 B, ss 32 B.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from canary_qday.kem import kem
from canary_qday.kem.params import ML_KEM_768

XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # "\./" "/^\"
PK_BYTES = 1216
CT_BYTES = 1120
SK_BYTES = 32


def _x25519(scalar: bytes, point: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(point)
    )


def _x25519_base(scalar: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()


def expand_decapsulation_key(sk: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Return (sk_M, sk_X, pk_M, pk_X) derived from the 32-byte seed sk."""
    if len(sk) != SK_BYTES:
        raise kem.KemInputError("X-Wing decapsulation key must be 32 bytes")
    expanded = hashlib.shake_256(sk).digest(96)
    pk_m, sk_m = kem.keygen_internal(ML_KEM_768, expanded[:32], expanded[32:64])
    sk_x = expanded[64:96]
    return sk_m, sk_x, pk_m, _x25519_base(sk_x)


def combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)."""
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def generate_key_pair_derand(sk: bytes) -> tuple[bytes, bytes]:
    """Deterministic key generation from a 32-byte seed -> (sk, pk)."""
    _, _, pk_m, pk_x = expand_decapsulation_key(sk)
    return sk, pk_m + pk_x


def generate_key_pair() -> tuple[bytes, bytes]:
    """Fresh key pair -> (sk, pk)."""
    return generate_key_pair_derand(os.urandom(SK_BYTES))


def encapsulate_derand(pk: bytes, eseed: bytes) -> tuple[bytes, bytes]:
    """Deterministic encapsulation with a 64-byte eseed -> (ss, ct)."""
    if len(pk) != PK_BYTES or len(eseed) != 64:
        raise kem.KemInputError("bad X-Wing public key or eseed length")
    pk_m, pk_x = pk[:1184], pk[1184:]
    kem.check_ek(ML_KEM_768, pk_m)
    ek_x = eseed[32:64]
    ct_x = _x25519_base(ek_x)
    ss_x = _x25519(ek_x, pk_x)
    ss_m, ct_m = kem.encaps_internal(ML_KEM_768, pk_m, eseed[:32])
    return combiner(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Randomised encapsulation -> (ss, ct)."""
    return encapsulate_derand(pk, os.urandom(64))


def decapsulate(ct: bytes, sk: bytes) -> bytes:
    """Decapsulation -> ss (implicit rejection inherited from ML-KEM)."""
    if len(ct) != CT_BYTES:
        raise kem.KemInputError("X-Wing ciphertext must be 1120 bytes")
    sk_m, sk_x, _, pk_x = expand_decapsulation_key(sk)
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_m = kem.decaps(ML_KEM_768, sk_m, ct_m)
    ss_x = _x25519(sk_x, ct_x)
    return combiner(ss_m, ss_x, ct_x, pk_x)
