"""TLS-style X25519MLKEM768 combiner, for comparison with X-Wing only.

In TLS 1.3 hybrid key exchange the two shared secrets are simply concatenated
(ML-KEM first for X25519MLKEM768) and fed into the TLS key schedule, which
binds the transcript. Outside TLS, plain concatenation does not bind the
ciphertexts or public keys; we model the key schedule step with HKDF over
the transcript to make the comparison fair. Not used by any profile.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from canary_qday.kem import kem
from canary_qday.kem.params import ML_KEM_768


def keygen() -> tuple[tuple[bytes, bytes], bytes]:
    """Return ((dk_M, sk_X), pk_M || pk_X)."""
    ek_m, dk_m = kem.keygen(ML_KEM_768)
    sk_x = X25519PrivateKey.generate()
    return (dk_m, sk_x.private_bytes_raw()), ek_m + sk_x.public_key().public_bytes_raw()


def _kdf(secret: bytes, transcript: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"tls-style-hybrid" + transcript).derive(
        secret
    )


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Return (ss, ct_M || ct_X)."""
    pk_m, pk_x = pk[:1184], pk[1184:]
    ss_m, ct_m = kem.encaps(ML_KEM_768, pk_m)
    eph = X25519PrivateKey.generate()
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(pk_x))
    ct = ct_m + eph.public_key().public_bytes_raw()
    return _kdf(ss_m + ss_x, pk + ct), ct


def decapsulate(sk: tuple[bytes, bytes], pk: bytes, ct: bytes) -> bytes:
    """Return ss."""
    dk_m, sk_x = sk
    ss_m = kem.decaps(ML_KEM_768, dk_m, ct[:1088])
    ss_x = X25519PrivateKey.from_private_bytes(sk_x).exchange(
        X25519PublicKey.from_public_bytes(ct[1088:])
    )
    return _kdf(ss_m + ss_x, pk + ct)


# Re-export for callers that want fresh randomness without importing os.
urandom = os.urandom
