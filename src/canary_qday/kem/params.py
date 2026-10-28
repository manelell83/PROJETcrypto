"""Parameter sets for ML-KEM (FIPS 203, Table 2) and Kyber-shaped toy profiles.

A single dataclass describes both: the standard sets use n = 256 and the NTT,
toy sets use a smaller power-of-two n and schoolbook multiplication.
"""

from __future__ import annotations

from dataclasses import dataclass

Q = 3329
"""The ML-KEM modulus, kept unchanged in every toy profile."""


@dataclass(frozen=True)
class Params:
    """A Module-LWE parameter set over R_q = Z_q[X]/(X^n + 1)."""

    name: str
    n: int
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    q: int = Q

    def __post_init__(self) -> None:
        if self.n < 8 or self.n & (self.n - 1):
            raise ValueError("n must be a power of two >= 8")
        if not 1 <= self.k <= 8:
            raise ValueError("k out of range")
        if not (1 <= self.du <= 11 and 1 <= self.dv <= 11):
            raise ValueError("du/dv out of range")
        if self.eta1 not in (1, 2, 3) or self.eta2 not in (1, 2, 3):
            raise ValueError("eta must be in {1, 2, 3}")

    @property
    def uses_ntt(self) -> bool:
        """Standard sets (n = 256) use the FIPS 203 NTT; toy sets use schoolbook."""
        return self.n == 256

    @property
    def is_standard(self) -> bool:
        """True for the three FIPS 203 parameter sets."""
        return self.name in STANDARD

    @property
    def msg_bytes(self) -> int:
        """Length of the K-PKE plaintext (one bit per coefficient)."""
        return self.n // 8

    @property
    def poly12_bytes(self) -> int:
        """Size of one ByteEncode_12 polynomial."""
        return 12 * self.n // 8

    @property
    def ek_bytes(self) -> int:
        """Encapsulation key size: k encoded polynomials plus the 32-byte seed rho."""
        return self.k * self.poly12_bytes + 32

    @property
    def dk_pke_bytes(self) -> int:
        """K-PKE decryption key size."""
        return self.k * self.poly12_bytes

    @property
    def dk_bytes(self) -> int:
        """ML-KEM decapsulation key size: dk_pke || ek || H(ek) || z."""
        return self.dk_pke_bytes + self.ek_bytes + 64

    @property
    def ct_bytes(self) -> int:
        """Ciphertext size: k compressed u polynomials plus one compressed v."""
        return (self.k * self.du + self.dv) * self.n // 8


ML_KEM_512 = Params("ML-KEM-512", 256, 2, 3, 2, 10, 4)
ML_KEM_768 = Params("ML-KEM-768", 256, 3, 2, 2, 10, 4)
ML_KEM_1024 = Params("ML-KEM-1024", 256, 4, 2, 2, 11, 5)

STANDARD: dict[str, Params] = {
    p.name: p for p in (ML_KEM_512, ML_KEM_768, ML_KEM_1024)
}
