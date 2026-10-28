# Test vectors — provenance

Vectors are copied verbatim from official sources. None were generated or edited by this project.

| File | Source | Retrieved | SHA-256 |
|---|---|---|---|
| `acvp/ML-KEM-keyGen-FIPS203/internalProjection.json` | NIST ACVP-Server, `gen-val/json-files/ML-KEM-keyGen-FIPS203/`, branch `master` at commit `975de31eb83d87039ec88934fdc47d8c312b892d` — https://github.com/usnistgov/ACVP-Server | 2026-10-28 | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| `acvp/ML-KEM-encapDecap-FIPS203/internalProjection.json` | same repository and commit, `gen-val/json-files/ML-KEM-encapDecap-FIPS203/` | 2026-10-28 | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |
| `xwing/draft-connolly-cfrg-xwing-kem-11.txt` | IETF, https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt (draft revision 11, 2026-09-23). Test vectors are in Appendix C and are parsed directly from the text by `tests/kat/xwing_vectors.py`. | 2026-10-28 | `1353f61f0d706199d86b6802eab83cabbb5195b2d99fb35bca20f5e4f83db786` |

## Contents

- keyGen: 75 cases (25 per parameter set: ML-KEM-512/768/1024), inputs `d`, `z`, expected `ek`, `dk`.
- encapDecap: 135 cases — 75 encapsulation (`ek`, `m` → `c`, `k`), 30 decapsulation (valid and modified ciphertexts), 30 decapsulation-key checks, 30 encapsulation-key checks (FIPS 203 §7.2–7.3).
- X-Wing: 3 cases (`seed/sk`, `pk`, `eseed`, `ct`, `ss`).

## Verification status (measured on 2026-10-28)

- All 240 ACVP cases matched the implementation in `src/canary_qday/kem` (checked by a script; a pytest suite is pending, see `docs/status.md`).
- All 3 X-Wing cases matched (`pk`, `ct`, `ss`, and decapsulation).

To re-check integrity:

```bash
sha256sum vectors/acvp/*/internalProjection.json vectors/xwing/*.txt
```

Passing known-answer tests shows functional conformance on these inputs only; it is not evidence of security (no constant-time claim, see the root README).
