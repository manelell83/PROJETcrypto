# M8 (lab attacker) — status

**Status: partially delivered.** A real, LLL-based lab attacker now exists and is
tested (`lab/attacker/`). It genuinely captures traffic, extracts the public
instance, reduces the lattice and, on a solvable instance, recovers the secret,
decrypts the traffic and triggers the trap. **It does not break the real RED or
ORANGE profiles**: LLL alone cannot reach their embedding dimension (129 and 257),
so the attacker reports `key-not-recovered: BKZ required`. A full break needs the
deferred BKZ step. Until then, the M9 demo keeps using the lab oracle by default.

## What is delivered (and proven)

| Piece | File | Proven by |
|---|---|---|
| Integer LLL (exact rational Gram-Schmidt) | `lab/attacker/lattice.py` | `tests/unit/test_lattice.py`: size/Lovász conditions, unimodular lattice preservation, covolume, shortest-vector-reaches-minimum |
| Primal (Kannan) embedding + verified `solve_lwe` | `lab/attacker/lattice.py` | `tests/unit/test_kannan.py`: planted-secret recovery on tiny synthetic and `rot_matrix`-structured instances; high-noise returns None |
| Toy LWE helpers (`public_instance`, `shared_secret_from_secret`) | `src/canary_qday/kem/profiles.py` (unchanged) | `tests/unit/test_attacker_helpers.py`: LWE form with small error, GREEN refused |
| Lab TCP capture relay + hostile-input extractor | `lab/attacker/capture.py`, `extract.py` | `tests/unit/test_capture.py`: synthetic extraction, 10 hostile-input cases, in-process end-to-end capture |
| Recovery chain (recover secret → shared secret → decrypt → trigger trap) | `lab/attacker/recover.py` | `tests/unit/test_recover.py`: AEAD decryption of real captured RED traffic with the known secret, real in-process canary trap trigger, guarded `trigger_trap` |
| CLI and lab entry points | `lab/attacker/__main__.py`, `lab/attacker/live.py`, `run.py attack` | `tests/unit/test_live.py`; `run.py attack` runs end-to-end on the real lab |
| Guard (SEC-003) | `lab/attacker/guard.py` | `tests/security/test_guard_and_redaction.py` |

Capabilities **proven on solvable instances**: a planted secret is recovered from
the public instance, and the post-recovery chain (shared-secret reconstruction and
AEAD decryption) works against **real captured RED traffic** when given the secret
read from `dk` (`test_decrypt_chain_with_known_secret` — this isolates the steps
after key recovery; it is **not** evidence that LLL broke RED).

## What is NOT demonstrated

- **Recovery of the real RED or ORANGE secret key.** LLL's approximation factor is
  exponential in the dimension; the primal embedding is 2·N+1 (RED N=64 → 129,
  ORANGE N=128 → 257). `recover_secret` refuses any dimension above a documented
  budget (`DEFAULT_MAX_DIM = 40`) and returns `key-not-recovered: BKZ required`
  without running a doomed reduction. Raising the budget does not make LLL succeed.
- Anything about ML-KEM-768 or X-Wing (GREEN), which the guard refuses.

## The simulated scenario (M9) is unchanged

The M9 demo still replaces the break with a **lab-oracle record** (`CQ_LAB_SIM=1`,
0600 file under `<data_dir>/lab-oracle/`, banner `SIMULATED BREAK - no cryptanalysis
performed`) so the detection/response chain (steps 3–6) can be shown end to end.
The real attacker is available separately:

- `run.py attack [--keep]` — capture a real RED stream and run the real attacker;
- `python -m lab.attacker --capture <file> --profile RED` — attack an existing capture;
- `python -m lab.scenario.simulated_attacker --real-attack` — the M9 scenario plus one
  **informative** step R that runs the real attacker; its single extra check only
  verifies that `key-not-recovered` is honestly reported, never a success. The 21
  default checks are unchanged.

## Consequences for the requirements

- **FR-013** (attacker recovers toy keys on ≥ 90 % of RED instances, experiment E3):
  **still not met.** The attacker module exists and recovers tiny instances, but it
  does not break the real RED profile with LLL only; the ≥ 90 % bar needs BKZ.
- **EXP-003** (attack cost vs parameters): **not run.** Needs a working break at the
  real dimension, i.e. BKZ. The toy parameters remain **provisional**: their DFR is
  measured (E4), their attack cost is not (`docs/calibration.md`).
- **SEC-003** (guard): implemented, exercised by the scenario and unit-tested.

## What a full break would still need (the deferred BKZ step)

1. A real BKZ with an SVP oracle on projected blocks (enumeration or sieving), or
   `fpylll`/`fplll` in a separate attacker container (`fpylll` 0.6.4 with `cysignals`
   installs in `python:3.12-slim`, verified 2026-10-28; it does not install on Windows).
   The honest `DEFAULT_MAX_DIM` budget would then be raised to the reachable dimension.
2. Experiment E3: ≥ 30 instances per parameter set, timeout, success rate, compared
   with the lattice-estimator prediction.
3. Toy parameters for RED/ORANGE re-calibrated from the measured attack cost and
   approved by a human (OPEN item 3).
4. The lab oracle kept as the M9 default, so the demo still works where BKZ is too slow.
