# Toy parameters and calibration

**Status: DFR measured (E4); attack-cost calibration deferred.** The RED/ORANGE choice is therefore **provisional** (OPEN item 3 is not closed).

## Candidates

All candidates keep q = 3329 and the full ML-KEM structure (K-PKE, FO transform with implicit rejection). Multiplication is schoolbook in Z_q[X]/(X^n+1). n ≥ 64 keeps the K-PKE message at ≥ 64 bits, so brute-forcing m is not a shortcut. Source: `src/canary_qday/kem/profiles.py`.

| Candidate | n | k | η1 | η2 | du | dv | ek (B) | ct (B) | Role |
|---|---|---|---|---|---|---|---|---|---|
| toy-n64-k1 | 64 | 1 | 2 | 2 | 10 | 4 | 128 | 112 | **RED (provisional)** |
| toy-n64-k2 | 64 | 2 | 2 | 2 | 10 | 4 | 224 | 192 | **ORANGE (provisional)** |
| toy-n64-k3 | 64 | 3 | 2 | 2 | 10 | 4 | 320 | 272 | candidate |
| toy-n128-k2 | 128 | 2 | 2 | 2 | 10 | 4 | 416 | 384 | candidate |
| toy-n64-k1-du4dv2 | 64 | 1 | 2 | 2 | 4 | 2 | 128 | 48 | negative control |
| toy-n64-k2-du4dv2 | 64 | 2 | 2 | 2 | 4 | 2 | 224 | 80 | negative control |

## E4 — measured decryption-failure rate

Method (`experiments/runners/e4_dfr.py`):
- A trial is `KeyGen_internal` (a new key every 100 trials), then `Encaps_internal`, then `Decaps_internal`. It fails when the decapsulated key differs from the encapsulated one.
- Seeds are deterministic (`random.Random("20261028:<candidate>")`, experiment only).
- Acceptance: the one-sided 95 % upper bound on the DFR must be < 10⁻³. The bound is the rule of three for 0 failures and the Wilson bound otherwise.

### Run 1: 2000 trials per candidate (200 for the negative controls)

Results directory: `experiments/results/e4/20261028T193851Z/` (git-ignored; reproduce with `python tools/run.py exp e4 2000`).

| Candidate | Trials | Failures | Measured DFR | 95 % upper bound | Meets threshold | Wall time (s) |
|---|---|---|---|---|---|---|
| toy-n64-k1 | 2000 | 0 | 0 | 1.5e-3 | no (too few trials) | 7.81 |
| toy-n64-k2 | 2000 | 0 | 0 | 1.5e-3 | no (too few trials) | 21.80 |
| toy-n64-k3 | 2000 | 0 | 0 | 1.5e-3 | no (too few trials) | 40.68 |
| toy-n128-k2 | 2000 | 0 | 0 | 1.5e-3 | no (too few trials) | 76.84 |
| toy-n64-k1-du4dv2 | 200 | 200 | 1 | 1 | no | 0.79 |
| toy-n64-k2-du4dv2 | 200 | 200 | 1 | 1 | no | 2.11 |

### Run 2: 5000 trials per candidate

Results directory: `experiments/results/e4/20261028T194152Z/` (reproduce with `python tools/run.py exp e4 5000`). The same seeds are used, so the first 2000 trials of each candidate repeat run 1.

| Candidate | Trials | Failures | Measured DFR | 95 % upper bound | Meets threshold | Wall time (s)* |
|---|---|---|---|---|---|---|
| toy-n64-k1 | 5000 | 0 | 0 | 6.0e-4 | **yes** | 21.62 |
| toy-n64-k2 | 5000 | 0 | 0 | 6.0e-4 | **yes** | 55.92 |
| toy-n64-k3 | 5000 | 0 | 0 | 6.0e-4 | **yes** | 111.11 |
| toy-n128-k2 | 5000 | 0 | 0 | 6.0e-4 | **yes** | 195.64 |
| toy-n64-k1-du4dv2 | 200 | 200 | 1 | 1 | no | 0.84 |
| toy-n64-k2-du4dv2 | 200 | 200 | 1 | 1 | no | 2.41 |

\* Run 2 shared the CPU with pytest runs started at the same time, so its wall times are inflated and not comparable with run 1.

**DFR conclusion (only):** the four du=10/dv=4 candidates, including the provisional RED (`toy-n64-k1`) and ORANGE (`toy-n64-k2`), meet the documented threshold (95 % upper bound < 10⁻³) on this run. The du=4/dv=2 variants are rejected. This says nothing about how hard the candidates are to attack.

### Reading the numbers

- Zero failures in N trials does **not** mean the DFR is zero; it only bounds it (< 3/N at 95 %). At least 3000 failure-free trials are needed to pass the 10⁻³ threshold.
- The `du4dv2` controls fail on every trial. The likely cause, not separately measured, is that coarse compression (du = 4, dv = 2) adds rounding noise far above the q/4 decoding margin. Either way, the controls show that the harness detects failures.
- For the standard sets the DFR is not measurable. FIPS 203 (Table 1) gives 2⁻¹³⁹ (ML-KEM-512), 2⁻¹⁶⁴ (768) and 2⁻¹⁷⁴ (1024).
- Timings are wall-clock times of pure Python on one machine (Windows 11, Python 3.13.4). They are not representative of optimised implementations.

## Deferred: attack-cost calibration

Spec M3 asks that RED/ORANGE be chosen from **lattice-estimator** predictions and **E3** measurements (attack success rate and time). Neither is part of this delivery:

| Item | Status | Reason |
|---|---|---|
| lattice-estimator (SageMath container) | not run | Docker is blocked on the delivery machine (system disk full); the SageMath image cannot be used. No estimator numbers are reported or guessed. |
| E3 (attack cost vs parameters) | not run | depends on the attacker module M8, which is not delivered (`docs/m8-status.md`) |

Consequences:
- The claim "RED is breakable in the demo, ORANGE with more compute" is **not established** by this repository. The demo's attacker step is simulated.
- To close OPEN 3:
  1. run the estimator for each candidate (primal and dual uSVP; secret and error distributions = CBD(η));
  2. run E3 on ≥ 30 instances per candidate;
  3. pick RED/ORANGE from the measured data;
  4. have a human approve the choice;
  5. update `PROFILE_PARAMS` and this page.
