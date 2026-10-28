# M8 (lab attacker) — status

**Status: not delivered.** The project contains no cryptanalytic attack code. The attacker step in the demo and in the lab guide is a **simulation**, labelled as such everywhere it appears.

## Why M8 is not delivered

The specification (§4, §14) plans a lab-only module that recovers toy-profile keys from captured traffic. This module was not produced in this delivery. The decision was taken with the project owner on 2026-10-28. The rest of the chain (traps, canary, SIEM, response) does not depend on *how* a key gets broken, so it can be demonstrated and tested without it.

## What replaces it: the simulated scenario

| Real M8 step (spec §3, step 4) | Simulated replacement |
|---|---|
| Extract the public instance from the pcap | Step 1 shows only the public handshake metadata (profile, `key_id`) that a passive observer sees. Nothing is decrypted. |
| Break the toy key, decapsulate, decrypt the payload | Step 2 reads a **lab-oracle record**. When `CQ_LAB_SIM=1`, the generator writes it for RED/ORANGE streams only, as a 0600 file under `<data_dir>/lab-oracle/`. It holds exactly what a successful attacker would have read: the trap URL and one synthetic credential. Output banner: `SIMULATED BREAK - no cryptanalysis performed`. |
| Use the stolen material | Steps 3–6 are **not simulated**. They use the real proxy, backend stubs, canary server, mock SIEM, signed webhook and response engine. |

What the scenario therefore demonstrates:

- the detection and response path from trap use to an incident report;
- the dry-run guarantee;
- containment: profile switch, key revocation, secret rotation;
- the negative controls.

What it does **not** demonstrate:

- that the toy profiles are breakable, or how much it costs to break them;
- anything about ML-KEM-768 or X-Wing, whose security is not affected and not tested by this scenario.

The guard (`lab/attacker/guard.py`) is delivered and is called before every lab-attacker action. It requires `CQ_LAB=1`, accepts only toy profiles and only lab hosts. It refuses GREEN, which the scenario checks.

## Consequences for the requirements

- **FR-013** (attacker recovers toy keys, experiment E3): **not met**.
- **EXP-003** (attack cost vs parameters): **not run**. The toy parameters therefore remain **provisional**: their decryption-failure rate is measured (E4), but their attack cost is not (see `docs/calibration.md`).
- **SEC-003** (guard): implemented, exercised by the scenario and unit-tested (`tests/security/test_guard_and_redaction.py`).

## What a future real M8 would need (design level)

1. A separate attacker container. `fpylll` 0.6.4 with `cysignals` installs in `python:3.12-slim`: verified on 2026-10-28. It does not install on Windows.
2. Every entry point calls `guard.require_lab()` first. The module may import only `kem.params` / `kem.profiles` (spec §8), and `src/` never imports it.
3. Parsing of captured traffic treated as hostile input, with lengths and frame types validated first.
4. A key-recovery method taken from the published lattice-cryptanalysis literature (cited, not invented). It would be validated first on deterministic tiny instances in CI, then measured against the lattice-estimator prediction in experiment E3 (≥ 30 instances per parameter set, timeout, success rate).
5. Toy parameters for RED/ORANGE then re-calibrated from measured data, and approved by a human (OPEN item 3).
6. The simulated oracle kept as a fallback, so the guide still works on machines that cannot run the attack container.
