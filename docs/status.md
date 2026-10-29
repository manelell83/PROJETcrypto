# Requirement status (2026-10-28)

Legend:
- **Verified (pytest)**: covered by a test under `tests/` that passed.
- **Verified (script)**: a repository command was run and passed.
- **Partial**: some criteria verified, others not.
- **Not met** / **Not done**.

Evidence details: `docs/test-results.md`.

## Delivery summary (reference commit `c70f971`, branch `feat/M9-simulated-scenario`)

All checks below were re-run on a clean working tree after `c70f971`, on Windows 11 with Python 3.13.4 and without Docker.

**Delivered and verified**

| Item | Evidence |
|---|---|
| ML-KEM-512/768/1024 (FIPS 203) | `python tools/run.py kat`: 243/243 vectors (240 NIST ACVP and 3 X-Wing draft-11); vector SHA-256 match `vectors/README.md` |
| X-Wing hybrid | 3/3 draft-11 vectors (same command) |
| Response engine, SIEM mock, canary, backend stubs, guard, redaction | `python tools/run.py test`: 90 passed (1 third-party deprecation warning) |
| Simulated attacker scenario (M9) | `python tools/run.py demo`: 21/21 checks; also covered by the e2e pytest |
| E4 decryption-failure rate | two runs with fixed seeds (2000 and 5000 trials); see `docs/calibration.md`. Raw data under `experiments/results/e4/` are git-ignored, so they stay local; reproduce with `python tools/run.py exp e4 5000`. |
| Code quality | ruff clean (`src lab tools tests experiments`); `mypy --strict` clean on `src`; bandit: no open finding (justified annotations) |

**Delivered but not tested under real conditions**

| Item | Gap |
|---|---|
| Splunk HEC sink | unit-tested only against an unreachable endpoint (buffering, no token shown) |
| `siem/splunk/props.conf`, `savedsearches.conf` | never loaded into Splunk; the native webhook payload needs an adapter that is not implemented |
| `SharedSecretPath` webhook mode | unit-tested with the project's `Alert` schema, not with a real Splunk webhook |
| Secret-file permission check (0600) | skipped on Windows; only the POSIX path is meaningful |

**Delivered since the first summary**

- LLL-based lab attacker (`lab/attacker/`): integer LLL, Kannan embedding with verified `solve_lwe`, lab capture relay, hostile-input extractor, full recovery chain and CLI (`run.py attack`, `python -m lab.attacker`). Proven on solvable instances; honest `key-not-recovered: BKZ required` on real RED/ORANGE. See `docs/m8-status.md`.

**Deferred / out of the current scope**

| Item | Status |
|---|---|
| Per-package coverage | total 88.23 % meets the 80 % target; `kem` (≈ 85 %) and `channel` (≈ 88 %) remain below their 90 % target (`response` ≈ 95 % meets it) |
| Real Splunk integration | not done (no live instance; payload adapter missing) |
| M8 full break (RED/ORANGE key recovery) and E3 | not demonstrated; the LLL attacker is delivered but cannot reach dim 129/257 — BKZ deferred (`docs/m8-status.md`) |
| lattice-estimator | not run (Docker unavailable on the delivery machine) |
| SageMath calibration of the toy parameters | not done; RED/ORANGE remain provisional (`docs/calibration.md`) |
| Also not done | dedicated crypto-core pytest tests, 1000-run interop vs liboqs (FR-002), fuzzing, pip-audit, gitleaks, CI workflow, Python 3.12 run, experiments E2/E3/E5–E7 |

## Requirement by requirement

| ID | Status | Evidence / gap |
|---|---|---|
| FR-001 ML-KEM per FIPS 203 | Verified (script) | `tools/check_vectors.py`: 240/240 ACVP cases. Sizes printed in the guide (part 1.3). |
| FR-002 interop with a reference | **Not met** | 20-run check against `cryptography` (ML-KEM-768) passed earlier; required: 1000 per set vs liboqs |
| FR-003 toy profiles, DFR measured | Partial | E4 measured (`docs/calibration.md`); threshold reached only with ≥ 3000 failure-free trials; attack-cost calibration deferred |
| FR-004 X-Wing | Verified (script) | 3/3 draft-11 vectors. Tamper test not in pytest. |
| FR-005 secure channel | Partial | Round trip and refusal of a revoked RED key observed end to end; dedicated tamper/replay/downgrade pytest tests not delivered |
| FR-006 traps and registry | Verified (pytest) | unique tokens; queries by profile/key/params/epoch; no secret values stored |
| FR-007 canary server | Verified (pytest + e2e) | identical responses for valid, unknown and malformed tokens; event only for a valid token |
| FR-008 SIEM ingestion and alert | Verified with the **mock** SIEM | e2e and unit tests; latency not measured (E6); live Splunk untested, webhook adapter missing |
| FR-009 policy matrix | Verified (pytest) | all RED/ORANGE/GREEN cases, untrusted or allow-listed token, auto-lab |
| FR-010 exposure | Verified (pytest) | key-level and algorithmic sets equal the synthetic ground truth; expired secrets skipped |
| FR-011 rotation | Verified (pytest + e2e) | rotated secrets refused afterwards (401); rotation idempotent |
| FR-012 report | Verified (pytest + e2e) | JSON and Markdown with profile, window, exposed streams, actions, Irrecoverable and Neutralised sections |
| FR-013 attacker recovers toy keys | **Not met** | LLL attacker delivered and tested (recovers tiny instances; decrypts real captured RED traffic given the key), but it does not break real RED/ORANGE — the ≥ 90 % bar needs BKZ (`docs/m8-status.md`) |
| FR-014 one-command demo | Verified | `python tools/run.py demo` (21/21) and the e2e pytest |
| SEC-001 webhook auth and replay | Verified (pytest + e2e) | HMAC and path-secret modes; forged → 401, stale → 400, replay → 409 |
| SEC-002 dry-run without side effects | Verified (pytest + e2e) | SHA-256 of registry and policy unchanged |
| SEC-003 attacker guard | Verified (pytest) | lab env, toy profiles only, lab hosts only; runs before every socket (capture, trap trigger) |
| SEC-004 no secrets in repo or logs | Partial | redaction tests and an e2e log scan pass; gitleaks not run |
| SEC-005 input validation and fuzz | Partial | schema, length and size checks tested at the webhook and HEC endpoints; no fuzz campaign (1e5 inputs) |
| SEC-006 key files 0600 | Partial | enforced and tested on POSIX; skipped on Windows (documented) |
| SEC-007 rate limiting | Verified (pytest) | burst → one rotation; endpoint returns 429 |
| NFR-001 reproducible from a clean clone | Partial | local Python path documented and exercised; Docker path not available |
| NFR-002 type and lint clean | Verified | ruff clean on `src lab tools tests experiments`; `mypy --strict` clean on `src` (lab, tools and tests are not type-checked) |
| NFR-003 coverage | Partial | total 88.23 % (≥ 80 %: met); `response` ≈ 95 % (met); `kem` ≈ 85 % and `channel` ≈ 88 % (statements; < 90 %: not met) |
| NFR-004 deterministic experiments | Verified for E4 | fixed seeds; failure counts are reproducible by construction |
| NFR-005 latency measured (E6) | Not done | |
| EXP-001…007 | Partial | E4 implemented and run; E1 covered informally by `check-vectors`; E2, E3, E5, E6 and E7 not done |
