# Test and check results (observed)

Every number below comes from a command actually run on the delivery machine on 2026-10-28 (Windows 11, Python 3.13.4, no Docker). Commands are run from the repository root.

## Summary

| Check | Command | Result |
|---|---|---|
| pytest (unit, security, e2e) | `python tools/run.py test` | **64 passed**, 1 warning, ≈ 30–37 s |
| Official vectors (NIST ACVP and X-Wing draft-11) | `python tools/run.py check-vectors` | **243/243** match |
| Simulated scenario (demo) | `python tools/run.py demo` | **21/21** checks passed (several runs) |
| Lint | `ruff check src lab tools tests experiments` | All checks passed |
| Types | `mypy src` (`--strict` via pyproject) | Success: no issues found in 51 source files |
| Static security analysis | `bandit -q -r src lab tools` | 0 open findings after triage (below) |
| Coverage | `pytest --cov=canary_qday` | **75 %** total (details below) |
| E4 DFR | `python tools/run.py exp e4 2000` and `... 5000` | see `docs/calibration.md` |

The only pytest warning is a `StarletteDeprecationWarning` raised by `fastapi.testclient` about `httpx`. It is a third-party deprecation, not a project issue. No dependency was added to silence it.

## pytest suites

| File | Tests | Covers |
|---|---|---|
| `tests/unit/test_response_policy.py` | 11 | FR-009 policy matrix (RED/ORANGE/GREEN, untrusted or allow-listed token, auto-lab, profiles to disable) |
| `tests/unit/test_response_engine.py` | 13 | FR-010 exposure against synthetic ground truth; FR-011 rotation and idempotency; FR-012 report; SEC-002 dry-run byte-identical; SEC-007 burst rate limiting; dry and apply rate scopes; approval flow (`E_POLICY`, `E_NOT_FOUND`) |
| `tests/unit/test_siem_and_services.py` | 10 | FR-006 tokens and registry (no secret value stored); FR-007 canary identical responses, event only for a valid token, log-injection neutralised; backend stub 200/401/404/503; lab oracle never for GREEN; mock SIEM rule, throttling, HMAC signature and HTTP auth; file sink |
| `tests/security/test_webhook.py` | 10 | SEC-001 HMAC (valid, forged, tampered body, stale, replayed signature), short secrets, path-secret mode, alert timestamp window, API codes 202/401/400/409/422/429, admin token |
| `tests/security/test_guard_and_redaction.py` | 19 | SEC-003 guard (lab env, non-toy profiles, lab and non-lab hosts); SEC-004 redaction and JSON logs; HEC sink never shows its token and buffers when down; SEC-006 secret files |
| `tests/e2e/test_simulated_scenario.py` | 1 | FR-014 / M9: full scenario on local processes (ports +200), 21 checks, no `FAKE-` value or full trap token in logs, events or reports |

During development, the first run of `test_response_engine.py` had 5 failures. They came from a test fixture: the synthetic streams were dated t = 1000 s, so their secrets were already expired at the real current time. The fixture was corrected to use the current time; the production code was not changed for this.

## Coverage (statements, in-process only)

| Package | Coverage | Spec target (NFR-003) |
|---|---|---|
| `response` | ≈ 94 % (480 statements, 29 missed) | ≥ 90 %: **met** |
| `kem` | 28–100 % per module | ≥ 90 %: **not met**. The KEM is exercised by `tools/check_vectors.py` (243 vectors), which runs outside pytest. |
| `channel` | 62–88 % per module | ≥ 90 %: **not met** |
| `services/proxy.py` | 0 % measured | runs in a subprocess during the e2e test, which coverage does not follow |
| Total | 75 % | ≥ 80 %: **not met** |

## bandit triage

| Finding | Location | Decision |
|---|---|---|
| B608 SQL string building | `common/store.py` (`IN (?,?,…)`) | false positive: only `?` placeholders are interpolated, values are bound; annotated `nosec` with a justification |
| B311 `random` | `traffic/generator.py` | non-security choice of stub services and request names; annotated |
| B105 hard-coded password | `traffic/traps.py` | `"db_password": 5` maps a secret *kind* to a sensitivity level; annotated |
| B404/B603/B607 subprocess | `tools/lab.py`, `tools/run.py` | fixed local commands, no external input; annotated |

## Not run, and why

| Item | Reason |
|---|---|
| `pip-audit` | needs network access and a local cache on the system disk, which is full. To run: `python tools/run.py audit`. |
| gitleaks | not installed. A manual review of the diff found no secret (see the final check in the delivery notes). |
| Docker compose lab, CI workflow | Docker is blocked on the delivery machine; no `.github/workflows` file is delivered. |
| Dedicated crypto-core pytest tests (NTT and codec properties, tampered frames, downgrade, fuzzing) | not part of this delivery. The core is checked by the official vectors and by the end-to-end scenario only. |
| Interoperability at scale (FR-002: 1000 runs per set against liboqs) | not done. An earlier 20-run check against `cryptography` (OpenSSL) for ML-KEM-768 passed. |
| Live Splunk | not available; see `siem/splunk/README.md` |
| Python 3.12 | only Python 3.13.4 was used |

Passing these tests shows that the implemented behaviour matches the tested cases. It is **not** evidence of cryptographic security.
