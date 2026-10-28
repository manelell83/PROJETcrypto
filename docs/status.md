# Requirement status (2026-10-28)

Legend:
- **Verified**: executed, with the evidence named.
- **Implemented, untested**: code exists but was not executed against the criterion.
- **Not met**: the criterion is not satisfied.
- **Not done**: no implementation.

No pytest suite is committed yet. "Verified" below means a script or the scenario was actually run; it does not mean a CI test exists.

| ID | Status | Evidence / gap |
|---|---|---|
| FR-001 ML-KEM per FIPS 203 | Verified (script) | 240/240 ACVP cases and FIPS 203 sizes. pytest KAT suite pending. |
| FR-002 interop | Not met | 20 cross keygen/encaps/decaps with `cryptography` (ML-KEM-768) passed. Required: 1000 per set with liboqs. |
| FR-003 toy profiles | Partially verified | Round trips OK. DFR smoke check only (200 runs). E4 not run. |
| FR-004 X-Wing | Verified (script) | 3/3 draft-11 vectors. |
| FR-005 secure channel | Verified (smoke) | Round trip for RED, ORANGE and GREEN. A refused RED handshake after revocation is observed in the scenario. Tamper and downgrade tests pending. |
| FR-006 traps and registry | Verified (scenario) | Unique token per stream; registry queried by `key_id` and `params_id`. |
| FR-007 canary server | Verified (scenario) | Valid and unknown tokens return identical status, body and content type. Only a valid token raises an event. |
| FR-008 SIEM ingestion and alert | Verified with the mock SIEM (scenario) | Alert fired and delivered within the scenario run. Latency not measured (E6). Real Splunk untested. |
| FR-009 policy matrix | Partially verified | RED path observed in dry-run and apply. ORANGE and GREEN paths not executed. |
| FR-010 exposure | Partially verified | Key-level and algorithmic sets reported (2/2 in the scenario). No synthetic ground-truth test. |
| FR-011 rotation | Verified (scenario) | 8 secrets rotated; stolen credential then refused (401). Idempotency not separately tested. |
| FR-012 report | Verified (scenario) | JSON and Markdown with profile, window, exposed streams, actions, and irrecoverable vs neutralised. |
| FR-013 attacker | Not met | M8 not delivered (`docs/m8-status.md`). |
| FR-014 one-command demo | Verified | `python tools/run.py demo` runs the simulated scenario with the mock SIEM. |
| SEC-001 webhook auth and replay | Verified (scenario) | Forged alert → 401; replayed alert → 409. `SharedSecretPath` not exercised. |
| SEC-002 dry-run byte-identical | Verified (scenario) | SHA-256 of `registry.db` and `policy.json` unchanged after a dry-run incident. |
| SEC-003 guard | Verified (scenario) | Guard refuses GREEN. Host refusal and missing `CQ_LAB` not exercised. |
| SEC-004 no secrets in logs | Partially verified | Manual grep of the scenario logs, events and reports: no `FAKE-` values, no full trap tokens. gitleaks not run; no automated redaction test. |
| SEC-005 input validation and fuzz | Implemented, untested | Length and schema checks in frames, KEM and alerts. No fuzz run. |
| SEC-006 key files 0600 | Implemented, partially effective | `write_secret`/`read_secret` enforce 0600 on POSIX; the check is skipped on Windows (documented). |
| SEC-007 rate limiting | Implemented, untested | |
| NFR-001 to NFR-005 | Not done | No CI workflow, coverage, experiments or latency measurement yet. |
| EXP-001 to EXP-007 | Not done | |
