# Canary Q-Day

A study of **ML-KEM (Kyber, FIPS 203)** and a lab built on it. Synthetic encrypted traffic, at three crypto levels, carries trap credentials. When a trap is used, a SIEM alert triggers a policy-gated, dry-run-by-default incident response.

> **Study artefact.** The ML-KEM implementation is pure Python, **not constant-time** and **not for production**. Passing tests shows functional conformance only, not security.
>
> **The attacker step is simulated.** No cryptanalytic attack is implemented (M8 not delivered, see [docs/m8-status.md](docs/m8-status.md)). Nothing here suggests that ML-KEM or X-Wing are weakened.

## What is in the box

| Area | Content |
|---|---|
| `src/canary_qday/kem` | ML-KEM-512/768/1024 from FIPS 203 (NTT, CBD, rejection sampling, codecs, K-PKE, FO transform with implicit rejection, input checks) and Kyber-shaped toy profiles with schoolbook multiplication. Standard library only. |
| `src/canary_qday/hybrid` | X-Wing (draft-connolly-cfrg-xwing-kem-11) and a TLS-style combiner kept for comparison. |
| `src/canary_qday/channel` | One-shot KEM handshake, HKDF-SHA256 with the profile bound in `info`, ChaCha20-Poly1305 with counter nonces, length-prefixed frames, replay and downgrade protection. |
| `src/canary_qday/traffic`, `services` | Generator, traps, registry, proxy, backend stubs, canary server. |
| `src/canary_qday/siem` | `SiemSink`, file sink, Splunk HEC sink, mock SIEM with a rule and a signed webhook. |
| `src/canary_qday/response` | Webhook auth, policy matrix, exposure, actions (dry-run by default), incident report. |
| `lab/` | Attacker guard and the **simulated** attacker scenario. |
| `vectors/` | Official NIST ACVP and X-Wing draft vectors, with provenance and SHA-256 ([vectors/README.md](vectors/README.md)). |

Profiles:
- `RED` = toy n=64, k=1;
- `ORANGE` = toy n=64, k=2;
- `GREEN` = X-Wing (X25519 + ML-KEM-768).

The toy parameters are **provisional** (see [docs/decisions.md](docs/decisions.md)).

## Quick start

```bash
python tools/run.py setup
```

```bash
python tools/run.py demo
```

The demo starts the lab on `127.0.0.1` (ports 8081, 8088, 8090, 9443), runs the simulated scenario and prints `RESULT: n/n checks passed`. On machines with `make`, `make setup` and `make demo` do the same.

## Commands

| Command | What it does |
|---|---|
| `python tools/run.py setup` | create `.venv` and install the project (`.[dev,exp]`) |
| `python tools/run.py test` | pytest: unit, security and end-to-end suites |
| `python tools/run.py lint` | ruff and `mypy --strict` on `src/` |
| `python tools/run.py kat` (or `check-vectors`) | official NIST ACVP and X-Wing vectors |
| `python tools/run.py demo [--keep]` | simulated attacker scenario on a fresh `var/demo` |
| `python tools/run.py lab-up [--apply]` / `lab-down` | start or stop the local lab services |
| `python tools/run.py gen RED 2 [--lab-sim]` | generate streams in the running lab |
| `python tools/run.py exp e4 [trials]` | E4: decryption-failure rate of the toy candidates |
| `python tools/run.py attack [--keep]` | real LLL lab attacker on RED (honest `key-not-recovered: BKZ required`) |
| `python tools/run.py audit` | bandit and pip-audit (pip-audit needs network access) |

The step-by-step lab guide (in French) is in [docs/guide/TP-canary-qday.md](docs/guide/TP-canary-qday.md).

## Documentation

- [docs/architecture.md](docs/architecture.md): components, protocol, trust zones, response engine.
- [docs/decisions.md](docs/decisions.md): OPEN items and deviations from the spec.
- [docs/calibration.md](docs/calibration.md): toy parameters and measured DFR (E4); deferred calibration.
- [docs/test-results.md](docs/test-results.md): test and check results actually observed.
- [docs/m8-status.md](docs/m8-status.md): why the attacker module is not delivered and what replaces it.
- [docs/status.md](docs/status.md): requirement-by-requirement status.
- [siem/splunk/README.md](siem/splunk/README.md): Splunk configuration (untested) and known gaps.

## Status

In short:
- the KEM and X-Wing vectors pass, and so does the pytest suite (including the end-to-end simulated scenario with the mock SIEM);
- E4 (DFR) is measured;
- not done: CI, experiments E1–E3 and E5–E7, a live Splunk test, the lattice-estimator calibration and the attacker module (M8).

## Limitations (spec §12)

1. The canary does **not** detect passive harvesting. It detects **decrypt-and-use** of synthetic traps only, and a careful attacker may ignore the traps.
2. Synthetic traffic says something about the crypto class, not about whether real traffic was captured.
3. The own implementation is for study. A realistic GREEN deployment should use a reviewed library.
4. No novelty claim is made without a proper literature search.
5. Toy profiles are deliberately weak. Their DFR is measured (E4), but their attack cost is not (E3 and lattice-estimator deferred), so the parameter choice remains provisional.
6. The attacker step of the demo is simulated (lab oracle). No cryptanalysis is implemented.
