# CLAUDE.md — Canary Q-Day

Read `IMPLEMENTATION_SPEC.md` **before any change**. It is authoritative. If a task conflicts with it, stop and ask. Anything marked **OPEN** is a human decision: do not guess.

## Project in one paragraph
Academic advanced-cryptography project: in-depth study of ML-KEM (Kyber, FIPS 203), validated by a lab where synthetic encrypted traffic carries traps; if toy-parameter profiles are broken by a lab attacker, a SIEM alert triggers a policy-gated response. ~70% study of Kyber, ~30% SOC application.

## Working rules
1. Work **one milestone at a time** (spec §14). Never generate the whole project in one go.
2. Start each milestone by stating the plan (files, tests, commands). End it by running tests, showing `git diff --stat`, reporting results, and **waiting for approval** (mandatory for M1–M3, M7, M8).
3. Small commits, Conventional Commits (`feat(kem): ...`), branch `feat/Mx-name`.
4. Write the test first or together with the code. A task is not done until its tests run green.
5. Ask when something is OPEN, ambiguous, or would add a component not in the spec. Do not add services, databases, AI, blockchain or frameworks "to look sophisticated".

## Coding conventions
- Python 3.12, type hints everywhere, `mypy --strict` and `ruff` clean, docstrings on public functions.
- `kem/` depends on the standard library only. Respect the dependency rules in spec §8.
- No global mutable state in the crypto core. Pure functions where possible.
- Errors: use the typed exceptions in `common/errors.py`; never leak secrets in messages.

## Security invariants (never violate)
- **Never invent a cryptographic primitive.** Only ML-KEM/toy-Kyber (the research objective) is implemented by hand; everything else comes from `cryptography`/`hashlib`.
- Randomness only from `os.urandom`/`secrets`. Deterministic seeds only in tests/KAT/experiments, and clearly marked.
- Never commit, print, or log: private keys, shared secrets, session keys, tokens, plaintext payloads, HEC token. Log `token_id` (truncated hash) only.
- Never fabricate test vectors, benchmark numbers, security proofs, or citations. Vectors come from official sources, with provenance and SHA-256 in `vectors/README.md`. If a source is unavailable, say so.
- The own Python implementation makes **no constant-time claim** and must not be described as production-secure.
- The attacker module (`lab/attacker`) must call `guard.py` first, refuse non-toy profiles and non-lab hosts, and is never imported by `src/`.
- Response actions are **dry-run by default**; heavy actions require approval (spec §7.4). Actions must be idempotent.
- Constant-time comparison (`hmac.compare_digest`) for MACs and tokens.
- Treat all external input (webhooks, pcap content, frames, JSON) as hostile: validate lengths, schemas and encodings first.
- Pin dependencies; check `pip-audit`; do not add a dependency without justification in the PR description.

## Testing workflow
`make lint` → `make test` → `make kat` → (after integration work) `make lab-up && pytest tests/integration` → `make audit`.
- Property tests with `hypothesis`; fuzz targets for every parser.
- Never assert wall-clock timing in unit tests; timing belongs in `experiments/`.
- Coverage gates: ≥ 90% on `kem`, `channel`, `response`; ≥ 80% overall.
- Passing tests is not proof of cryptographic security; do not claim it.

## Experiments
Run through `make exp E=<id>`. Store config, raw data, environment (`env.json`) and seeds. Report **measured** results only; keep expected values and measured values in separate fields. Do not write conclusions before data exists.

## When unsure
Stop, summarise what you know, list the options with trade-offs, and ask. A short question is better than a wrong architectural decision.
