# Versions

Recorded on 2026-10-28 from `pip freeze` in the project virtualenv (Windows 11, Python 3.13.4).
These are **installed** versions. They are not yet pinned with hashes in a lock file, and their release notes have not been reviewed individually. Both remain to do (spec §6).

| Package | Version | Role |
|---|---|---|
| cryptography | 50.0.2 | X25519, HKDF, ChaCha20-Poly1305; ML-KEM-768/1024 as differential reference |
| fastapi | 0.162.0 | canary server, mock SIEM, response engine |
| uvicorn | 0.54.0 | ASGI server |
| httpx | 0.28.1 | HTTP client |
| pydantic | 2.14.1 | schemas (via FastAPI) |
| PyYAML | 6.0.3 | experiment configs |
| pytest / pytest-cov / hypothesis | 9.2.0 / 7.1.0 / 6.170.13 | tests |
| ruff / mypy | 0.17.3 / 2.4.0 | lint and types |
| bandit / pip-audit | 1.9.4 / 2.10.1 | audit |
| pandas / matplotlib | 3.1.0 / 3.11.2 | experiments |

Docker image check (2026-10-28): `fpylll` 0.6.4 and `cysignals` 1.12.6 install in `python:3.12-slim` (Linux). They are not used by any delivered code.
