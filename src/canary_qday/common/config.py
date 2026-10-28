"""Runtime configuration from environment variables, plus secret-file checks."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from canary_qday.common.errors import ConfigError


@dataclass(frozen=True)
class Settings:
    """Paths and endpoints. Defaults suit a local run; compose overrides them."""

    data_dir: Path
    secrets_dir: Path
    registry_db: Path
    response_db: Path
    policy_file: Path
    reports_dir: Path
    canary_base_url: str
    proxy_host: str
    proxy_port: int
    siem_sink: str  # "file" | "hec"
    hec_url: str
    response_url: str

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from CQ_* environment variables."""
        data = Path(os.environ.get("CQ_DATA_DIR", "var"))
        secrets = Path(os.environ.get("CQ_SECRETS_DIR", str(data / "secrets")))
        return cls(
            data_dir=data,
            secrets_dir=secrets,
            registry_db=Path(os.environ.get("CQ_REGISTRY_DB", str(data / "registry.db"))),
            response_db=Path(os.environ.get("CQ_RESPONSE_DB", str(data / "response.db"))),
            policy_file=Path(os.environ.get("CQ_POLICY_FILE", str(data / "policy.json"))),
            reports_dir=Path(os.environ.get("CQ_REPORTS_DIR", str(data / "reports"))),
            canary_base_url=os.environ.get("CQ_CANARY_URL", "http://127.0.0.1:8081"),
            proxy_host=os.environ.get("CQ_PROXY_HOST", "127.0.0.1"),
            proxy_port=int(os.environ.get("CQ_PROXY_PORT", "9443")),
            siem_sink=os.environ.get("CQ_SIEM_SINK", "file"),
            hec_url=os.environ.get("CQ_HEC_URL", "http://127.0.0.1:8088"),
            response_url=os.environ.get("CQ_RESPONSE_URL", "http://127.0.0.1:8090"),
        )


def check_secret_file(path: Path) -> None:
    """Refuse secret files readable by group/others (SEC-006).

    On Windows, POSIX modes are not meaningful; the check is skipped there and the
    lab relies on Docker secrets inside Linux containers instead.
    """
    if not path.is_file():
        raise ConfigError("secret file missing")
    if os.name == "nt":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ConfigError("secret file permissions too open (expected 0600)")


def read_secret(path: Path) -> bytes:
    """Read a secret file after the permission check."""
    check_secret_file(path)
    return path.read_bytes()


def write_secret(path: Path, data: bytes) -> None:
    """Create or replace a secret file with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)
    if os.name != "nt":
        os.chmod(path, 0o600)


def env_secret(name: str, file_var: str) -> str:
    """Secret from <file_var> (Docker secret path) or, for local runs, <name>."""
    file_path = os.environ.get(file_var)
    if file_path:
        return read_secret(Path(file_path)).decode().strip()
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"missing secret {name}")
    return value
