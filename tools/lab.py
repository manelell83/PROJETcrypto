"""Start/stop the local lab as plain processes on 127.0.0.1 (no Docker needed).

Services: mock SIEM (HEC + rule + webhook), response engine, canary server, proxy.
Lab secrets (HEC token, webhook secret, admin token) are generated on first run
into <data_dir>/secrets/*.txt (0600 on POSIX) and passed as *_FILE variables.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import socket

# Justification (bandit B404/B603/B607): the lab launcher only runs fixed local commands.
import subprocess  # nosec B404
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from canary_qday.common.config import write_secret


@dataclass(frozen=True)
class Ports:
    """TCP ports of the lab services."""

    hec: int = 8088
    response: int = 8090
    canary: int = 8081
    proxy: int = 9443

    @classmethod
    def offset(cls, base: int) -> Ports:
        """Ports shifted by base (used by tests to avoid clashing with a running lab)."""
        return cls(8088 + base, 8090 + base, 8081 + base, 9443 + base)


SECRET_NAMES = ("hec_token", "webhook_secret", "admin_token")


def ensure_secrets(data_dir: Path) -> dict[str, Path]:
    """Create the lab secrets once; return their paths."""
    paths = {}
    for name in SECRET_NAMES:
        p = data_dir / "secrets" / f"{name}.txt"
        if not p.exists():
            write_secret(p, secrets.token_hex(32).encode())
        paths[name] = p
    return paths


def lab_env(data_dir: Path, ports: Ports, *, apply: bool) -> dict[str, str]:
    """Environment shared by every lab process."""
    s = ensure_secrets(data_dir)
    env = dict(os.environ)
    env.update(
        CQ_DATA_DIR=str(data_dir),
        CQ_HEC_TOKEN_FILE=str(s["hec_token"]),
        CQ_WEBHOOK_SECRET_FILE=str(s["webhook_secret"]),
        CQ_ADMIN_TOKEN_FILE=str(s["admin_token"]),
        CQ_SIEM_SINK="hec",
        CQ_HEC_URL=f"http://127.0.0.1:{ports.hec}",
        CQ_WEBHOOK_URL=f"http://127.0.0.1:{ports.response}/v1/alerts",
        CQ_CANARY_URL=f"http://127.0.0.1:{ports.canary}",
        CQ_RESPONSE_URL=f"http://127.0.0.1:{ports.response}",
        CQ_PROXY_HOST="127.0.0.1",
        CQ_PROXY_PORT=str(ports.proxy),
        CQ_APPLY="1" if apply else "0",
        PYTHONUNBUFFERED="1",
    )
    env.pop("CQ_HEC_TOKEN", None)
    env.pop("CQ_WEBHOOK_SECRET", None)
    env.pop("CQ_ADMIN_TOKEN", None)
    return env


def _commands(ports: Ports) -> dict[str, list[str]]:
    py = sys.executable
    uv = [py, "-m", "uvicorn", "--factory", "--host", "127.0.0.1", "--log-level", "warning"]
    return {
        "mock-siem": [*uv, "--port", str(ports.hec), "canary_qday.siem.mock_hec:app_from_env"],
        "response": [py, "-m", "canary_qday.response.webhook"],
        "canary": [*uv, "--port", str(ports.canary),
                   "canary_qday.services.canary_server:app_from_env"],
        "proxy": [py, "-m", "canary_qday.services.proxy"],
    }


def _wait_port(port: int, timeout: float = 30.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _pidfile(data_dir: Path) -> Path:
    return data_dir / "lab-pids.json"


def start_service(name: str, data_dir: Path, ports: Ports, *, apply: bool) -> int:
    """Start one service and wait for its port; return the PID."""
    env = lab_env(data_dir, ports, apply=apply)
    if name == "response":
        env["CQ_PORT"] = str(ports.response)
    logs = data_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log = (logs / f"{name}.log").open("ab")
    proc = subprocess.Popen(_commands(ports)[name], env=env, stdout=log, stderr=log)  # noqa: S603  # nosec B603
    port = {"mock-siem": ports.hec, "response": ports.response,
            "canary": ports.canary, "proxy": ports.proxy}[name]
    if not _wait_port(port):
        proc.terminate()
        raise RuntimeError(f"{name} did not start; see {logs / (name + '.log')}")
    pids = _read_pids(data_dir)
    pids[name] = proc.pid
    _pidfile(data_dir).write_text(json.dumps(pids), encoding="utf-8")
    return proc.pid


def _read_pids(data_dir: Path) -> dict[str, int]:
    p = _pidfile(data_dir)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def stop_service(name: str, data_dir: Path) -> None:
    """Stop one service if running."""
    pids = _read_pids(data_dir)
    pid = pids.pop(name, None)
    if pid is not None:
        _kill(pid)
        _pidfile(data_dir).write_text(json.dumps(pids), encoding="utf-8")


def _kill(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],  # noqa: S603, S607  # nosec
                       capture_output=True, check=False)
    else:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, 15)


def up(data_dir: Path, ports: Ports, *, apply: bool = False) -> dict[str, int]:
    """Start all services (response engine dry-run unless apply)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    for name in ("mock-siem", "response", "canary", "proxy"):
        start_service(name, data_dir, ports, apply=apply)
    (data_dir / "lab-ports.json").write_text(json.dumps(asdict(ports)), encoding="utf-8")
    return _read_pids(data_dir)


def down(data_dir: Path) -> None:
    """Stop every service started by up()."""
    for name in list(_read_pids(data_dir)):
        stop_service(name, data_dir)
