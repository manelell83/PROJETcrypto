"""Cross-platform task runner (make is not available everywhere, e.g. Windows).

Usage: python tools/run.py <target> [args]
Targets mirror the Makefile contract of IMPLEMENTATION_SPEC.md section 13:
  setup lint test kat check-vectors lab-up lab-down gen demo scenario exp audit
The lab always lives in var/demo (same directory as the demo scenario).
Targets that are not implemented yet say so and exit with code 2.
"""

from __future__ import annotations

import os

# Justification (bandit B404/B603): the task runner only runs fixed local commands.
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
LAB_DIR = ROOT / "var" / "demo"
VENV_PY = ROOT / ".venv" / (
    "Scripts/python.exe" if os.name == "nt" else "bin/python"
)


def _py() -> str:
    return str(VENV_PY) if VENV_PY.exists() else sys.executable


def _run(*cmd: str, env: dict[str, str] | None = None) -> int:
    print("+", " ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT, env=env)  # noqa: S603  # nosec B603


def setup() -> int:
    """Create .venv and install the project with dev and experiment extras."""
    if not VENV_PY.exists():
        rc = _run(sys.executable, "-m", "venv", str(ROOT / ".venv"))
        if rc:
            return rc
    return _run(str(VENV_PY), "-m", "pip", "install", "-e", ".[dev,exp]")


def lint() -> int:
    """ruff + mypy --strict."""
    return _run(_py(), "-m", "ruff", "check", "src", "lab", "tools") or _run(
        _py(), "-m", "mypy", "src"
    )


def test() -> int:
    """pytest (all suites present under tests/)."""
    return _run(_py(), "-m", "pytest")


def kat() -> int:
    """Known-answer tests: official ACVP and X-Wing vectors (tools/check_vectors.py)."""
    return _run(_py(), "tools/check_vectors.py")


def lab_up() -> int:
    """Start the local lab (response engine dry-run unless --apply)."""
    from tools import lab

    pids = lab.up(LAB_DIR.resolve(), lab.Ports(), apply="--apply" in sys.argv)
    print("lab up:", pids)
    return 0


def lab_down() -> int:
    """Stop the local lab."""
    from tools import lab

    lab.down(LAB_DIR.resolve())
    print("lab down")
    return 0


def check_vectors() -> int:
    """Official ACVP and X-Wing vectors (works before the pytest suite exists)."""
    return _run(_py(), "tools/check_vectors.py")


def gen() -> int:
    """Generate traffic in the running lab: run.py gen PROFILE [N] [--lab-sim]."""
    from tools import lab

    args = [a for a in sys.argv[2:] if not a.startswith("--")]
    profile = args[0] if args else "RED"
    n = args[1] if len(args) > 1 else "1"
    env = lab.lab_env(LAB_DIR.resolve(), lab.Ports(), apply=False)
    if "--lab-sim" in sys.argv:
        env["CQ_LAB_SIM"] = "1"
    return _run(
        _py(), "-m", "canary_qday.traffic.generator", "--profile", profile, "--streams", n, env=env
    )


def scenario() -> int:
    """Simulated attacker scenario (no cryptanalysis), see docs/m8-status.md."""
    env = dict(os.environ, CQ_LAB="1")
    extra = sys.argv[2:]
    return _run(_py(), "-m", "lab.scenario.simulated_attacker", *extra, env=env)


def exp() -> int:
    """Experiments: run.py exp e4 [trials]. Only E4 is implemented."""
    args = sys.argv[2:]
    if not args or args[0].lower() != "e4":
        print("only E4 (decryption-failure rate) is implemented; see docs/status.md")
        return 2
    return _run(_py(), "-m", "experiments.runners.e4_dfr", *args[1:])


def audit() -> int:
    """bandit + pip-audit."""
    return _run(_py(), "-m", "bandit", "-q", "-r", "src") or _run(_py(), "-m", "pip_audit")


TARGETS = {
    "setup": setup,
    "lint": lint,
    "test": test,
    "kat": kat,
    "check-vectors": check_vectors,
    "lab-up": lab_up,
    "lab-down": lab_down,
    "gen": gen,
    "demo": scenario,
    "scenario": scenario,
    "exp": exp,
    "audit": audit,
}


def main() -> int:
    """Dispatch."""
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        print(__doc__)
        return 2
    # Targets import the project: re-run under the project virtualenv when it exists.
    if (
        sys.argv[1] != "setup"
        and VENV_PY.exists()
        and Path(sys.executable).resolve() != VENV_PY.resolve()
    ):
        return subprocess.call([str(VENV_PY), __file__, *sys.argv[1:]], cwd=ROOT)  # noqa: S603  # nosec B603
    return TARGETS[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
