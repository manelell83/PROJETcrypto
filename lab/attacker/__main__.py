"""Lab attacker CLI: run the real recovery chain on a capture (M8).

    CQ_LAB=1 python -m lab.attacker --capture <file> --profile RED

The guard runs first (lab mode, toy profile only). This performs a REAL attack
attempt -- no simulation -- but with LLL only, so on the real RED/ORANGE
profiles it reports `key-not-recovered` (BKZ required), never a false success.
For the simulated end-to-end story, use the M9 scenario instead.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from canary_qday.kem.profiles import params_for
from lab.attacker.guard import require_lab
from lab.attacker.recover import DEFAULT_MAX_DIM, run_attack

BANNER = "REAL ATTACK (lab, toy profiles) - LLL only, no cryptanalysis of ML-KEM/X-Wing"


def main() -> int:
    """Parse arguments, enforce the guard, run the chain, print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path, help="capture file to attack")
    parser.add_argument("--profile", choices=["RED", "ORANGE"], default="RED")
    parser.add_argument("--max-dim", type=int, default=DEFAULT_MAX_DIM)
    args = parser.parse_args()

    require_lab(args.profile)  # CQ_LAB=1 and a toy profile, before anything else
    print(BANNER)
    result = run_attack(args.capture, params_for(args.profile), max_dim=args.max_dim)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.status == "trap-triggered" else 1


if __name__ == "__main__":
    raise SystemExit(main())
