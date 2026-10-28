"""Lab oracle for the SIMULATED attacker scenario (stand-in for the undelivered M8).

When lab simulation is enabled, the generator records, for toy-profile streams
only, what an attacker *would* learn after breaking the toy key: the trap URL
and one synthetic credential. The record replaces the cryptanalytic step; it
proves nothing about the security of ML-KEM or X-Wing. GREEN streams are never
recorded. Files are written 0600 under <data_dir>/lab-oracle/.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from canary_qday.common.config import write_secret
from canary_qday.kem.profiles import TOY_PROFILES

BANNER = "SIMULATED BREAK - no cryptanalysis performed (lab oracle, see docs/m8-status.md)"


def enabled() -> bool:
    """Lab simulation is opt-in via CQ_LAB_SIM=1."""
    return os.environ.get("CQ_LAB_SIM") == "1"


def record(
    data_dir: Path,
    *,
    stream_id: str,
    profile: str,
    key_id: str,
    trap_url: str,
    service: str,
    credential: str,
) -> Path | None:
    """Write the oracle record for a toy stream; return its path (None for GREEN)."""
    if profile not in TOY_PROFILES:
        return None
    path = data_dir / "lab-oracle" / f"{stream_id}.json"
    body = {
        "banner": BANNER,
        "stream_id": stream_id,
        "profile": profile,
        "key_id": key_id,
        "trap_url": trap_url,
        "service": service,
        "credential": credential,
    }
    write_secret(path, json.dumps(body, sort_keys=True).encode())
    return path
