"""Lab enforcement configuration shared by the proxy (reader) and the response engine (writer).

Stored as a small JSON file written atomically. The proxy re-reads it when its
mtime changes, so a profile switch takes effect on the next connection.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class LabPolicy:
    """Allowed profiles, current epoch per profile, revocations and blocks."""

    allowed_profiles: list[str] = field(default_factory=lambda: ["RED", "ORANGE", "GREEN"])
    epochs: dict[str, int] = field(default_factory=lambda: {"RED": 1, "ORANGE": 1, "GREEN": 1})
    revoked_key_ids: list[str] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)
    stopped_services: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        """Canonical JSON (sorted keys) so identical policies are byte-identical."""
        return json.dumps(asdict(self), sort_keys=True, indent=2) + "\n"


def load(path: Path) -> LabPolicy:
    """Load the policy, or the default policy if the file does not exist."""
    if not path.exists():
        return LabPolicy()
    data = json.loads(path.read_text(encoding="utf-8"))
    return LabPolicy(**data)


def save(path: Path, policy: LabPolicy) -> None:
    """Atomically replace the policy file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(policy.to_json(), encoding="utf-8")
    os.replace(tmp, path)
