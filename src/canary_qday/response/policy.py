"""Response policy matrix (spec 7.4).

| Profile | Automatic                                         | Needs approval            |
|---------|---------------------------------------------------|---------------------------|
| RED     | classify, switch_profile, rotate_secrets, report  | firewall_block, service_stop |
| ORANGE  | same + notify_analyst                             | firewall_block, service_stop |
| GREEN   | create_incident, report (skeleton)                | everything else           |

Automatic actions for RED/ORANGE only run when the trap token is valid and not
allow-listed; otherwise every action waits for a human. Heavy actions become
automatic only with auto_lab=True, and never for GREEN.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Mode(StrEnum):
    """How an action may run."""

    AUTO = "auto"
    APPROVAL = "approval"


HEAVY = frozenset({"firewall_block", "service_stop"})
ALL_ACTIONS = (
    "create_incident",
    "classify",
    "switch_profile",
    "rotate_secrets",
    "notify_analyst",
    "firewall_block",
    "service_stop",
    "report",
)

_MATRIX: dict[str, dict[str, Mode]] = {
    "RED": {
        "create_incident": Mode.AUTO,
        "classify": Mode.AUTO,
        "switch_profile": Mode.AUTO,
        "rotate_secrets": Mode.AUTO,
        "report": Mode.AUTO,
        "firewall_block": Mode.APPROVAL,
        "service_stop": Mode.APPROVAL,
    },
    "ORANGE": {
        "create_incident": Mode.AUTO,
        "classify": Mode.AUTO,
        "switch_profile": Mode.AUTO,
        "rotate_secrets": Mode.AUTO,
        "notify_analyst": Mode.AUTO,
        "report": Mode.AUTO,
        "firewall_block": Mode.APPROVAL,
        "service_stop": Mode.APPROVAL,
    },
    "GREEN": {
        "create_incident": Mode.AUTO,
        "report": Mode.AUTO,
        "classify": Mode.APPROVAL,
        "switch_profile": Mode.APPROVAL,
        "rotate_secrets": Mode.APPROVAL,
        "notify_analyst": Mode.APPROVAL,
        "firewall_block": Mode.APPROVAL,
        "service_stop": Mode.APPROVAL,
    },
}

ALWAYS_AUTO = frozenset({"create_incident", "report"})


@dataclass(frozen=True)
class Decision:
    """Planned actions split by mode."""

    auto: tuple[str, ...]
    approval: tuple[str, ...]


def decide(profile: str, *, token_valid: bool, allowlisted: bool, auto_lab: bool) -> Decision:
    """Apply the matrix to one alert."""
    if profile not in _MATRIX:
        raise ValueError("unknown profile")
    row = _MATRIX[profile]
    trusted = token_valid and not allowlisted
    auto: list[str] = []
    approval: list[str] = []
    for action in ALL_ACTIONS:
        mode = row.get(action)
        if mode is None:
            continue
        if action not in ALWAYS_AUTO and not trusted:
            mode = Mode.APPROVAL
        if auto_lab and action in HEAVY and profile != "GREEN" and trusted:
            mode = Mode.AUTO
        (auto if mode is Mode.AUTO else approval).append(action)
    return Decision(tuple(auto), tuple(approval))


PROFILE_STRENGTH = {"RED": 1, "ORANGE": 2, "GREEN": 3}


def profiles_to_disable(broken: str) -> list[str]:
    """A broken profile and every weaker one are removed from the allow-list."""
    level = PROFILE_STRENGTH[broken]
    return [p for p, s in PROFILE_STRENGTH.items() if s <= level]
