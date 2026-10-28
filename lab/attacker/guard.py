"""Guard for every lab-attacker entry point (SEC-003). Call `require_lab()` first.

Refuses to run unless:
  * CQ_LAB=1 is set (explicit opt-in, lab machines only);
  * the target profile is a toy profile (RED / ORANGE), never GREEN or a FIPS 203 set;
  * every target host is a lab host (loopback or a compose service name).

M8 (a real cryptanalytic attacker) is NOT delivered; see docs/m8-status.md.
This guard protects the simulated scenario in lab/scenario/ and any future module.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

from canary_qday.kem.profiles import TOY_PROFILES, is_toy, params_for

LAB_HOSTS = frozenset(
    {"localhost", "canary", "proxy", "mock-siem", "response", "backend", "generator"}
)


class GuardError(PermissionError):
    """The requested action is outside the lab's allowed scope."""


def require_lab_env() -> None:
    """Refuse unless the operator explicitly enabled lab mode."""
    if os.environ.get("CQ_LAB") != "1":
        raise GuardError("lab mode not enabled (set CQ_LAB=1 on a lab machine)")


def require_toy_profile(profile: str) -> None:
    """Refuse GREEN, standard parameter sets and unknown profiles."""
    if profile not in TOY_PROFILES:
        raise GuardError(f"profile {profile!r} is not a toy profile")
    if not is_toy(params_for(profile)):
        raise GuardError("parameters are not toy parameters")


def require_lab_host(target: str) -> None:
    """Accept loopback addresses, the compose service names and CQ_LAB_HOSTS entries."""
    host = urlsplit(target).hostname if "://" in target else target
    if not host:
        raise GuardError("no host")
    extra = {h.strip() for h in os.environ.get("CQ_LAB_HOSTS", "").split(",") if h.strip()}
    if host in LAB_HOSTS or host in extra:
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise GuardError(f"host {host!r} is not a lab host")


def require_lab(profile: str, *targets: str) -> None:
    """All checks, in order. Every lab-attacker entry point calls this first."""
    require_lab_env()
    require_toy_profile(profile)
    for t in targets:
        require_lab_host(t)
