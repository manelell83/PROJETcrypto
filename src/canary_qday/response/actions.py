"""Response actions. Dry-run by default; every action is idempotent and logged.

In dry-run, actions only describe what they would do: the registry and the lab
policy file are not opened for writing (SEC-002).
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from canary_qday.common import labpolicy
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.store import SecretRow, Store
from canary_qday.response.exposure import Exposure
from canary_qday.response.policy import profiles_to_disable

_log = get_logger("response.actions")


@dataclass
class Context:
    """Everything an action needs."""

    incident_id: str
    profile: str
    key_id: str
    params_id: str
    src_ip: str
    exposure: Exposure
    store: Store
    policy_path: Path
    notify_path: Path
    dry_run: bool = True
    now: float = field(default_factory=time.time)


def _new_secret_value(kind: str) -> str:
    return f"FAKE-{kind}-{secrets.token_urlsafe(18)}"


def classify(ctx: Context) -> dict[str, Any]:
    """Classify the incident from the exposure sets."""
    return {
        "classification": "confirmed-decrypt-and-use",
        "key_level_streams": len(ctx.exposure.key_level),
        "algorithmic_streams": len(ctx.exposure.algorithmic),
    }


def switch_profile(ctx: Context) -> dict[str, Any]:
    """Remove the broken profile (and weaker ones) from the allow-list, revoke the key, bump epochs."""
    pol = labpolicy.load(ctx.policy_path)
    disable = profiles_to_disable(ctx.profile)
    new_allowed = [p for p in pol.allowed_profiles if p not in disable]
    changed = (
        new_allowed != pol.allowed_profiles or ctx.key_id not in pol.revoked_key_ids
    )
    detail: dict[str, Any] = {"disable": disable, "allowed_after": new_allowed,
                              "revoke_key_id": ctx.key_id}
    if not changed:
        return {**detail, "noop": True}
    if not ctx.dry_run:
        pol.allowed_profiles = new_allowed
        pol.revoked_key_ids = sorted({*pol.revoked_key_ids, ctx.key_id})
        for p in disable:
            pol.epochs[p] = pol.epochs.get(p, 1) + 1
        labpolicy.save(ctx.policy_path, pol)
    return detail


def rotate_secrets(ctx: Context) -> dict[str, Any]:
    """Revoke and replace every exposed active secret, highest priority first."""
    rotated: list[str] = []
    for s in ctx.exposure.to_rotate:
        if ctx.dry_run:
            rotated.append(s.secret_id)
            continue
        new = SecretRow(
            str(uuid.uuid4()), s.stream_id, s.service, s.kind, s.sensitivity,
            ctx.now, s.expires_at, "active", None,
        )
        if ctx.store.rotate_secret(s.secret_id, new, _new_secret_value(s.kind)):
            rotated.append(s.secret_id)
    return {
        "rotated": rotated,
        "skipped_expired": list(ctx.exposure.skipped_expired),
        "already_inactive": list(ctx.exposure.already_inactive),
        **({"noop": True} if not rotated else {}),
    }


def notify_analyst(ctx: Context) -> dict[str, Any]:
    """Append a notification line for the analyst queue (lab stand-in for e-mail/chat)."""
    line = {"ts": ctx.now, "incident_id": ctx.incident_id, "profile": ctx.profile,
            "message": "toy-profile break detected; automatic containment applied"}
    if not ctx.dry_run:
        ctx.notify_path.parent.mkdir(parents=True, exist_ok=True)
        with ctx.notify_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
    return {"queued": True}


def firewall_block(ctx: Context) -> dict[str, Any]:
    """Block the source IP that used the trap (lab: proxy deny-list)."""
    pol = labpolicy.load(ctx.policy_path)
    if ctx.src_ip in pol.blocked_ips:
        return {"ip": ctx.src_ip, "noop": True}
    if not ctx.dry_run:
        pol.blocked_ips = sorted({*pol.blocked_ips, ctx.src_ip})
        labpolicy.save(ctx.policy_path, pol)
    return {"ip": ctx.src_ip}


def service_stop(ctx: Context) -> dict[str, Any]:
    """Stop the services that appeared in key-level exposed streams."""
    services = sorted({svc for s in ctx.store.streams(key_id=ctx.key_id) for svc in s.services})
    pol = labpolicy.load(ctx.policy_path)
    new = sorted(set(pol.stopped_services) | set(services))
    if new == sorted(pol.stopped_services):
        return {"services": services, "noop": True}
    if not ctx.dry_run:
        pol.stopped_services = new
        labpolicy.save(ctx.policy_path, pol)
    return {"services": services}


def create_incident(ctx: Context) -> dict[str, Any]:
    """The incident record itself is created by the engine; this documents it."""
    return {"incident_id": ctx.incident_id}


ACTIONS = {
    "create_incident": create_incident,
    "classify": classify,
    "switch_profile": switch_profile,
    "rotate_secrets": rotate_secrets,
    "notify_analyst": notify_analyst,
    "firewall_block": firewall_block,
    "service_stop": service_stop,
}


def run(kind: str, ctx: Context) -> dict[str, Any]:
    """Execute one action and log it (without secrets)."""
    detail = ACTIONS[kind](ctx)
    log_event(_log, "action", incident_id=ctx.incident_id, action=kind, dry_run=ctx.dry_run,
              noop=bool(detail.get("noop")))
    return detail
