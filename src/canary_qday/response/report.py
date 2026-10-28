"""Incident report in JSON and Markdown: what is irrecoverable vs what was neutralised."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _iso(ts: float | None) -> str:
    return "n/a" if ts is None else datetime.fromtimestamp(ts, UTC).isoformat()


def build(
    *,
    incident_id: str,
    alert: dict[str, Any],
    classification: str,
    dry_run: bool,
    exposure: dict[str, Any],
    actions: list[dict[str, Any]],
    pending_approval: list[str],
    created_at: float,
) -> dict[str, Any]:
    """Assemble the JSON report."""
    ev = alert["event"]
    done = [a for a in actions if a["status"] in ("done", "planned")]
    rotated: list[str] = next(
        (a["detail"].get("rotated", []) for a in done if a["kind"] == "rotate_secrets"), []
    )
    switched = any(a["kind"] == "switch_profile" for a in done)
    return {
        "incident_id": incident_id,
        "created_at": _iso(created_at),
        "dry_run": dry_run,
        "alert_id": alert["alert_id"],
        "classification": classification,
        "profile": ev["profile"],
        "params_id": ev["params_id"],
        "key_id": ev["key_id"],
        "epoch": ev["epoch"],
        "trigger": {
            "stream_id": ev["stream_id"],
            "token_id": ev["token_id"],
            "src_ip": ev["src_ip"],
            "ts": ev["ts"],
        },
        "window": {"start": _iso(exposure["window_start"]), "end": _iso(exposure["window_end"])},
        "exposed_streams": {
            "key_level": exposure["key_level"],
            "algorithmic": exposure["algorithmic"],
        },
        "actions": [
            {"kind": a["kind"], "mode": a["mode"], "status": a["status"], "detail": a["detail"]}
            for a in actions
        ],
        "pending_approval": pending_approval,
        "irrecoverable": [
            f"Payloads of {len(exposure['key_level'])} stream(s) encrypted to key {ev['key_id']} "
            "must be considered disclosed if they were captured; this cannot be undone.",
            f"{len(exposure['algorithmic'])} stream(s) share params {ev['params_id']}: "
            "an attacker can repeat the attack on their keys (algorithmic exposure).",
            "Passive harvesting of other traffic is not detectable by the canary.",
        ],
        "neutralised": [
            f"{len(rotated)} exposed secret(s) "
            + ("would be" if dry_run else "were")
            + " revoked and replaced.",
            (
                "Future traffic on the broken profile "
                + ("would be" if dry_run else "is")
                + " refused (profile switch, key revoked)."
            )
            if switched
            else "No profile switch was executed automatically.",
        ],
    }


def to_markdown(r: dict[str, Any]) -> str:
    """Human-readable rendering of the report."""
    lines = [
        f"# Incident {r['incident_id']}",
        "",
        f"- Created: {r['created_at']}"
        + ("  **(DRY-RUN: nothing was changed)**" if r["dry_run"] else ""),
        f"- Classification: {r['classification']}",
        f"- Profile / params / key: {r['profile']} / {r['params_id']} / {r['key_id']} "
        f"(epoch {r['epoch']})",
        f"- Trigger: stream {r['trigger']['stream_id']}, token_id {r['trigger']['token_id']}, "
        f"from {r['trigger']['src_ip']} at {r['trigger']['ts']}",
        f"- Exposure window: {r['window']['start']} -> {r['window']['end']}",
        f"- Key-level exposed streams: {len(r['exposed_streams']['key_level'])}",
        f"- Algorithmic exposed streams: {len(r['exposed_streams']['algorithmic'])}",
        "",
        "## Actions",
        "",
        "| Action | Mode | Status |",
        "|---|---|---|",
        *[f"| {a['kind']} | {a['mode']} | {a['status']} |" for a in r["actions"]],
        "",
        "Pending human approval: " + (", ".join(r["pending_approval"]) or "none"),
        "",
        "## Irrecoverable",
        "",
        *[f"- {x}" for x in r["irrecoverable"]],
        "",
        "## Neutralised",
        "",
        *[f"- {x}" for x in r["neutralised"]],
        "",
    ]
    return "\n".join(lines)


def write(reports_dir: Path, r: dict[str, Any]) -> tuple[Path, Path]:
    """Write <incident>.json and <incident>.md."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    jp = reports_dir / f"{r['incident_id']}.json"
    mp = reports_dir / f"{r['incident_id']}.md"
    jp.write_text(json.dumps(r, sort_keys=True, indent=2), encoding="utf-8")
    mp.write_text(to_markdown(r), encoding="utf-8")
    return jp, mp
