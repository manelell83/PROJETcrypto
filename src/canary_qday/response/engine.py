"""Response engine: alert -> policy -> exposure -> actions -> report."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from canary_qday.common.errors import NotFoundError, PolicyError, ReplayError
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.store import Store
from canary_qday.response import actions as act
from canary_qday.response import exposure as exp
from canary_qday.response import policy, report
from canary_qday.response.state import ResponseState
from canary_qday.siem.schemas import Alert

RATE_WINDOW_S = 300.0  # at most one containment run per params_id per window (SEC-007)
RATE_LIMITED = frozenset({"switch_profile", "rotate_secrets", "notify_analyst"})
_log = get_logger("response.engine")


@dataclass
class EngineConfig:
    """Paths and switches."""

    registry_db: Path
    response_db: Path
    policy_file: Path
    reports_dir: Path
    notify_file: Path
    apply: bool = False  # dry-run unless True
    auto_lab: bool = False


class ResponseEngine:
    """Stateless orchestration over the registry and the response state DB."""

    def __init__(self, cfg: EngineConfig) -> None:
        self.cfg = cfg
        self.store = Store(cfg.registry_db)
        self.state = ResponseState(cfg.response_db)

    def _ctx(self, incident_id: str, alert: Alert, ex: exp.Exposure, now: float) -> act.Context:
        ev = alert.event
        return act.Context(
            incident_id=incident_id, profile=ev.profile, key_id=ev.key_id,
            params_id=ev.params_id, src_ip=ev.src_ip, exposure=ex, store=self.store,
            policy_path=self.cfg.policy_file, notify_path=self.cfg.notify_file,
            dry_run=not self.cfg.apply, now=now,
        )

    def _run(self, incident_id: str, kind: str, mode: str, ctx: act.Context) -> None:
        key = f"{incident_id}:{kind}"
        if kind in RATE_LIMITED:
            covered = self.state.rate_check(
                f"{kind}:{ctx.params_id}:{'dry' if ctx.dry_run else 'apply'}",
                ctx.now, RATE_WINDOW_S, incident_id,
            )
            if covered is not None and covered != incident_id:
                self.state.record_action(key, incident_id, kind, mode, "rate_limited",
                                         {"covered_by": covered}, ctx.now)
                return
        detail = act.run(kind, ctx)
        status = "noop" if detail.get("noop") else ("planned" if ctx.dry_run else "done")
        self.state.record_action(key, incident_id, kind, mode, status, detail, ctx.now)

    def handle(self, alert: Alert, now: float | None = None) -> dict[str, Any]:
        """Process one authenticated alert. Raises ReplayError for a duplicate alert_id."""
        now = time.time() if now is None else now
        ev = alert.event
        incident_id = str(uuid.uuid4())
        if not self.state.create_incident(incident_id, alert.alert_id, now, ev.profile,
                                          not self.cfg.apply):
            raise ReplayError("alert already processed")
        tok = self.store.token_by_id(ev.token_id, ev.stream_id)
        stream = self.store.stream(ev.stream_id)
        consistent = (
            stream is not None and stream.key_id == ev.key_id
            and stream.profile == ev.profile and stream.params_id == ev.params_id
        )
        token_valid = tok is not None and consistent
        allowlisted = bool(tok and tok[0])
        decision = policy.decide(ev.profile, token_valid=token_valid, allowlisted=allowlisted,
                                 auto_lab=self.cfg.auto_lab)
        ex = exp.compute(self.store, key_id=ev.key_id, params_id=ev.params_id, now=now)
        ctx = self._ctx(incident_id, alert, ex, now)
        for kind in decision.auto:
            if kind != "report":
                self._run(incident_id, kind, "auto", ctx)
        for kind in decision.approval:
            self.state.record_action(f"{incident_id}:{kind}", incident_id, kind, "approval",
                                     "pending", {}, now)
        if not token_valid:
            classification = "unverified-token"
        elif allowlisted:
            classification = "allow-listed (benign test)"
        else:
            classification = "confirmed-decrypt-and-use"
        rep = self._report(incident_id, alert, classification, ex, now)
        log_event(_log, "incident", incident_id=incident_id, profile=ev.profile,
                  classification=classification, dry_run=not self.cfg.apply)
        return rep

    def _report(self, incident_id: str, alert: Alert, classification: str,
                ex: exp.Exposure, created_at: float) -> dict[str, Any]:
        actions = self.state.actions(incident_id)
        pending = [a["kind"] for a in actions if a["status"] == "pending"]
        rep = report.build(
            incident_id=incident_id, alert=alert.model_dump(), classification=classification,
            dry_run=not self.cfg.apply,
            exposure={"key_level": list(ex.key_level), "algorithmic": list(ex.algorithmic),
                      "window_start": ex.window_start, "window_end": ex.window_end},
            actions=actions, pending_approval=pending, created_at=created_at,
        )
        rep["alert"] = alert.model_dump()
        report.write(self.cfg.reports_dir, rep)
        self.state.set_report(incident_id, "awaiting-approval" if pending else "contained", rep)
        return rep

    def approve(self, incident_id: str, kinds: list[str], now: float | None = None) -> dict[str, Any]:
        """Run actions a human approved. Only pending actions of this incident can be approved."""
        now = time.time() if now is None else now
        inc = self.state.incident(incident_id)
        if inc is None or inc["report"] is None:
            raise NotFoundError("unknown incident")
        pending = {a["kind"] for a in self.state.actions(incident_id) if a["status"] == "pending"}
        if not kinds or not set(kinds) <= pending:
            raise PolicyError("action not pending for this incident")
        alert = Alert.model_validate(inc["report"]["alert"])
        ex = exp.compute(self.store, key_id=alert.event.key_id,
                         params_id=alert.event.params_id, now=now)
        ctx = self._ctx(incident_id, alert, ex, now)
        for kind in kinds:
            detail = act.run(kind, ctx)
            status = "noop" if detail.get("noop") else ("planned" if ctx.dry_run else "done")
            self.state.record_action(f"{incident_id}:{kind}", incident_id, kind, "approved",
                                     status, detail, now)
        return self._report(incident_id, alert, inc["report"]["classification"], ex,
                            inc["created_at"])
