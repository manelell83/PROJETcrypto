"""Pedagogical SIMULATED attacker scenario (stand-in for the undelivered M8).

!!! No cryptanalysis is performed. The "break" step reads a lab-oracle record
written by the generator (CQ_LAB_SIM=1). This scenario demonstrates detection
and response, not an attack on ML-KEM, toy Kyber or X-Wing. See docs/m8-status.md.

Steps (each timestamped in the summary):
  0  lab up (response engine in DRY-RUN), traffic RED x2, ORANGE x1, GREEN x1
  1  passive observation: only public handshake metadata is visible; no alert
  2  simulated break: guard, then lab-oracle record of a RED stream
  3  credential reuse through the proxy (attacker's own channel) -> accepted
  4a trap use -> canary -> mock SIEM -> signed webhook -> response (DRY-RUN):
     report written, registry and lab policy byte-identical
  C  controls: unknown token (identical response, no alert), forged alert (401),
     replayed alert (409), guard refuses GREEN
  4b restart response engine with --apply, trap of the second RED stream
  5  observe containment: RED removed, key revoked, secrets rotated
  6  retry: stolen credential refused, new RED stream refused, GREEN still works

Run: python tools/run.py scenario     (or: make demo)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from canary_qday.channel import framing
from canary_qday.channel import handshake as hs
from canary_qday.common import labpolicy
from canary_qday.common.config import Settings, read_secret
from canary_qday.common.errors import CanaryError
from canary_qday.common.redact import token_id
from canary_qday.common.sig import sign_hmac
from canary_qday.common.store import Store
from canary_qday.traffic import generator
from canary_qday.traffic.lab_oracle import BANNER
from lab.attacker.guard import GuardError, require_lab, require_lab_host
from tools import lab

UA = "canary-qday-simulated-attacker/1.0"


@dataclass
class Summary:
    """Timestamped log of steps and checks."""

    started: float = field(default_factory=time.time)
    steps: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)

    def step(self, sid: str, title: str, **info: Any) -> None:
        """Record and print a step."""
        t = round(time.time() - self.started, 3)
        self.steps.append({"step": sid, "title": title, "t_s": t, **info})
        print(f"\n[{t:7.2f}s] STEP {sid}: {title}")
        for k, v in info.items():
            print(f"           {k}: {v}")

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        """Record and print a pass/fail check."""
        self.checks.append({"check": name, "ok": ok, "detail": detail})
        print(f"           [{'PASS' if ok else 'FAIL'}] {name}" + (f" ({detail})" if detail else ""))

    @property
    def ok(self) -> bool:
        """True if every check passed."""
        return all(c["ok"] for c in self.checks)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "absent"


def _settings(data_dir: Path, ports: lab.Ports) -> Settings:
    return Settings(
        data_dir=data_dir, secrets_dir=data_dir / "secrets", registry_db=data_dir / "registry.db",
        response_db=data_dir / "response.db", policy_file=data_dir / "policy.json",
        reports_dir=data_dir / "reports", canary_base_url=f"http://127.0.0.1:{ports.canary}",
        proxy_host="127.0.0.1", proxy_port=ports.proxy, siem_sink="hec",
        hec_url=f"http://127.0.0.1:{ports.hec}", response_url=f"http://127.0.0.1:{ports.response}",
    )


async def _use_credential(s: Settings, service: str, credential: str) -> int:
    """Attacker opens its OWN channel (GREEN, a normal client) and presents a credential."""
    reader, writer = await asyncio.open_connection(s.proxy_host, s.proxy_port)
    try:
        f = hs.key_request("GREEN")
        writer.write(framing.encode(f.type, f.payload))
        kr = await framing.read_frame(reader)
        prof, epoch, _kid, ek = hs.parse_key_response(kr)
        hello, sess = hs.client_hello(prof, epoch, ek, uuid.uuid4().bytes)
        writer.write(framing.encode(hello.type, hello.payload))
        req = sess.seal(json.dumps({"service": service, "action": "export",
                                    "credential": credential}).encode())
        writer.write(framing.encode(req.type, req.payload))
        resp = await framing.read_frame(reader)
        return int(json.loads(sess.open(resp))["status"])
    finally:
        writer.close()


def _wait_report(reports: Path, stream_id: str, timeout: float = 20.0) -> dict[str, Any] | None:
    end = time.time() + timeout
    while time.time() < end:
        for p in sorted(reports.glob("*.json")) if reports.exists() else []:
            r = json.loads(p.read_text(encoding="utf-8"))
            if r.get("trigger", {}).get("stream_id") == stream_id:
                return dict(r)
        time.sleep(0.2)
    return None


def _alert_count(ports: lab.Ports) -> int:
    return len(httpx.get(f"http://127.0.0.1:{ports.hec}/alerts", timeout=5).json())


def _load_oracle(data_dir: Path, stream_id: str) -> dict[str, Any]:
    rec = json.loads(read_secret(data_dir / "lab-oracle" / f"{stream_id}.json"))
    assert rec["banner"] == BANNER
    return dict(rec)


def run(data_dir: Path, ports: lab.Ports, *, keep: bool = False) -> Summary:
    """Run the whole scenario on a fresh data directory."""
    import os

    sm = Summary()
    if data_dir.exists():
        lab.down(data_dir)
        shutil.rmtree(data_dir)
    os.environ.update(CQ_LAB="1", CQ_LAB_SIM="1")
    s = _settings(data_dir, ports)
    try:
        # -- 0. lab + traffic ------------------------------------------------
        lab.up(data_dir, ports, apply=False)
        store = Store(s.registry_db)
        streams: dict[str, list[generator.StreamResult]] = {}
        for prof, n in (("RED", 2), ("ORANGE", 1), ("GREEN", 1)):
            streams[prof] = [asyncio.run(generator.run_stream(store, s, prof)) for _ in range(n)]
        sm.step("0", "lab up (response engine DRY-RUN) and synthetic traffic generated",
                streams={p: len(v) for p, v in streams.items()})
        sm.check("all generated requests accepted (HTTP 200 from backends)",
                 all(c == 200 for v in streams.values() for r in v for c in r.responses))

        # -- 1. passive observation -------------------------------------------
        time.sleep(0.5)
        events = [json.loads(ln) for ln in
                  (data_dir / "siem" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        hand = [e["event"] for e in events if e.get("event", {}).get("event") == "handshake"]
        visible = sorted({(e["profile"], e["key_id"]) for e in hand})
        sm.step("1", "passive observation: public handshake metadata only",
                visible_profile_key_ids=visible,
                note="captured ciphertexts cannot be read without breaking the KEM; "
                     "passive harvesting raises no alert (limitation 1)")
        sm.check("no alert after passive observation", _alert_count(ports) == 0)

        # -- 2. simulated break ------------------------------------------------
        red1, red2 = streams["RED"]
        require_lab("RED", s.canary_base_url, f"{s.proxy_host}:{s.proxy_port}".split(":")[0])
        oracle1 = _load_oracle(data_dir, red1.stream_id)
        sm.step("2", BANNER, stream_id=red1.stream_id, profile=oracle1["profile"],
                key_id=oracle1["key_id"],
                learned="trap URL + one synthetic credential (values not printed)")

        # -- 3. credential reuse -----------------------------------------------
        code = asyncio.run(_use_credential(s, oracle1["service"], oracle1["credential"]))
        sm.step("3", "stolen synthetic credential reused through the proxy", http_status=code)
        sm.check("credential accepted before any response", code == 200)

        # -- 4a. trap use, DRY-RUN ---------------------------------------------
        reg_before, pol_before = _sha(s.registry_db), _sha(s.policy_file)
        require_lab_host(oracle1["trap_url"])
        r = httpx.get(oracle1["trap_url"], headers={"User-Agent": UA}, timeout=5)
        valid_resp = (r.status_code, r.text, r.headers.get("content-type"))
        rep = _wait_report(s.reports_dir, red1.stream_id)
        sm.step("4a", "trap used -> canary -> mock SIEM -> signed webhook -> response (DRY-RUN)",
                canary_http=r.status_code,
                incident=rep and rep["incident_id"],
                actions=rep and [(a["kind"], a["status"]) for a in rep["actions"]],
                pending_approval=rep and rep["pending_approval"])
        sm.check("incident report produced", rep is not None)
        sm.check("report marked dry_run", bool(rep and rep["dry_run"]))
        sm.check("registry byte-identical after dry-run", _sha(s.registry_db) == reg_before)
        sm.check("lab policy byte-identical after dry-run", _sha(s.policy_file) == pol_before)
        sm.check("heavy actions wait for approval",
                 bool(rep and set(rep["pending_approval"]) >= {"firewall_block", "service_stop"}))

        # -- C. controls ---------------------------------------------------------
        n_alerts = _alert_count(ports)
        bogus = httpx.get(f"{s.canary_base_url}/t/{'0' * 32}", headers={"User-Agent": UA},
                          timeout=5)
        time.sleep(1.0)
        sm.step("C", "controls (negative tests)")
        sm.check("unknown token gets an identical response",
                 (bogus.status_code, bogus.text, bogus.headers.get("content-type")) == valid_resp)
        sm.check("unknown token raises no alert", _alert_count(ports) == n_alerts)
        secret = read_secret(data_dir / "secrets" / "webhook_secret.txt")
        tok = oracle1["trap_url"].rsplit("/", 1)[1]
        alert = {
            "alert_id": str(uuid.uuid4()), "ts": datetime.now(UTC).isoformat(),
            "rule": "control_replay", "severity": "high",
            "event": {"event": "trap_triggered", "event_id": str(uuid.uuid4()),
                      "ts": datetime.now(UTC).isoformat(), "token_id": token_id(tok),
                      "stream_id": red1.stream_id, "profile": "RED", "params_id": "toy-n64-k1",
                      "key_id": red1.key_id, "epoch": 1, "src_ip": "127.0.0.1",
                      "user_agent": UA},
        }
        body = json.dumps(alert).encode()
        url = f"{s.response_url}/v1/alerts"
        ts = str(int(time.time()))
        forged = httpx.post(url, content=body, headers={"X-Timestamp": ts,
                                                        "X-Signature": "0" * 64}, timeout=10)
        sm.check("forged alert rejected (401 E_SIG_INVALID)", forged.status_code == 401)
        hdr = {"X-Timestamp": ts, "X-Signature": sign_hmac(secret, ts, body)}
        first = httpx.post(url, content=body, headers=hdr, timeout=10)
        again = httpx.post(url, content=body, headers=hdr, timeout=10)
        sm.check("replayed alert rejected (409 E_REPLAY)",
                 first.status_code == 202 and again.status_code == 409,
                 f"{first.status_code} then {again.status_code}")
        try:
            require_lab("GREEN")
            refused = False
        except GuardError:
            refused = True
        sm.check("guard refuses GREEN (no attack path on X-Wing / ML-KEM-768)", refused)

        # -- 4b. restart response engine with --apply ----------------------------
        lab.stop_service("response", data_dir)
        lab.start_service("response", data_dir, ports, apply=True)
        oracle2 = _load_oracle(data_dir, red2.stream_id)
        require_lab_host(oracle2["trap_url"])
        httpx.get(oracle2["trap_url"], headers={"User-Agent": UA}, timeout=5)
        rep2 = _wait_report(s.reports_dir, red2.stream_id)
        sm.step("4b", "response engine restarted with --apply; second RED trap used",
                incident=rep2 and rep2["incident_id"],
                actions=rep2 and [(a["kind"], a["status"]) for a in rep2["actions"]])
        sm.check("applied report produced", bool(rep2 and not rep2["dry_run"]))

        # -- 5. containment -------------------------------------------------------
        pol = labpolicy.load(s.policy_file)
        rotated = (next((a["detail"]["rotated"] for a in rep2["actions"]
                         if a["kind"] == "rotate_secrets"), []) if rep2 else [])
        sm.step("5", "containment observed", allowed_profiles=pol.allowed_profiles,
                revoked_key_ids=pol.revoked_key_ids, epochs=pol.epochs,
                rotated_secrets=len(rotated),
                key_level_streams=rep2 and len(rep2["exposed_streams"]["key_level"]),
                algorithmic_streams=rep2 and len(rep2["exposed_streams"]["algorithmic"]))
        sm.check("RED removed from allow-list", "RED" not in pol.allowed_profiles)
        sm.check("ORANGE and GREEN still allowed",
                 {"ORANGE", "GREEN"} <= set(pol.allowed_profiles))
        sm.check("RED key revoked", red1.key_id in pol.revoked_key_ids)
        sm.check("exposed secrets rotated", len(rotated) > 0)

        # -- 6. retry -------------------------------------------------------------
        code2 = asyncio.run(_use_credential(s, oracle1["service"], oracle1["credential"]))
        try:
            asyncio.run(generator.run_stream(store, s, "RED"))
            red_refused, why = False, "accepted"
        except (CanaryError, ConnectionError) as e:
            red_refused, why = True, str(e)
        green = asyncio.run(generator.run_stream(store, s, "GREEN"))
        sm.step("6", "attacker retries; legitimate GREEN traffic continues",
                stolen_credential_http=code2, new_red_stream=why, green_codes=green.responses)
        sm.check("stolen credential now refused (401)", code2 == 401)
        sm.check("new RED stream refused by proxy", red_refused)
        sm.check("GREEN traffic still served", all(c == 200 for c in green.responses))
    finally:
        out = data_dir / "scenario-summary.json"
        if data_dir.exists():
            out.write_text(json.dumps({"ok": sm.ok, "steps": sm.steps, "checks": sm.checks},
                                      indent=2, default=str), encoding="utf-8")
        if not keep:
            lab.down(data_dir)
    passed = sum(c["ok"] for c in sm.checks)
    print(f"\nRESULT: {passed}/{len(sm.checks)} checks passed -> {'OK' if sm.ok else 'FAILED'}")
    print(f"Summary: {data_dir / 'scenario-summary.json'}")
    return sm


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Simulated attacker scenario (no cryptanalysis).")
    ap.add_argument("--data-dir", default="var/demo")
    ap.add_argument("--port-offset", type=int, default=0)
    ap.add_argument("--keep", action="store_true", help="leave the lab running afterwards")
    a = ap.parse_args()
    result = run(Path(a.data_dir).resolve(), lab.Ports.offset(a.port_offset), keep=a.keep)
    sys.exit(0 if result.ok else 1)
