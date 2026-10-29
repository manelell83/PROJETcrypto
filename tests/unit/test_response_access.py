"""engine.handle_access: incident + report only, strictly separate from the trap path.

Proves no registry/policy mutation, no rotation/revocation/switch/containment, dry-run,
and replay protection by alert_id -- in both dry-run and apply modes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from canary_qday.common import labpolicy
from canary_qday.common.errors import ReplayError
from canary_qday.common.store import Store
from canary_qday.response.engine import ResponseEngine
from canary_qday.siem.schemas import AccessAlert, HandshakeEvent


def _access_alert(rule: str = "unauthorized_key_use", key_id: str = "a" * 16) -> AccessAlert:
    now = datetime.now(UTC).isoformat()
    return AccessAlert(
        alert_id=str(uuid.uuid4()), ts=now, rule=rule, severity="high",
        event=HandshakeEvent(
            event_id=str(uuid.uuid4()), ts=now, stream_id=str(uuid.uuid4()), profile="RED",
            key_id=key_id, epoch=1, src_ip="10.0.0.66", outcome="refused", reason="revoked_key",
        ),
    )


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "absent"


@pytest.mark.parametrize("apply", [False, True])
def test_handle_access_incident_only_no_mutation(
    tmp_path: Path, store: Store, engine_factory: Callable[..., ResponseEngine], apply: bool
) -> None:
    labpolicy.save(tmp_path / "policy.json", labpolicy.LabPolicy())
    before = (_sha(store.path), _sha(tmp_path / "policy.json"))
    eng = engine_factory(apply=apply)
    rep = eng.handle_access(_access_alert())

    assert rep["classification"] == "unauthorized-access-attempt"
    assert rep["dry_run"] is (not apply)
    kinds = {a["kind"] for a in rep["actions"]}
    assert kinds == {"create_incident"}  # report is implicit, no other action
    # No containment action whatsoever, in either mode.
    assert not ({"rotate_secrets", "switch_profile", "firewall_block", "service_stop"} & kinds)
    # Registry and policy are byte-identical: no mutation.
    assert (_sha(store.path), _sha(tmp_path / "policy.json")) == before
    # A report file was written.
    assert (tmp_path / "reports" / f"{rep['incident_id']}.md").exists()
    md = (tmp_path / "reports" / f"{rep['incident_id']}.md").read_text(encoding="utf-8")
    assert "Access incident" in md and "offline decryption" in md


def test_handle_access_replay_rejected(
    store: Store, engine_factory: Callable[..., ResponseEngine]
) -> None:
    eng = engine_factory()
    alert = _access_alert()
    eng.handle_access(alert)
    with pytest.raises(ReplayError):
        eng.handle_access(alert)


def test_report_records_rule_and_src_ip(
    tmp_path: Path, store: Store, engine_factory: Callable[..., ResponseEngine]
) -> None:
    rep = engine_factory().handle_access(_access_alert(rule="refused_handshake_burst"))
    jp = json.loads((tmp_path / "reports" / f"{rep['incident_id']}.json").read_text("utf-8"))
    assert jp["rule"] == "refused_handshake_burst"
    assert jp["trigger"]["src_ip"] == "10.0.0.66" and jp["trigger"]["reason"] == "revoked_key"


def test_access_incident_in_same_table(
    store: Store, engine_factory: Callable[..., ResponseEngine]
) -> None:
    eng = engine_factory()
    rep = eng.handle_access(_access_alert())
    inc = eng.state.incident(rep["incident_id"])
    assert inc is not None and inc["status"] == "reported"
