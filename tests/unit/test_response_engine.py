"""FR-010/011/012, SEC-002, SEC-007: exposure, rotation, report, dry-run and rate limiting."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from canary_qday.common import labpolicy
from canary_qday.common.errors import NotFoundError, PolicyError, ReplayError
from canary_qday.common.store import Store
from canary_qday.response import exposure
from canary_qday.response.engine import ResponseEngine
from canary_qday.traffic.registry import IssuedStream
from tests.conftest import KEY_ORANGE, KEY_RED_A, make_alert

Reg = dict[str, IssuedStream]
Factory = Callable[..., ResponseEngine]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "absent"


def test_exposure_sets_match_ground_truth(store: Store, registry: Reg) -> None:
    ex = exposure.compute(store, key_id=KEY_RED_A, params_id="toy-n64-k1", now=time.time())
    assert set(ex.key_level) == {registry["red_a1"].stream_id, registry["red_a2"].stream_id}
    assert set(ex.algorithmic) == {
        registry[k].stream_id for k in ("red_a1", "red_a2", "red_b")
    }
    # 3 RED streams x 2 services x 2 kinds; key-level secrets come first.
    assert len(ex.to_rotate) == 12
    key_level = set(ex.key_level)
    first = [s.stream_id in key_level for s in ex.to_rotate]
    assert first == sorted(first, reverse=True)


def test_expired_secrets_are_skipped(store: Store, registry: Reg) -> None:
    far_future = time.time() + 8 * 24 * 3600
    ex = exposure.compute(store, key_id=KEY_RED_A, params_id="toy-n64-k1", now=far_future)
    assert not ex.to_rotate
    assert len(ex.skipped_expired) == 12


def test_dry_run_leaves_registry_and_policy_byte_identical(
    tmp_path: Path, store: Store, registry: Reg, engine_factory: Factory
) -> None:
    labpolicy.save(tmp_path / "policy.json", labpolicy.LabPolicy())
    before = (_sha(store.path), _sha(tmp_path / "policy.json"))
    rep = engine_factory().handle(make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A))
    assert rep["dry_run"] is True
    assert {a["status"] for a in rep["actions"] if a["mode"] == "auto"} == {"planned"}
    assert (_sha(store.path), _sha(tmp_path / "policy.json")) == before
    assert not (tmp_path / "notify.jsonl").exists()


def test_apply_contains_red(
    tmp_path: Path, store: Store, registry: Reg, engine_factory: Factory
) -> None:
    rep = engine_factory(apply=True).handle(
        make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A)
    )
    pol = labpolicy.load(tmp_path / "policy.json")
    assert "RED" not in pol.allowed_profiles and "GREEN" in pol.allowed_profiles
    assert KEY_RED_A in pol.revoked_key_ids
    assert pol.epochs["RED"] == 2
    rotated = next(a for a in rep["actions"] if a["kind"] == "rotate_secrets")
    assert len(rotated["detail"]["rotated"]) == 12
    assert set(rep["pending_approval"]) == {"firewall_block", "service_stop"}
    assert rep["classification"] == "confirmed-decrypt-and-use"
    md = (tmp_path / "reports" / f"{rep['incident_id']}.md").read_text(encoding="utf-8")
    assert "## Irrecoverable" in md and "## Neutralised" in md


def test_rotation_is_idempotent(store: Store, registry: Reg, engine_factory: Factory) -> None:
    eng = engine_factory(apply=True)
    eng.handle(make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A))
    ex = exposure.compute(store, key_id=KEY_RED_A, params_id="toy-n64-k1", now=time.time())
    old = [s for s in store.secrets_for_streams(list(ex.algorithmic)) if s.status == "revoked"]
    assert len(old) == 12
    new_row = old[0]
    assert store.rotate_secret(old[0].secret_id, new_row, "FAKE-x-again") is False


def test_orange_notifies_analyst(
    tmp_path: Path, registry: Reg, engine_factory: Factory
) -> None:
    rep = engine_factory(apply=True).handle(
        make_alert(registry["orange"], "ORANGE", "toy-n64-k2", KEY_ORANGE)
    )
    assert any(a["kind"] == "notify_analyst" and a["status"] == "done" for a in rep["actions"])
    line = json.loads((tmp_path / "notify.jsonl").read_text(encoding="utf-8"))
    assert line["incident_id"] == rep["incident_id"]
    assert "RED" not in labpolicy.load(tmp_path / "policy.json").allowed_profiles


def test_green_creates_incident_only(
    tmp_path: Path, registry: Reg, engine_factory: Factory
) -> None:
    rep = engine_factory(apply=True, auto_lab=True).handle(
        make_alert(registry["green"], "GREEN", "xwing-mlkem768-x25519", "dddddddddddddddd")
    )
    assert {a["kind"] for a in rep["actions"] if a["mode"] == "auto"} == {"create_incident"}
    assert not (tmp_path / "policy.json").exists()


def test_unknown_token_is_not_auto_contained(
    tmp_path: Path, registry: Reg, engine_factory: Factory
) -> None:
    alert = make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A, token="f" * 32)
    rep = engine_factory(apply=True).handle(alert)
    assert rep["classification"] == "unverified-token"
    assert "switch_profile" in rep["pending_approval"]
    assert not (tmp_path / "policy.json").exists()


def test_mismatched_key_id_is_not_trusted(registry: Reg, engine_factory: Factory) -> None:
    alert = make_alert(registry["red_a1"], "RED", "toy-n64-k1", "0123456789abcdef")
    assert engine_factory(apply=True).handle(alert)["classification"] == "unverified-token"


def test_duplicate_alert_is_replay(registry: Reg, engine_factory: Factory) -> None:
    eng = engine_factory()
    alert = make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A)
    eng.handle(alert)
    with pytest.raises(ReplayError):
        eng.handle(alert)


def test_burst_does_not_rotate_n_times(registry: Reg, engine_factory: Factory) -> None:
    eng = engine_factory(apply=True)
    reps = [eng.handle(make_alert(registry[k], "RED", "toy-n64-k1", KEY_RED_A))
            for k in ("red_a1", "red_a2", "red_a1")]
    statuses = [next(a["status"] for a in r["actions"] if a["kind"] == "rotate_secrets")
                for r in reps]
    assert statuses == ["done", "rate_limited", "rate_limited"]


def test_dry_run_does_not_consume_the_apply_rate_window(
    registry: Reg, engine_factory: Factory
) -> None:
    engine_factory().handle(make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A))
    rep = engine_factory(apply=True).handle(
        make_alert(registry["red_a2"], "RED", "toy-n64-k1", KEY_RED_A)
    )
    assert next(a["status"] for a in rep["actions"] if a["kind"] == "rotate_secrets") == "done"


def test_approval_flow(tmp_path: Path, registry: Reg, engine_factory: Factory) -> None:
    eng = engine_factory(apply=True)
    rep = eng.handle(make_alert(registry["red_a1"], "RED", "toy-n64-k1", KEY_RED_A))
    with pytest.raises(PolicyError):
        eng.approve(rep["incident_id"], ["switch_profile"])  # not pending
    with pytest.raises(NotFoundError):
        eng.approve("no-such-incident", ["firewall_block"])
    after = eng.approve(rep["incident_id"], ["firewall_block"])
    assert after["pending_approval"] == ["service_stop"]
    assert "10.0.0.66" in labpolicy.load(tmp_path / "policy.json").blocked_ips
    with pytest.raises(PolicyError):
        eng.approve(rep["incident_id"], ["firewall_block"])  # no longer pending
