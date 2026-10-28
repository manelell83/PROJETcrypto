"""Shared fixtures: a synthetic registry and helpers to build alerts."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from canary_qday.common.redact import token_id
from canary_qday.common.store import Store
from canary_qday.response.engine import EngineConfig, ResponseEngine
from canary_qday.siem.schemas import Alert, TrapEvent
from canary_qday.traffic.registry import IssuedStream, register_stream

KEY_RED_A = "aaaaaaaaaaaaaaaa"
KEY_RED_B = "bbbbbbbbbbbbbbbb"
KEY_ORANGE = "cccccccccccccccc"
KEY_GREEN = "dddddddddddddddd"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    """Empty registry in a temporary directory."""
    return Store(tmp_path / "registry.db")


def add_stream(
    store: Store, profile: str, params_id: str, key_id: str, now: float | None = None
) -> IssuedStream:
    """Register one synthetic stream with two services."""
    return register_stream(
        store,
        profile=profile,
        params_id=params_id,
        key_id=key_id,
        epoch=1,
        services=["billing", "hr"],
        canary_base_url="http://canary",
        now=time.time() if now is None else now,
    )


@pytest.fixture
def registry(store: Store) -> dict[str, IssuedStream]:
    """Ground truth: 2 streams on RED key A, 1 on RED key B, 1 ORANGE, 1 GREEN."""
    return {
        "red_a1": add_stream(store, "RED", "toy-n64-k1", KEY_RED_A),
        "red_a2": add_stream(store, "RED", "toy-n64-k1", KEY_RED_A),
        "red_b": add_stream(store, "RED", "toy-n64-k1", KEY_RED_B),
        "orange": add_stream(store, "ORANGE", "toy-n64-k2", KEY_ORANGE),
        "green": add_stream(store, "GREEN", "xwing-mlkem768-x25519", KEY_GREEN),
    }


def make_alert(
    issued: IssuedStream, profile: str, params_id: str, key_id: str, *, token: str | None = None
) -> Alert:
    """A well-formed alert for a registered stream (or a forged token if given)."""
    now = datetime.now(UTC).isoformat()
    return Alert(
        alert_id=str(uuid.uuid4()),
        ts=now,
        rule="canary_trap_triggered",
        severity="high",
        event=TrapEvent(
            event_id=str(uuid.uuid4()),
            ts=now,
            token_id=token_id(token or issued.token),
            stream_id=issued.stream_id,
            profile=profile,  # type: ignore[arg-type]
            params_id=params_id,
            key_id=key_id,
            epoch=1,
            src_ip="10.0.0.66",
            user_agent="pytest",
        ),
    )


@pytest.fixture
def engine_factory(tmp_path: Path, store: Store) -> Callable[..., ResponseEngine]:
    """Build engines sharing the same registry, policy and response DB."""

    def build(*, apply: bool = False, auto_lab: bool = False) -> ResponseEngine:
        return ResponseEngine(
            EngineConfig(
                registry_db=store.path,
                response_db=tmp_path / "response.db",
                policy_file=tmp_path / "policy.json",
                reports_dir=tmp_path / "reports",
                notify_file=tmp_path / "notify.jsonl",
                apply=apply,
                auto_lab=auto_lab,
            )
        )

    return build
