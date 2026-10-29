"""Run the real attacker chain against a running lab proxy (M8 increment 5).

Wires the capture relay (lab/attacker/capture.py) in front of the lab proxy,
generates one toy stream so there is traffic to capture, then runs the real
recovery chain (lab/attacker/recover.py). `require_lab()` runs before any socket
is opened and GREEN is refused.

On the real toy profiles the chain honestly reports `key-not-recovered`
(BKZ required); this is not a break. The M9 scenario keeps using the lab oracle.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

from canary_qday.common.config import Settings
from canary_qday.common.store import Store
from canary_qday.kem.profiles import params_for
from canary_qday.traffic import generator
from lab.attacker.capture import Relay
from lab.attacker.guard import require_lab
from lab.attacker.recover import DEFAULT_MAX_DIM, AttackResult, run_attack


async def capture_stream(settings: Settings, capture_path: Path, profile: str) -> None:
    """Relay one `profile` stream through a lab relay in front of settings.proxy_*.

    The generator is pointed at the relay's ephemeral port; the relay forwards to
    the real proxy at (settings.proxy_host, settings.proxy_port) and records it.
    """
    relay = Relay(settings.proxy_host, settings.proxy_port, capture_path, profile)
    relay_server, writer = await relay.start("127.0.0.1", 0)
    relay_port = relay_server.sockets[0].getsockname()[1]
    try:
        store = Store(settings.registry_db)
        via_relay = replace(settings, proxy_port=relay_port)
        await generator.run_stream(store, via_relay, profile, ["billing"])
    finally:
        relay_server.close()
        await relay_server.wait_closed()
        writer.close()


def capture_and_attack(
    settings: Settings,
    capture_path: Path,
    profile: str = "RED",
    *,
    max_dim: int = DEFAULT_MAX_DIM,
) -> tuple[AttackResult, Path]:
    """Guarded, synchronous: capture one stream then run the real attack on it."""
    require_lab(profile, settings.proxy_host)  # lab mode + toy profile + lab host
    asyncio.run(capture_stream(settings, capture_path, profile))
    result = run_attack(capture_path, params_for(profile), max_dim=max_dim)
    return result, capture_path
