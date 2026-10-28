"""Synthetic traffic generator: opens a KEM channel per stream and sends a payload with a trap.

Run: python -m canary_qday.traffic.generator --profile RED --streams 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
import uuid
from dataclasses import dataclass

from canary_qday.channel import framing
from canary_qday.channel import handshake as hs
from canary_qday.common.config import Settings
from canary_qday.common.errors import CanaryError, PolicyError
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.store import Store
from canary_qday.services.backend_stub import SERVICES
from canary_qday.traffic.registry import register_stream

_log = get_logger("generator")


@dataclass
class StreamResult:
    """Outcome of one stream (no secrets)."""

    stream_id: str
    profile: str
    key_id: str
    responses: list[int]


async def _exchange(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, f: framing.Frame
) -> framing.Frame:
    writer.write(framing.encode(f.type, f.payload))
    await writer.drain()
    resp = await framing.read_frame(reader)
    if resp.type == framing.FrameType.ERROR:
        raise PolicyError(resp.payload.decode(errors="replace")[:32])
    return resp


async def run_stream(
    store: Store, settings: Settings, profile: str, services: list[str] | None = None,
    requests_per_stream: int = 2,
) -> StreamResult:
    """Run one stream end to end."""
    services = services or random.sample(SERVICES, 2)
    reader, writer = await asyncio.open_connection(settings.proxy_host, settings.proxy_port)
    try:
        kr = await _exchange(reader, writer, hs.key_request(profile))
        prof, epoch, kid, ek = hs.parse_key_response(kr)
        params_id = hs.params_id_for(prof)
        issued = register_stream(
            store, profile=prof, params_id=params_id, key_id=kid.hex(), epoch=epoch,
            services=services, canary_base_url=settings.canary_base_url,
        )
        hello, session = hs.client_hello(prof, epoch, ek, uuid.UUID(issued.stream_id).bytes)
        writer.write(framing.encode(hello.type, hello.payload))
        codes: list[int] = []
        for i in range(requests_per_stream):
            svc = services[i % len(services)]
            payload = {
                "stream_id": issued.stream_id,
                "service": svc,
                "action": random.choice(["list_invoices", "get_profile", "sync", "export"]),
                "credential": issued.credentials[f"{svc}.api_key"],
                "credentials": issued.credentials,
                "note": f"Password reset for the admin console: {issued.trap_url}",
            }
            resp = await _exchange(reader, writer, session.seal(json.dumps(payload).encode()))
            codes.append(int(json.loads(session.open(resp))["status"]))
        store.end_stream(issued.stream_id, time.time())
        log_event(_log, "stream done", stream_id=issued.stream_id, profile=prof,
                  key_id=kid.hex(), codes=codes)
        return StreamResult(issued.stream_id, prof, kid.hex(), codes)
    finally:
        writer.close()


async def run_many(profile: str, n: int, settings: Settings) -> list[StreamResult]:
    """Run n streams sequentially."""
    store = Store(settings.registry_db)
    out = []
    for _ in range(n):
        try:
            out.append(await run_stream(store, settings, profile))
        except (CanaryError, ConnectionError) as e:
            log_event(_log, "stream refused", profile=profile, error=type(e).__name__)
    return out


def main() -> None:
    """CLI."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=["RED", "ORANGE", "GREEN"], default="RED")
    ap.add_argument("--streams", type=int, default=1)
    args = ap.parse_args()
    res = asyncio.run(run_many(args.profile, args.streams, Settings.from_env()))
    print(json.dumps([r.__dict__ for r in res], indent=2))


if __name__ == "__main__":
    main()
