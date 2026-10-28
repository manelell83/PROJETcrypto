"""Canary proxy: terminates the KEM channel and forwards requests to backend stubs.

Keys: one static KEM key per (profile, epoch) under CQ_SECRETS_DIR, created on
first use. Private keys are written 0600 and refused if more permissive (SEC-006).
The lab policy file is re-read whenever it changes, so a profile switch, key
revocation, IP block or service stop by the response engine applies to the
next connection.

Run: python -m canary_qday.services.proxy
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx

from canary_qday.channel import framing
from canary_qday.channel import handshake as hs
from canary_qday.common import labpolicy
from canary_qday.common.config import read_secret, write_secret
from canary_qday.common.errors import CanaryError
from canary_qday.common.logging import get_logger, log_event
from canary_qday.common.store import Store
from canary_qday.services import backend_stub
from canary_qday.siem.base import SiemSink
from canary_qday.siem.schemas import HandshakeEvent

_log = get_logger("proxy")


class KeyManager:
    """Loads or creates the static key of each (profile, epoch)."""

    def __init__(self, secrets_dir: Path) -> None:
        self.dir = secrets_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def get(self, profile: str, epoch: int) -> hs.ServerKey:
        """Return the key, generating it on first use."""
        ek_path = self.dir / f"{profile}-e{epoch}.ek"
        dk_path = self.dir / f"{profile}-e{epoch}.dk"
        if not ek_path.exists() or not dk_path.exists():
            ek, dk = hs.suite_for(profile).keygen()
            write_secret(dk_path, dk)
            ek_path.write_bytes(ek)
        return hs.ServerKey(profile, epoch, ek_path.read_bytes(), read_secret(dk_path))


class Proxy:
    """Connection handler with hot-reloaded policy."""

    def __init__(
        self,
        keys: KeyManager,
        policy_file: Path,
        store: Store,
        sink: SiemSink | None = None,
        backend_url: str | None = None,
    ) -> None:
        self.keys = keys
        self.policy_file = policy_file
        self.store = store
        self.sink = sink
        self.backend_url = backend_url
        self.state = hs.ServerState(set())
        self._mtime = -1.0
        self.policy = labpolicy.LabPolicy()
        self.reload()

    def reload(self) -> None:
        """Re-read the policy file if it changed and refresh allowed keys."""
        mtime = self.policy_file.stat().st_mtime if self.policy_file.exists() else 0.0
        if mtime == self._mtime:
            return
        self._mtime = mtime
        self.policy = labpolicy.load(self.policy_file)
        self.state.allowed = set(self.policy.allowed_profiles)
        self.state.revoked = {bytes.fromhex(k) for k in self.policy.revoked_key_ids}
        for p in self.policy.allowed_profiles:
            self.state.install(self.keys.get(p, self.policy.epochs.get(p, 1)))
        log_event(_log, "policy loaded", allowed=self.policy.allowed_profiles,
                  epochs=self.policy.epochs)

    def _event(self, info: hs.HelloInfo | None, ip: str, outcome: str, reason: str = "") -> None:
        if self.sink is None:
            return
        self.sink.send(HandshakeEvent(
            event_id=str(uuid.uuid4()), ts=datetime.now(UTC).isoformat(),
            stream_id=str(uuid.UUID(bytes=info.stream_id)) if info else "",
            profile=info.profile if info else "", key_id=info.key_id.hex() if info else "",
            epoch=info.epoch if info else 0, src_ip=ip, outcome=outcome,  # type: ignore[arg-type]
            reason=reason,
        ))

    async def _backend(self, req: dict[str, object]) -> dict[str, object]:
        model = backend_stub.Request_.model_validate(req)
        if self.backend_url:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.post(f"{self.backend_url}/api", json=model.model_dump())
                return dict(r.json())
        return backend_stub.handle(self.store, self.policy_file, model)

    async def serve_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle one TCP connection."""
        peer = writer.get_extra_info("peername")
        ip = str(peer[0]) if peer else "unknown"
        self.reload()
        session: hs.Session | None = None
        try:
            if ip in self.policy.blocked_ips:
                raise CanaryError("blocked")
            while True:
                try:
                    frame = await asyncio.wait_for(framing.read_frame(reader), timeout=30)
                except (TimeoutError, CanaryError):
                    break
                if frame.type == framing.FrameType.KEY_REQUEST and session is None:
                    if len(frame.payload) != 1 or frame.payload[0] not in hs.PROFILE_BY_ID:
                        raise CanaryError("bad key request")
                    key = self.state.current(hs.PROFILE_BY_ID[frame.payload[0]])
                    out = hs.key_response(key)
                elif frame.type == framing.FrameType.HELLO and session is None:
                    info = None
                    try:
                        info = hs.parse_hello(frame)
                        session = self.state.accept(frame)
                    except CanaryError as e:
                        self._event(info, ip, "refused", e.code)
                        raise
                    self._event(info, ip, "accepted")
                    continue
                elif frame.type == framing.FrameType.DATA and session is not None:
                    req = json.loads(session.open(frame))
                    resp = await self._backend({k: req.get(k) for k in
                                                ("service", "action", "credential")})
                    out = session.seal(json.dumps(resp, sort_keys=True).encode())
                else:
                    raise CanaryError("unexpected frame")
                writer.write(framing.encode(out.type, out.payload))
                await writer.drain()
        except (CanaryError, ValueError) as e:
            code = getattr(e, "code", "E_FRAME")
            try:
                writer.write(framing.encode(framing.FrameType.ERROR, code.encode()))
                await writer.drain()
            except ConnectionError:
                pass
        finally:
            writer.close()


async def serve(proxy: Proxy, host: str, port: int) -> None:
    """Run the TCP server forever."""
    server = await asyncio.start_server(proxy.serve_conn, host, port)
    log_event(_log, "proxy listening", host=host, port=port)
    async with server:
        await server.serve_forever()


def main() -> None:
    """Entry point."""
    from canary_qday.common.config import Settings, env_secret
    from canary_qday.siem.base import make_sink

    s = Settings.from_env()
    sink: SiemSink
    if s.siem_sink == "hec":
        sink = make_sink("hec", hec_url=s.hec_url,
                         token=env_secret("CQ_HEC_TOKEN", "CQ_HEC_TOKEN_FILE"),
                         buffer_path=s.data_dir / "siem" / "proxy-buffer.jsonl")
    else:
        sink = make_sink("file", path=s.data_dir / "siem" / "proxy-events.jsonl")
    proxy = Proxy(KeyManager(s.secrets_dir), s.policy_file, Store(s.registry_db), sink,
                  os.environ.get("CQ_BACKEND_URL"))
    asyncio.run(serve(proxy, os.environ.get("CQ_BIND", s.proxy_host), s.proxy_port))


if __name__ == "__main__":
    main()
