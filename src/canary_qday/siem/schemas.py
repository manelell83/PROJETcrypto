"""Event and alert schemas (spec 7.1). Validation is strict: unknown fields are rejected."""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HEX8 = re.compile(r"^[0-9a-f]{8}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
Profile = Literal["RED", "ORANGE", "GREEN"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TrapEvent(_Strict):
    """Emitted by the canary server when a registered trap token is used."""

    event: Literal["trap_triggered"] = "trap_triggered"
    event_id: str = Field(min_length=36, max_length=36)
    ts: str = Field(max_length=40)
    token_id: str
    stream_id: str = Field(min_length=36, max_length=36)
    profile: Profile
    params_id: str = Field(max_length=40)
    key_id: str
    epoch: int = Field(ge=0, le=1_000_000)
    src_ip: str = Field(max_length=64)
    user_agent: str = Field(max_length=256)

    @field_validator("token_id")
    @classmethod
    def _tid(cls, v: str) -> str:
        if not _HEX8.fullmatch(v):
            raise ValueError("token_id must be 8 hex chars")
        return v

    @field_validator("key_id")
    @classmethod
    def _kid(cls, v: str) -> str:
        if not _HEX16.fullmatch(v):
            raise ValueError("key_id must be 16 hex chars")
        return v

    @field_validator("user_agent", "src_ip")
    @classmethod
    def _printable(cls, v: str) -> str:
        # Neutralise log injection: keep printable ASCII only.
        return "".join(c if 32 <= ord(c) < 127 else "?" for c in v)


class HandshakeEvent(_Strict):
    """Emitted by the proxy for each accepted or refused handshake (no secrets)."""

    event: Literal["handshake"] = "handshake"
    event_id: str
    ts: str
    stream_id: str
    profile: str
    key_id: str
    epoch: int
    src_ip: str
    outcome: Literal["accepted", "refused"]
    reason: str = ""


class Alert(_Strict):
    """Alert delivered by the SIEM to the response engine webhook."""

    alert_id: str = Field(min_length=8, max_length=64)
    ts: str = Field(max_length=40)
    rule: str = Field(max_length=64)
    severity: Literal["low", "medium", "high", "critical"]
    event: TrapEvent


def to_json(model: BaseModel) -> str:
    """UTF-8 JSON with sorted keys (spec 5: serialization)."""
    return json.dumps(model.model_dump(), sort_keys=True, separators=(",", ":"))


def parse_alert(raw: bytes | str | dict[str, Any]) -> Alert:
    """Validate an alert body; raises pydantic.ValidationError on any deviation."""
    if isinstance(raw, dict):
        return Alert.model_validate(raw)
    return Alert.model_validate_json(raw)
