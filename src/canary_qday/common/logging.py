"""JSON logging with mandatory redaction."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from canary_qday.common.redact import redact


class JsonFormatter(logging.Formatter):
    """One JSON object per line; the `fields` extra is redacted before output."""

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            data.update(redact(fields))
        return json.dumps(data, sort_keys=True, default=str)


def get_logger(name: str) -> logging.Logger:
    """Return a logger writing redacted JSON to stderr."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def log_event(logger: logging.Logger, msg: str, **fields: Any) -> None:
    """Log msg with structured fields (redacted by the formatter)."""
    logger.info(msg, extra={"fields": fields})
