"""Structured JSON-line logging for SIEM / pipeline ingestion.

Opt-in via ``--log-json FILE``. Each record is rendered as a single line of
JSON with ``ts``, ``level``, ``logger``, ``message``, plus any structured
``extra`` fields a caller attached. Rich-formatting tags are stripped so logs
remain machine-readable.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time

_RICH_TAG = re.compile(r"\[/?[a-zA-Z0-9 _#]+\]")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        message = _RICH_TAG.sub("", message)
        payload: dict = {
            "ts": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Carry over any user-attached structured fields.
        for key, value in record.__dict__.items():
            if key in payload or key.startswith("_"):
                continue
            if key in (
                "args", "asctime", "created", "exc_info", "exc_text",
                "filename", "funcName", "levelname", "levelno", "lineno",
                "module", "msecs", "message", "msg", "name", "pathname",
                "process", "processName", "relativeCreated", "stack_info",
                "thread", "threadName", "taskName",
            ):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        return json.dumps(payload, ensure_ascii=False)


def install_json_handler(target: str) -> logging.Handler:
    """Attach a JSON-line handler to the SprayMaster logger.

    ``target`` is either ``'-'`` for stderr or a writable file path.
    """
    handler: logging.Handler
    if target == "-":
        handler = logging.StreamHandler(sys.stderr)
    else:
        handler = logging.FileHandler(target, encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    handler.setLevel(logging.INFO)
    logging.getLogger("SprayMaster").addHandler(handler)
    return handler
