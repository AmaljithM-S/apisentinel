"""Structured JSON logging.

Container logs are machine-read far more often than they are eyeballed, so each
line is a JSON object. The request id emitted by the HTTP middleware is carried
through, which is what makes a failed scan traceable from the browser to the
subprocess that broke.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = repr(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # Access logs would duplicate the middleware line with less context.
    logging.getLogger("uvicorn.access").handlers = []
    logging.getLogger("uvicorn.access").propagate = False
    for noisy in ("httpx", "httpcore", "urllib3", "passlib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
