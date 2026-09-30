"""Logging that cannot leak sensitive values or credentials.

Scanners never pass raw matches to the logger. As a second line of defence,
every log line - including exception tracebacks and third-party messages - is
passed through the same detectors used for scanning and through a literal
scrub of any credential currently held in the environment.
"""

from __future__ import annotations

import logging
import os
import sys

from .detectors import build_redaction_engine

_SECRET_ENV_VARS = (
    "PGPASSWORD",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ACCESS_KEY_ID",
)
_HANDLER_NAME = "dcscanner-stderr"


def redact_text(text: str) -> str:
    for name in _SECRET_ENV_VARS:
        secret = os.environ.get(name)
        if secret and len(secret) >= 6:
            text = text.replace(secret, "[REDACTED]")
    return build_redaction_engine().redact(text)


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


def configure_logging(level: str = "WARNING") -> None:
    """Send logs to stderr through the redacting formatter (idempotent)."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if handler.get_name() == _HANDLER_NAME:
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.WARNING))
    # Client libraries log request details at DEBUG; keep them quiet regardless.
    for noisy in ("boto3", "botocore", "urllib3", "s3transfer", "psycopg"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
