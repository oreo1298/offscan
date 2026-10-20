"""Logging setup with secret redaction.

API keys and customer IDs for definition feeds end up in URLs; every log
record passes through :class:`RedactFilter` so they never reach a log file,
an error dialog or a report.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
import threading
from pathlib import Path

from . import appinfo, paths

_secrets: set[str] = set()
_lock = threading.Lock()
REDACTED = "«redacted»"


def register_secret(value: str | None) -> None:
    """Remember a secret so it is scrubbed from all log output."""
    if value and len(value) >= 4:
        with _lock:
            _secrets.add(value)


def redact(text: str) -> str:
    with _lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed format args: keep the record as is
            return True
        cleaned = redact(message)
        if cleaned != message or record.args:
            record.msg = cleaned
            record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
        return True


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"{appinfo.NAME}.{name}")


def setup(component: str, verbose: bool = False, to_file: bool = True,
          log_dir: Path | None = None) -> logging.Logger:
    """Configure the package logger for one process (gui, cli, helper, ...)."""
    logger = logging.getLogger(appinfo.NAME)
    logger.setLevel(logging.DEBUG)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    redact_filter = RedactFilter()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG if verbose else logging.WARNING)
    stream.setFormatter(fmt)
    stream.addFilter(redact_filter)
    logger.addHandler(stream)

    if to_file:
        directory = log_dir or paths.log_dir()
        try:
            paths.ensure_dir(directory)
            fh = logging.handlers.RotatingFileHandler(
                directory / f"{component}.log", maxBytes=2_000_000, backupCount=3,
                encoding="utf-8")
            fh.setLevel(logging.DEBUG if verbose else logging.INFO)
            fh.setFormatter(fmt)
            fh.addFilter(redact_filter)
            logger.addHandler(fh)
        except OSError as exc:
            logger.warning("cannot write log file in %s: %s", directory, exc)
    logger.propagate = False
    return logger
