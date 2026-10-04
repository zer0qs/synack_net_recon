"""Structured logging: human-readable console output plus a JSONL run log."""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from netrecon.core.jsonio import ARTIFACT_MODE

RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime", "taskName"}


class JsonlFormatter(logging.Formatter):
    """One JSON object per line, with any extra kwargs preserved."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in RESERVED and not key.startswith("_"):
                payload[key] = _jsonable(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    LEVEL_TAGS = {
        "DEBUG": "  ",
        "INFO": "[*]",
        "WARNING": "[!]",
        "ERROR": "[x]",
        "CRITICAL": "[X]",
    }

    def format(self, record: logging.LogRecord) -> str:
        tag = self.LEVEL_TAGS.get(record.levelname, "[?]")
        stamp = time.strftime("%H:%M:%S", time.gmtime(record.created))
        line = f"{stamp} {tag} {record.getMessage()}"
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in RESERVED and not key.startswith("_") and key != "stage"
        }
        if extras:
            rendered = " ".join(f"{k}={_compact(v)}" for k, v in sorted(extras.items()))
            line = f"{line} ({rendered})"
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


def _compact(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 60 else text[:57] + "..."


def configure(
    log_path: Path | None = None,
    *,
    verbose: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """Install console and (optionally) JSONL handlers on the netrecon logger."""
    root = logging.getLogger("netrecon")
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    root.propagate = False

    console_level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(console_level)
    console.setFormatter(ConsoleFormatter())
    root.addHandler(console)

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        # The run log carries every finding the stages logged, so it gets the
        # same mode as the artifacts rather than whatever the umask allows.
        try:
            log_path.chmod(ARTIFACT_MODE)
        except OSError:  # noqa: S110 - a filesystem without modes is not fatal
            pass
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonlFormatter())
        root.addHandler(file_handler)

    return root


class Timer:
    """Context manager recording wall-clock seconds for a block."""

    def __init__(self) -> None:
        self.started = 0.0
        self.finished = 0.0

    def __enter__(self) -> Timer:
        self.started = time.monotonic()
        return self

    def __exit__(self, *exc: object) -> None:
        self.finished = time.monotonic()

    @property
    def elapsed(self) -> float:
        end = self.finished or time.monotonic()
        return round(end - self.started, 3)
