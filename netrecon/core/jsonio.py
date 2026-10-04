"""Atomic JSON writing, so an interrupted run never leaves half a result file."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_json(path: str | Path, data: Any, *, indent: int = 2) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            json.dump(data, handle, indent=indent, default=str, sort_keys=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return path


def read_json(path: str | Path, default: Any = None) -> Any:
    path = Path(path)
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        # A tool that wrote binary rubbish into a result file must degrade to
        # "no data", exactly like a truncated or missing one.
        return default


def write_lines(path: str | Path, lines: list[str]) -> Path:
    """Write a line-per-entry artifact, atomically.

    Same contract as :func:`write_json`: an interrupted or failing write must
    leave either the previous file or no file, never a truncated host list that
    a later stage would read as "these are all the live hosts".
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write("".join(f"{line}\n" for line in lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return path
