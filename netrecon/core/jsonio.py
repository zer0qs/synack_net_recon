"""Atomic JSON writing, so an interrupted run never leaves half a result file."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

#: Every artifact in a run directory holds client-confidential data: service
#: versions, internal hostnames, and the secret and PII candidates found in
#: front-end code. The JSON artifacts were already 0600, but only as an
#: accident of :class:`tempfile.NamedTemporaryFile`, while the reports -- the
#: files anyone actually opens -- were left at whatever the umask gave, i.e.
#: world-readable on a stock Linux. The mode is now explicit and the same for
#: all of them.
ARTIFACT_MODE = 0o600

#: A run directory should not be listable by other users either.
RUN_DIR_MODE = 0o700


def secure_mkdir(path: str | Path) -> Path:
    """``mkdir -p`` where every component created gets :data:`RUN_DIR_MODE`.

    ``Path.mkdir(parents=True, mode=...)`` applies the mode only to the final
    component: parents are created with the default, so a nested artifact
    directory left its intermediate levels world-readable.
    """
    path = Path(path)
    missing = [p for p in (path, *path.parents) if not p.exists()]
    path.mkdir(parents=True, exist_ok=True)
    for component in missing:
        try:
            component.chmod(RUN_DIR_MODE)
        except OSError:  # noqa: S110 - a filesystem without modes is not fatal
            pass
    return path


def write_text(path: str | Path, text: str) -> Path:
    """Write a text artifact atomically, with the artifact file mode."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(handle.name, ARTIFACT_MODE)
        os.chmod(handle.name, ARTIFACT_MODE)
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return path


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
        os.chmod(handle.name, ARTIFACT_MODE)
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
        os.chmod(handle.name, ARTIFACT_MODE)
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return path
