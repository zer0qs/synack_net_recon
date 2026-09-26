"""Common stage plumbing."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class StageSkipped(Exception):
    """Raised by a stage that cannot run; recorded as ``skipped``, not a failure."""


class StageFailed(Exception):
    """Raised by a stage that ran and could not produce usable output."""


@dataclass
class StageResult:
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, Path | str] = field(default_factory=dict)
    backend: str | None = None
    detail: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
