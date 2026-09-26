"""Checkpoint / resume state, persisted as ``state.json`` in the run directory."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

STATE_FILENAME = "state.json"
STATE_VERSION = 1

PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
SKIPPED = "skipped"


class StateError(Exception):
    """The on-disk state cannot be used."""


@dataclass
class StageState:
    name: str
    status: str = PENDING
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    detail: str | None = None
    backend: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "counts": dict(self.counts),
            "outputs": dict(self.outputs),
            "detail": self.detail,
            "backend": self.backend,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageState:
        return cls(
            name=data["name"],
            status=data.get("status", PENDING),
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            duration_seconds=data.get("duration_seconds"),
            counts=dict(data.get("counts") or {}),
            outputs=dict(data.get("outputs") or {}),
            detail=data.get("detail"),
            backend=data.get("backend"),
        )


@dataclass
class RunState:
    run_dir: Path
    run_name: str
    started_at: str
    scope_fingerprint: str
    scope_source: str | None = None
    netrecon_version: str = ""
    config_snapshot: dict[str, Any] = field(default_factory=dict)
    stages: dict[str, StageState] = field(default_factory=dict)
    finished_at: str | None = None

    # -- lifecycle -------------------------------------------------------

    @property
    def path(self) -> Path:
        return self.run_dir / STATE_FILENAME

    @classmethod
    def create(
        cls,
        run_dir: Path,
        *,
        run_name: str,
        scope_fingerprint: str,
        scope_source: str | None,
        netrecon_version: str,
        config_snapshot: dict[str, Any],
    ) -> RunState:
        state = cls(
            run_dir=run_dir,
            run_name=run_name,
            started_at=utc_now(),
            scope_fingerprint=scope_fingerprint,
            scope_source=scope_source,
            netrecon_version=netrecon_version,
            config_snapshot=config_snapshot,
        )
        state.save()
        return state

    @classmethod
    def load(cls, run_dir: Path) -> RunState:
        path = Path(run_dir) / STATE_FILENAME
        if not path.is_file():
            raise StateError(f"no checkpoint found at {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StateError(f"could not read checkpoint {path}: {exc}") from exc
        if data.get("state_version") != STATE_VERSION:
            raise StateError(
                f"checkpoint {path} was written by an incompatible version "
                f"(found {data.get('state_version')!r}, expected {STATE_VERSION})"
            )
        state = cls(
            run_dir=Path(run_dir),
            run_name=data.get("run_name", "default"),
            started_at=data.get("started_at", utc_now()),
            scope_fingerprint=data.get("scope_fingerprint", ""),
            scope_source=data.get("scope_source"),
            netrecon_version=data.get("netrecon_version", ""),
            config_snapshot=data.get("config_snapshot") or {},
            finished_at=data.get("finished_at"),
        )
        for name, stage_data in (data.get("stages") or {}).items():
            state.stages[name] = StageState.from_dict({"name": name, **stage_data})
        return state

    def save(self) -> None:
        """Atomically write the checkpoint."""
        payload = {
            "state_version": STATE_VERSION,
            "run_name": self.run_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scope_fingerprint": self.scope_fingerprint,
            "scope_source": self.scope_source,
            "netrecon_version": self.netrecon_version,
            "config_snapshot": self.config_snapshot,
            "stages": {name: stage.to_dict() for name, stage in self.stages.items()},
        }
        self.run_dir.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.run_dir,
            prefix=".state-",
            suffix=".tmp",
            delete=False,
        )
        try:
            with handle:
                json.dump(payload, handle, indent=2, default=str)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, self.path)
        except BaseException:
            Path(handle.name).unlink(missing_ok=True)
            raise

    # -- stage bookkeeping ----------------------------------------------

    def stage(self, name: str) -> StageState:
        return self.stages.setdefault(name, StageState(name))

    def is_completed(self, name: str) -> bool:
        stage = self.stages.get(name)
        return stage is not None and stage.status == COMPLETED

    def begin(self, name: str, *, backend: str | None = None) -> StageState:
        stage = self.stage(name)
        stage.status = RUNNING
        stage.started_at = utc_now()
        stage.finished_at = None
        stage.duration_seconds = None
        stage.detail = None
        stage.backend = backend
        self.save()
        return stage

    def complete(
        self,
        name: str,
        *,
        duration: float,
        counts: dict[str, int] | None = None,
        outputs: dict[str, Path | str] | None = None,
        detail: str | None = None,
        backend: str | None = None,
    ) -> StageState:
        stage = self.stage(name)
        stage.status = COMPLETED
        stage.finished_at = utc_now()
        stage.duration_seconds = round(duration, 3)
        stage.counts = dict(counts or {})
        stage.outputs = {k: str(v) for k, v in (outputs or {}).items()}
        stage.detail = detail
        if backend:
            stage.backend = backend
        self.save()
        return stage

    def fail(self, name: str, *, duration: float, detail: str) -> StageState:
        stage = self.stage(name)
        stage.status = FAILED
        stage.finished_at = utc_now()
        stage.duration_seconds = round(duration, 3)
        stage.detail = detail
        self.save()
        return stage

    def skip(self, name: str, *, detail: str) -> StageState:
        stage = self.stage(name)
        stage.status = SKIPPED
        stage.finished_at = utc_now()
        stage.detail = detail
        self.save()
        return stage

    def finish(self) -> None:
        self.finished_at = utc_now()
        self.save()

    def check_scope(self, fingerprint: str) -> None:
        """Refuse to resume a run whose scope file has changed."""
        if self.scope_fingerprint and self.scope_fingerprint != fingerprint:
            raise StateError(
                "the scope file has changed since this run was started; resuming "
                "could scan hosts the earlier stages never authorised. Start a new "
                "run instead of resuming."
            )

    def timings(self) -> Iterator[tuple[str, float]]:
        for name, stage in self.stages.items():
            if stage.duration_seconds is not None:
                yield name, stage.duration_seconds


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def timestamp_dirname() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def find_latest_run(base: Path) -> Path | None:
    """Most recent timestamped run directory under ``results/<run>/``."""
    if not base.is_dir():
        return None
    candidates = [
        child
        for child in base.iterdir()
        if child.is_dir() and (child / STATE_FILENAME).is_file()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.name)
