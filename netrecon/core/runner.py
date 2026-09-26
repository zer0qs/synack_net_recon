"""Subprocess execution and the run context shared by all stages."""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

from netrecon.core.config import Config
from netrecon.core.privileges import Privileges
from netrecon.core.scope import Scope
from netrecon.core.state import RunState
from netrecon.core.tools import ToolRegistry

log = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


class CommandFailed(Exception):
    """A subprocess exited non-zero (and the caller asked us to care)."""

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        super().__init__(
            f"{result.argv[0]} exited {result.returncode} after {result.duration}s: "
            f"{result.tail()}"
        )


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def tail(self, lines: int = 4) -> str:
        source = self.stderr.strip() or self.stdout.strip()
        if not source:
            return "(no output)"
        return " | ".join(source.splitlines()[-lines:])

    @property
    def command(self) -> str:
        return shlex.join(self.argv)


def run_command(
    argv: Sequence[str],
    *,
    timeout: int | None = None,
    check: bool = False,
    cwd: Path | None = None,
    stdin_data: str | None = None,
    log_output: bool = True,
) -> CommandResult:
    """Run *argv* with no shell, capturing output and timing it.

    ``argv`` is always a list - netrecon never builds shell strings, so target
    values cannot be interpreted as shell syntax.
    """
    argv = tuple(str(part) for part in argv)
    log.debug("exec", extra={"command": shlex.join(argv), "timeout": timeout})
    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            input=stdin_data,
            check=False,
        )
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        returncode = 124
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{argv[0]} is not installed or not on PATH") from exc

    duration = round(time.monotonic() - started, 3)
    result = CommandResult(argv, returncode, stdout or "", stderr or "", duration, timed_out)

    if log_output:
        level = logging.DEBUG if result.ok else logging.WARNING
        log.log(
            level,
            "%s finished rc=%s in %.1fs",
            argv[0],
            returncode,
            duration,
            extra={"command": shlex.join(argv), "timed_out": timed_out},
        )
        if not result.ok and result.tail() != "(no output)":
            log.log(level, "%s output: %s", argv[0], result.tail())

    if check and not result.ok:
        raise CommandFailed(result)
    return result


def run_parallel(
    items: Iterable[T],
    worker: Callable[[T], R],
    *,
    concurrency: int,
    label: str = "task",
) -> list[R]:
    """Map *worker* over *items* with a bounded thread pool, in input order."""
    items = list(items)
    if not items:
        return []
    workers = max(1, min(concurrency, len(items)))
    log.debug("running %d %s(s) with %d worker(s)", len(items), label, workers)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=label) as pool:
        return list(pool.map(worker, items))


@dataclass
class RunPaths:
    """Every file netrecon writes for a run."""

    root: Path

    @property
    def live_hosts(self) -> Path:
        return self.root / "live_hosts.txt"

    @property
    def open_ports(self) -> Path:
        return self.root / "open_ports.json"

    @property
    def services(self) -> Path:
        return self.root / "services.json"

    @property
    def report(self) -> Path:
        return self.root / "report.md"

    @property
    def summary(self) -> Path:
        return self.root / "summary.json"

    @property
    def nuclei(self) -> Path:
        return self.root / "nuclei.json"

    @property
    def run_log(self) -> Path:
        return self.root / "run.log"

    @property
    def scope_snapshot(self) -> Path:
        return self.root / "scope.txt"

    @property
    def nmap_dir(self) -> Path:
        return self.root / "nmap"

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def targets_dir(self) -> Path:
        return self.root / "targets"

    def ensure(self) -> None:
        for directory in (self.root, self.nmap_dir, self.raw_dir, self.targets_dir):
            directory.mkdir(parents=True, exist_ok=True)


@dataclass
class RunContext:
    """Handed to every stage; the only way a stage reaches targets or tools."""

    config: Config
    scope: Scope
    paths: RunPaths
    state: RunState
    tools: ToolRegistry
    privileges: Privileges
    active: bool = False
    full_ports: bool = False
    dry_run: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def logger(self, stage: str) -> logging.LoggerAdapter:
        return logging.LoggerAdapter(logging.getLogger(f"netrecon.{stage}"), {"stage": stage})

    def sweep_ports(self) -> str:
        return self.config.ports.sweep_full if self.full_ports else self.config.ports.sweep

    def targets_file(self, name: str, candidates: Iterable[str] | None = None) -> tuple[Path, int]:
        """Write a scope-enforced target file under ``targets/``."""
        return self.scope.write_targets(self.paths.targets_dir / name, candidates)

    def live_hosts(self) -> list[str]:
        """Live hosts from the discovery checkpoint, re-filtered through scope.

        Re-enforcing on read means a hand-edited ``live_hosts.txt`` or a stale
        checkpoint still cannot widen the scan.
        """
        path = self.paths.live_hosts
        if not path.is_file():
            return []
        raw = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
        return list(self.scope.enforce(raw).allowed_str)

    def stage_timeout(self) -> int:
        return self.config.limits.stage_timeout_seconds

    def env_note(self) -> str:
        return f"uid={os.geteuid()} raw_sockets={self.privileges.raw_sockets}"
