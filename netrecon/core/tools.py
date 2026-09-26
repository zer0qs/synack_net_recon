"""External tool discovery and version reporting."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version_args: tuple[str, ...]
    required_for: tuple[str, ...]
    install_hint: str
    needs_raw_sockets: bool = False


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "nmap",
        ("--version",),
        ("discovery", "sweep-fallback", "services", "scripts", "os_detect"),
        "apt-get install -y nmap",
    ),
    ToolSpec(
        "masscan",
        ("--version",),
        ("sweep",),
        "apt-get install -y masscan",
        needs_raw_sockets=True,
    ),
    ToolSpec(
        "fping",
        ("--version",),
        ("discovery",),
        "apt-get install -y fping",
        needs_raw_sockets=True,
    ),
    ToolSpec(
        "naabu",
        ("-version",),
        ("sweep",),
        "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    ),
    ToolSpec(
        "nuclei",
        ("-version",),
        ("nuclei",),
        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
)


@dataclass(frozen=True)
class ToolStatus:
    spec: ToolSpec
    path: str | None
    version: str | None
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.path is not None

    @property
    def name(self) -> str:
        return self.spec.name

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "required_for": list(self.spec.required_for),
            "install_hint": self.spec.install_hint,
            "error": self.error,
        }


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-\w.]+)?)")


def _probe_version(path: str, args: tuple[str, ...]) -> tuple[str | None, str | None]:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [path, *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)

    output = (completed.stdout or "") + (completed.stderr or "")
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    if not first_line:
        return None, "tool produced no version output"
    match = _VERSION_RE.search(first_line)
    return (match.group(1) if match else first_line[:80]), None


def check_tools(specs: tuple[ToolSpec, ...] = TOOL_SPECS) -> dict[str, ToolStatus]:
    """Locate each supported tool and read back its version."""
    statuses: dict[str, ToolStatus] = {}
    for spec in specs:
        path = shutil.which(spec.name)
        if path is None:
            statuses[spec.name] = ToolStatus(spec, None, None, "not found on PATH")
            continue
        version, error = _probe_version(path, spec.version_args)
        statuses[spec.name] = ToolStatus(spec, path, version, error)
    return statuses


class ToolRegistry:
    """Lookup helper passed to stages."""

    def __init__(self, statuses: dict[str, ToolStatus]) -> None:
        self._statuses = statuses

    @classmethod
    def detect(cls) -> ToolRegistry:
        return cls(check_tools())

    def __getitem__(self, name: str) -> ToolStatus:
        return self._statuses[name]

    def has(self, name: str) -> bool:
        status = self._statuses.get(name)
        return status is not None and status.available

    def path(self, name: str) -> str:
        status = self._statuses.get(name)
        if status is None or status.path is None:
            hint = ""
            if status is not None:
                hint = f" ({status.spec.install_hint})"
            raise FileNotFoundError(f"required tool {name!r} is not installed{hint}")
        return status.path

    def version(self, name: str) -> str | None:
        status = self._statuses.get(name)
        return status.version if status else None

    def available(self) -> list[str]:
        return sorted(name for name, s in self._statuses.items() if s.available)

    def missing(self) -> list[str]:
        return sorted(name for name, s in self._statuses.items() if not s.available)

    def to_dict(self) -> dict[str, object]:
        return {name: status.to_dict() for name, status in sorted(self._statuses.items())}
