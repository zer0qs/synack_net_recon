"""Raw-socket capability detection.

Raw-socket stages (masscan, ``nmap -sS``, ``nmap -O``, ``fping``) need either
root or ``CAP_NET_RAW``.  Rather than letting a tool fail with a confusing
permissions error half way through a run, netrecon probes once up front and
degrades to connect-scan equivalents with an explicit message.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

#: Bit position of CAP_NET_RAW in the Linux capability bitmask.
CAP_NET_RAW_BIT = 13
CAP_NET_ADMIN_BIT = 12

_STATUS_PATH = Path("/proc/self/status")


def _effective_caps(status_path: Path = _STATUS_PATH) -> int | None:
    """Return the effective capability bitmask, or ``None`` if unreadable."""
    try:
        text = status_path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", text, re.MULTILINE)
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:  # pragma: no cover - kernel would have to be lying
        return None


def has_capability(bit: int, status_path: Path = _STATUS_PATH) -> bool:
    caps = _effective_caps(status_path)
    if caps is None:
        return False
    return bool(caps & (1 << bit))


@dataclass(frozen=True)
class Privileges:
    """What raw-socket work this process is allowed to do."""

    euid: int
    is_root: bool
    cap_net_raw: bool
    cap_net_admin: bool

    @property
    def raw_sockets(self) -> bool:
        return self.is_root or self.cap_net_raw

    @property
    def reason(self) -> str:
        if self.is_root:
            return "running as root (uid 0)"
        if self.cap_net_raw:
            return "CAP_NET_RAW is present in the effective capability set"
        return (
            f"running as uid {self.euid} without CAP_NET_RAW; raw-socket stages "
            "are unavailable"
        )

    def describe(self) -> str:
        state = "available" if self.raw_sockets else "unavailable"
        return f"raw sockets {state} - {self.reason}"

    def to_dict(self) -> dict[str, object]:
        return {
            "euid": self.euid,
            "is_root": self.is_root,
            "cap_net_raw": self.cap_net_raw,
            "cap_net_admin": self.cap_net_admin,
            "raw_sockets": self.raw_sockets,
            "reason": self.reason,
        }


def detect(status_path: Path = _STATUS_PATH) -> Privileges:
    euid = os.geteuid()
    return Privileges(
        euid=euid,
        is_root=euid == 0,
        cap_net_raw=has_capability(CAP_NET_RAW_BIT, status_path),
        cap_net_admin=has_capability(CAP_NET_ADMIN_BIT, status_path),
    )


DEGRADE_MESSAGE = (
    "Raw sockets are not available to this process, so netrecon will degrade to "
    "unprivileged equivalents:\n"
    "  * host discovery      : nmap -sn TCP connect probes instead of ICMP/fping\n"
    "  * fast port sweep     : nmap -sT connect scan instead of masscan SYN scan\n"
    "  * OS detection        : skipped (requires raw packets)\n"
    "Connect scans are slower, noisier in target logs, and see fewer filtered\n"
    "ports. To run the privileged path, re-run under sudo, or grant the binary\n"
    "CAP_NET_RAW (see README: 'Privileges'). In Docker, add --cap-add=NET_RAW\n"
    "--cap-add=NET_ADMIN."
)
