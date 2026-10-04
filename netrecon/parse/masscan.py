"""Parsers for masscan and naabu output.

Both tools are tolerant about what they emit - masscan's JSON is a
comma-separated stream that may be truncated if it is interrupted, and its list
format is line-oriented.  These parsers are deliberately forgiving: a damaged
record is skipped with a warning rather than aborting a run whose expensive
scan already completed.

Every parser returns bare ``OpenPort`` records.  Scope filtering happens in the
calling stage via ``Scope.enforce`` - nothing here is trusted to be in scope.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpenPort:
    ip: str
    port: int
    protocol: str = "tcp"
    reason: str | None = None
    ttl: int | None = None
    source: str = "masscan"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "reason": self.reason,
            "ttl": self.ttl,
            "source": self.source,
        }


#: Scanners never report a port outside this range; anything else is damaged
#: or tampered-with output, and "port 70000 is open" would be a fabricated
#: finding rather than a parse of what the host said.
PORT_RANGE = range(0, 65536)


def _dedupe(ports: Iterable[OpenPort]) -> list[OpenPort]:
    seen: set[tuple[str, int, str]] = set()
    unique: list[OpenPort] = []
    for entry in ports:
        key = (entry.ip, entry.port, entry.protocol)
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    unique.sort(key=lambda p: (p.ip, p.protocol, p.port))
    return unique


def _iter_json_records(text: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from masscan's ``-oJ`` output.

    Handles the well-formed array case, the common ``{...},\\n{...},`` stream
    and a truncated file from an interrupted scan.
    """
    stripped = text.strip()
    if not stripped:
        return

    try:
        loaded = json.loads(stripped)
    # RecursionError, not JSONDecodeError, is what deeply nested brackets raise:
    # 20 000 of them in one line of tool output used to abort the run.
    except (json.JSONDecodeError, RecursionError):
        pass
    else:
        records = loaded if isinstance(loaded, list) else [loaded]
        for record in records:
            if isinstance(record, dict):
                yield record
        return

    # Fall back to a per-record scan, which survives truncation.
    decoder = json.JSONDecoder()
    index = 0
    length = len(stripped)
    while index < length:
        char = stripped[index]
        if char in "[],\n\r\t ":
            index += 1
            continue
        try:
            record, offset = decoder.raw_decode(stripped, index)
        except (json.JSONDecodeError, RecursionError):
            log.warning("skipping malformed JSON record at offset %d", index)
            newline = stripped.find("\n", index)
            if newline == -1:
                return
            index = newline + 1
            continue
        if isinstance(record, dict):
            yield record
        index = offset


def parse_masscan_json(source: str | Path) -> list[OpenPort]:
    """Parse ``masscan -oJ`` output into open-port records."""
    text = _read(source)
    results: list[OpenPort] = []

    for record in _iter_json_records(text):
        ip = record.get("ip")
        if not ip:
            continue  # masscan writes a trailing {"finished": 1} style record
        entries = record.get("ports")
        # "ports" has been seen as a string, a number and null in damaged
        # output; only a list is iterable in the way this loop needs.
        if not isinstance(entries, list):
            continue
        for port_entry in entries:
            if not isinstance(port_entry, dict):
                continue
            port = port_entry.get("port")
            if not isinstance(port, int) or isinstance(port, bool):
                continue
            if port not in PORT_RANGE:
                continue
            if str(port_entry.get("status", "open")).lower() != "open":
                continue
            results.append(
                OpenPort(
                    ip=str(ip),
                    port=port,
                    protocol=str(port_entry.get("proto", "tcp")).lower(),
                    reason=port_entry.get("reason"),
                    ttl=port_entry.get("ttl") if isinstance(port_entry.get("ttl"), int) else None,
                    source="masscan",
                )
            )

    return _dedupe(results)


#: The port group is bounded to five digits: ``int()`` refuses a string of
#: more than 4300 digits outright (CVE-2020-10735 hardening), so an unbounded
#: ``\d+`` turns one absurd line of tool output into an uncaught ValueError.
_LIST_RE = re.compile(
    r"^(?P<state>open|closed)\s+(?P<proto>\w{1,16})\s+(?P<port>\d{1,5})\s+(?P<ip>[0-9a-fA-F:.]{1,45})"
)


def parse_masscan_list(source: str | Path) -> list[OpenPort]:
    """Parse ``masscan -oL`` output (``open tcp 80 10.0.0.1 1700000000``)."""
    results: list[OpenPort] = []
    for line in _read(source).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LIST_RE.match(line)
        if not match or match.group("state") != "open":
            continue
        if int(match.group("port")) not in PORT_RANGE:
            continue
        results.append(
            OpenPort(
                ip=match.group("ip"),
                port=int(match.group("port")),
                protocol=match.group("proto").lower(),
                source="masscan",
            )
        )
    return _dedupe(results)


def parse_naabu_json(source: str | Path) -> list[OpenPort]:
    """Parse naabu's JSON-lines output.

    naabu has used both ``{"ip": ..., "port": 80}`` and a nested
    ``{"ip": ..., "port": {"Port": 80, "Protocol": "TCP"}}`` shape; both are
    accepted here.
    """
    results: list[OpenPort] = []
    for lineno, line in enumerate(_read(source).splitlines(), start=1):
        line = line.strip().rstrip(",")
        if not line or line in {"[", "]"}:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            log.warning("skipping malformed naabu record on line %d", lineno)
            continue
        if not isinstance(record, dict):
            continue

        ip = record.get("ip") or record.get("host")
        if not ip:
            continue

        port_field = record.get("port")
        protocol = str(record.get("protocol") or "tcp").lower()
        if isinstance(port_field, dict):
            protocol = str(port_field.get("Protocol") or protocol).lower()
            port_field = port_field.get("Port")
        if isinstance(port_field, str) and port_field.isdigit():
            port_field = int(port_field)
        if not isinstance(port_field, int) or isinstance(port_field, bool):
            continue
        if port_field not in PORT_RANGE:
            continue

        results.append(
            OpenPort(ip=str(ip), port=port_field, protocol=protocol, source="naabu")
        )
    return _dedupe(results)


def group_by_host(ports: Iterable[OpenPort]) -> dict[str, list[OpenPort]]:
    grouped: dict[str, list[OpenPort]] = {}
    for entry in ports:
        grouped.setdefault(entry.ip, []).append(entry)
    for entries in grouped.values():
        entries.sort(key=lambda p: (p.protocol, p.port))
    return dict(sorted(grouped.items()))


def port_spec(ports: Iterable[OpenPort], protocol: str = "tcp") -> str:
    """Comma-separated port list for feeding back into nmap."""
    numbers = sorted({p.port for p in ports if p.protocol == protocol})
    return ",".join(str(n) for n in numbers)


def _is_readable_file(path: Path) -> bool:
    """``path.is_file()`` that never raises.

    ``is_file()`` propagates ``OSError`` for a name the filesystem rejects
    outright - ``ENAMETOOLONG`` for a component over 255 bytes - and
    ``ValueError`` for an embedded null byte. Tool output handed in as a string
    reaches this check, so a single long line of scanner garbage must read as
    "not a file" rather than abort the run.
    """
    try:
        return path.is_file()
    except (OSError, ValueError):
        return False


def _read(source: str | Path) -> str:
    if isinstance(source, Path):
        if not _is_readable_file(source):
            log.warning("output file missing: %s", source)
            return ""
        return _read_file(source)
    text = str(source)
    candidate = Path(text) if len(text) < 4096 and "\n" not in text else None
    if candidate is not None and _is_readable_file(candidate):
        return _read_file(candidate)
    return text


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("output file %s could not be read: %s", path, exc)
        return ""
