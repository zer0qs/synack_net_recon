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
    except json.JSONDecodeError:
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
        except json.JSONDecodeError:
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
        for port_entry in record.get("ports") or []:
            if not isinstance(port_entry, dict):
                continue
            port = port_entry.get("port")
            if not isinstance(port, int):
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


_LIST_RE = re.compile(
    r"^(?P<state>open|closed)\s+(?P<proto>\w+)\s+(?P<port>\d+)\s+(?P<ip>[0-9a-fA-F:.]+)"
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
        except json.JSONDecodeError:
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
        if not isinstance(port_field, int):
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


def _read(source: str | Path) -> str:
    if isinstance(source, Path):
        if not source.is_file():
            log.warning("output file missing: %s", source)
            return ""
        return source.read_text(encoding="utf-8", errors="replace")
    text = str(source)
    candidate = Path(text) if len(text) < 4096 and "\n" not in text else None
    if candidate is not None and candidate.is_file():
        return candidate.read_text(encoding="utf-8", errors="replace")
    return text
