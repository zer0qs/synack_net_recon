"""Parser for nmap XML output.

Only the elements netrecon reports on are modelled.  Unknown elements are
ignored so a newer nmap does not break the run.

Note on XML safety: these files are produced by the nmap process we spawned,
but the parser is still kept to Python's stdlib ``ElementTree``, which does not
resolve external entities.  Nothing here follows DTDs or network references.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class NmapParseError(Exception):
    """The XML was not recognisable nmap output."""


@dataclass
class Service:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None
    cpes: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        """Human-readable ``product version (extrainfo)`` style label."""
        parts = [p for p in (self.product, self.version) if p]
        text = " ".join(parts)
        if self.extrainfo:
            text = f"{text} ({self.extrainfo})" if text else f"({self.extrainfo})"
        if not text:
            return self.name or "unknown"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "tunnel": self.tunnel,
            "method": self.method,
            "confidence": self.confidence,
            "cpes": list(self.cpes),
            "label": self.label,
        }


@dataclass
class Port:
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service: Service | None = None
    scripts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "reason": self.reason,
            "service": self.service.to_dict() if self.service else None,
            "scripts": dict(self.scripts),
        }


@dataclass
class OsMatch:
    name: str
    accuracy: int
    families: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "accuracy": self.accuracy, "families": list(self.families)}


@dataclass
class Host:
    address: str
    address_type: str = "ipv4"
    status: str = "unknown"
    status_reason: str | None = None
    hostnames: tuple[str, ...] = ()
    mac: str | None = None
    vendor: str | None = None
    ports: list[Port] = field(default_factory=list)
    os_matches: list[OsMatch] = field(default_factory=list)
    host_scripts: dict[str, str] = field(default_factory=dict)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def is_up(self) -> bool:
        return self.status == "up"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "address_type": self.address_type,
            "status": self.status,
            "status_reason": self.status_reason,
            "hostnames": list(self.hostnames),
            "mac": self.mac,
            "vendor": self.vendor,
            "ports": [p.to_dict() for p in self.ports],
            "os_matches": [o.to_dict() for o in self.os_matches],
            "host_scripts": dict(self.host_scripts),
        }


@dataclass
class NmapReport:
    hosts: list[Host] = field(default_factory=list)
    args: str | None = None
    version: str | None = None
    start: str | None = None
    elapsed: float | None = None
    exit_status: str | None = None

    @property
    def up_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.is_up]

    def host(self, address: str) -> Host | None:
        for candidate in self.hosts:
            if candidate.address == address:
                return candidate
        return None

    def addresses(self) -> list[str]:
        return [h.address for h in self.hosts]

    def to_dict(self) -> dict[str, Any]:
        return {
            "args": self.args,
            "version": self.version,
            "start": self.start,
            "elapsed": self.elapsed,
            "exit_status": self.exit_status,
            "hosts": [h.to_dict() for h in self.hosts],
        }


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_or_none(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _parse_service(element: ET.Element) -> Service:
    return Service(
        name=element.get("name"),
        product=element.get("product"),
        version=element.get("version"),
        extrainfo=element.get("extrainfo"),
        tunnel=element.get("tunnel"),
        method=element.get("method"),
        confidence=_int_or_none(element.get("conf")),
        cpes=tuple(cpe.text for cpe in element.findall("cpe") if cpe.text),
    )


def _parse_scripts(parent: ET.Element) -> dict[str, str]:
    scripts: dict[str, str] = {}
    for script in parent.findall("script"):
        script_id = script.get("id")
        if not script_id:
            continue
        output = script.get("output")
        if output is None:
            output = "".join(script.itertext())
        scripts[script_id] = (output or "").strip()
    return scripts


def _parse_host(element: ET.Element) -> Host | None:
    address = None
    address_type = "ipv4"
    mac = None
    vendor = None

    for addr in element.findall("address"):
        kind = addr.get("addrtype", "")
        value = addr.get("addr")
        if not value:
            continue
        if kind in {"ipv4", "ipv6"} and address is None:
            address, address_type = value, kind
        elif kind == "mac":
            mac, vendor = value, addr.get("vendor")

    if address is None:
        log.debug("skipping <host> element with no IP address")
        return None

    status_el = element.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"
    status_reason = status_el.get("reason") if status_el is not None else None

    hostnames = tuple(
        name.get("name", "")
        for name in element.findall("hostnames/hostname")
        if name.get("name")
    )

    ports: list[Port] = []
    for port_el in element.findall("ports/port"):
        port_number = _int_or_none(port_el.get("portid"))
        if port_number is None:
            continue
        state_el = port_el.find("state")
        service_el = port_el.find("service")
        ports.append(
            Port(
                port=port_number,
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                reason=state_el.get("reason") if state_el is not None else None,
                service=_parse_service(service_el) if service_el is not None else None,
                scripts=_parse_scripts(port_el),
            )
        )
    ports.sort(key=lambda p: (p.protocol, p.port))

    os_matches = [
        OsMatch(
            name=match.get("name", "unknown"),
            accuracy=_int_or_none(match.get("accuracy")) or 0,
            families=tuple(
                cls.get("osfamily", "")
                for cls in match.findall("osclass")
                if cls.get("osfamily")
            ),
        )
        for match in element.findall("os/osmatch")
    ]
    os_matches.sort(key=lambda m: m.accuracy, reverse=True)

    host_scripts = _parse_scripts(element.find("hostscript") or ET.Element("hostscript"))

    return Host(
        address=address,
        address_type=address_type,
        status=status,
        status_reason=status_reason,
        hostnames=hostnames,
        mac=mac,
        vendor=vendor,
        ports=ports,
        os_matches=os_matches,
        host_scripts=host_scripts,
    )


def parse_nmap_xml(source: str | Path) -> NmapReport:
    """Parse an nmap XML file (or XML string) into a :class:`NmapReport`."""
    try:
        if isinstance(source, Path) or (
            isinstance(source, str) and not source.lstrip().startswith("<")
        ):
            path = Path(source)
            if not path.is_file():
                raise NmapParseError(f"nmap XML not found: {path}")
            root = ET.parse(path).getroot()  # noqa: S314 - stdlib, no entity resolution
        else:
            root = ET.fromstring(source)  # noqa: S314
    except ET.ParseError as exc:
        raise NmapParseError(f"malformed nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError(f"expected <nmaprun> root element, found <{root.tag}>")

    runstats = root.find("runstats/finished")
    hosts = [host for host in (_parse_host(el) for el in root.findall("host")) if host]

    return NmapReport(
        hosts=hosts,
        args=root.get("args"),
        version=root.get("version"),
        start=root.get("startstr") or root.get("start"),
        elapsed=_float_or_none(runstats.get("elapsed")) if runstats is not None else None,
        exit_status=runstats.get("exit") if runstats is not None else None,
    )


def parse_many(paths: Iterable[str | Path]) -> list[NmapReport]:
    """Parse several XML files, logging and skipping the unreadable ones."""
    reports: list[NmapReport] = []
    for path in paths:
        try:
            reports.append(parse_nmap_xml(path))
        except NmapParseError as exc:
            log.warning("skipping unreadable nmap XML %s: %s", path, exc)
    return reports
