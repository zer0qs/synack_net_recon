"""SNMP analysis: an agent that answers is a read-only shell on the device.

SNMP is a management protocol that was never designed to be exposed. When an
agent answers a community-string query it will usually describe the operating
system, every interface and address it has, the processes it is running and the
software installed - enough to map an internal network and pick targets without
sending a packet to any of them. nmap's ``snmp-*`` scripts query with the
default community ``public``, so output coming back at all is itself the
finding.

The analyzer only reports what the script output supports. An open 161/udp with
no script data proves nothing (UDP ports are reported open on no response at
all), so it produces no high finding here.
"""

from __future__ import annotations

import re
from typing import Any

from netrecon.analyze.base import Finding, ServiceEvidence

#: nmap service names for an SNMP agent or trap listener.
SNMP_SERVICE_NAMES: frozenset[str] = frozenset({"snmp", "snmptrap"})

SNMP_PORTS: frozenset[int] = frozenset({161, 162})

#: Caps on list data copied into ``data``; full output stays in scripts.json.
MAX_INTERFACES = 30
MAX_ITEMS = 40

#: SNMPv1 and v2c send the community string in cleartext; v3 is not matched.
_LEGACY_VERSION = re.compile(r"\bsnmpv(?:1|2c?)\b", re.IGNORECASE)

# Lines a failed or refused query leaves behind; never device data.
_ERROR_PREFIXES: tuple[str, ...] = (
    "error",
    "false",
    "no response",
    "timeout",
    "request timed out",
    "snmp request failed",
    "could not",
    "failed",
)

_KEY_VALUE = re.compile(r"^([A-Za-z][A-Za-z0-9 _.\-]*?)\s*:\s*(.+)$")

_UPTIME = re.compile(r"(?i)\b(?:system\s+)?uptime\s*:\s*(.+)$")

_NETSTAT_ROW = re.compile(r"^(TCP|UDP)\s+(\S+)\s+(\S+)", re.IGNORECASE)

_PID_HEADER = re.compile(r"^(\d+)\s*:?$")

#: snmp-info keys that only a responding agent can produce.
_INFO_KEYS: frozenset[str] = frozenset(
    {"enterprise", "engineidformat", "engineiddata", "snmpengineboots", "snmpenginetime"}
)


class SnmpAnalyzer:
    """Findings from ``snmp-*`` NSE output and the ``-sV`` banner."""

    name = "snmp"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        service = (evidence.service or "").strip().lower()
        if service in SNMP_SERVICE_NAMES:
            return True
        if _ran_snmp_script(evidence):
            return True
        return evidence.port in SNMP_PORTS

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        description, uptime = _parse_sysdescr(evidence.script("snmp-sysdescr"))
        info = _parse_info(evidence.script("snmp-info"))

        findings: list[Finding] = []
        findings.extend(_readable_findings(evidence, description, uptime, info))
        findings.extend(_system_findings(evidence, description, uptime, info))
        findings.extend(_interface_findings(evidence))
        findings.extend(_process_findings(evidence))
        findings.extend(_software_findings(evidence))
        findings.extend(_version_findings(evidence))
        return findings


# -- individual findings -------------------------------------------------


def _readable_findings(
    evidence: ServiceEvidence,
    description: str | None,
    uptime: str | None,
    info: dict[str, str],
) -> list[Finding]:
    """High: data came back, so the community string nmap used was accepted."""
    quoted: list[str] = []
    sources: list[str] = []
    if description:
        sources.append("snmp-sysdescr")
        quoted.append(description)
        if uptime:
            quoted.append(f"System uptime: {uptime}")
    if info:
        sources.append("snmp-info")
        quoted.extend(f"{key}: {value}" for key, value in info.items())
    if not quoted:
        return []

    community = (evidence.extrainfo or "").strip()
    return [
        Finding(
            key="snmp.readable-with-default-community",
            title="SNMP agent readable with a default community string",
            severity="high",
            summary=(
                "The agent returned device data to an unauthenticated query. nmap's "
                "snmp scripts read with the community string 'public' unless told "
                "otherwise, so a reply means a default (or otherwise guessable) "
                "community is accepted for read access. Everything the agent's MIB "
                "covers - interfaces, routes, processes, installed software, sometimes "
                "configuration - is readable by anyone who can reach this port."
            ),
            evidence=_quote(quoted, 8),
            recommendation=(
                "Treat this as a credentialed read of the device: confirm which "
                "community strings are configured, replace defaults, restrict the agent "
                "to known management sources by ACL and firewall, and move to SNMPv3 "
                "with authPriv. Disable the agent where nothing consumes it."
            ),
            source=", ".join(sources),
            data={"community_used": community or "public (nmap default)"},
        )
    ]


def _system_findings(
    evidence: ServiceEvidence,
    description: str | None,
    uptime: str | None,
    info: dict[str, str],
) -> list[Finding]:
    """Info: the system identity the agent disclosed, for inventory."""
    extra = _system_fields(evidence)
    data: dict[str, Any] = {
        "sysdescr": description,
        "uptime": uptime,
        "contact": extra.get("contact"),
        "location": extra.get("location"),
        "system_name": extra.get("name"),
        "enterprise": info.get("enterprise"),
    }
    data = {key: value for key, value in data.items() if value}
    if not data:
        return []
    quoted = [f"{key}: {value}" for key, value in data.items()]
    return [
        Finding(
            key="snmp.system-information",
            title="System information disclosed over SNMP",
            severity="info",
            summary=(
                "The agent named the platform and, where configured, its contact and "
                "location. This identifies the device and its OS build for inventory; "
                "review the disclosed version against vendor advisories rather than "
                "treating the string itself as a weakness."
            ),
            evidence=_quote(quoted, 8),
            recommendation=(
                "Where SNMP must stay enabled, keep sysContact and sysLocation free of "
                "names, phone numbers and rack-level detail that assists social "
                "engineering or physical access."
            ),
            source="snmp-sysdescr, snmp-info",
            data=data,
        )
    ]


def _interface_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Medium: interface and socket tables map the network behind the host."""
    interfaces = _parse_interfaces(evidence.script("snmp-interfaces"))
    endpoints = _parse_netstat(evidence.script("snmp-netstat"))
    if not interfaces and not endpoints:
        return []

    sources: list[str] = []
    quoted: list[str] = []
    if interfaces:
        sources.append("snmp-interfaces")
        quoted.extend(_describe_interface(iface) for iface in interfaces)
    if endpoints:
        sources.append("snmp-netstat")
        quoted.extend(endpoints)

    addresses = sorted({address for iface in interfaces for address in iface.get("addresses", [])})
    return [
        Finding(
            key="snmp.interfaces-disclosed",
            title="Network interfaces and addresses enumerable over SNMP",
            severity="medium",
            summary=(
                f"{len(interfaces)} interface(s) and {len(endpoints)} socket table entry(ies) "
                "were readable. This hands over the host's own addressing and, through its "
                "other interfaces and connections, the internal networks it reaches - a map "
                "of segments an outside querier should not be able to see, including "
                "management networks and the addresses of peers worth attacking next."
            ),
            evidence=_quote(quoted, 10),
            recommendation=(
                "Restrict the agent to management sources, limit the exposed MIB view to "
                "what monitoring actually reads, and verify this host is not bridging a "
                "management segment to an untrusted one."
            ),
            source=", ".join(sources),
            data={
                "interfaces": interfaces[:MAX_INTERFACES],
                "interface_count": len(interfaces),
                "addresses": addresses[:MAX_INTERFACES],
                "socket_entries": endpoints[:MAX_ITEMS],
                "socket_entry_count": len(endpoints),
                "truncated": len(interfaces) > MAX_INTERFACES or len(endpoints) > MAX_ITEMS,
            },
        )
    ]


def _process_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Medium: the running process list, with paths and arguments."""
    processes = _parse_processes(evidence.script("snmp-processes"))
    if not processes:
        return []
    return [
        Finding(
            key="snmp.processes-disclosed",
            title="Running processes enumerable over SNMP",
            severity="medium",
            summary=(
                f"{len(processes)} running process(es) were readable, with paths and in some "
                "cases command-line arguments. That reveals which security agents and "
                "services are present (and which are not), and arguments passed on a "
                "command line occasionally carry credentials."
            ),
            evidence=_quote(processes, 10),
            recommendation=(
                "Restrict the agent to known management sources and exclude the host "
                "resources MIB from the view SNMP exposes."
            ),
            source="snmp-processes",
            data={
                "processes": processes[:MAX_ITEMS],
                "process_count": len(processes),
                "truncated": len(processes) > MAX_ITEMS,
            },
        )
    ]


def _software_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Medium: the installed software inventory, patch levels included."""
    software = _parse_lines(evidence.script("snmp-win32-software"))
    if not software:
        return []
    return [
        Finding(
            key="snmp.software-disclosed",
            title="Installed software enumerable over SNMP",
            severity="medium",
            summary=(
                f"{len(software)} installed product(s) were readable, including update and "
                "hotfix entries. An outside reader can therefore work out the patch level "
                "of this host without touching it; review the listed versions against "
                "vendor advisories."
            ),
            evidence=_quote(software, 10),
            recommendation=(
                "Restrict the agent to management sources and narrow the exposed MIB view; "
                "an installed-software inventory should not be world-readable."
            ),
            source="snmp-win32-software",
            data={
                "software": software[:MAX_ITEMS],
                "software_count": len(software),
                "truncated": len(software) > MAX_ITEMS,
            },
        )
    ]


def _version_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Medium: v1/v2c, reported only when the banner actually says so."""
    banner = evidence.banner
    match = _LEGACY_VERSION.search(banner)
    if not match:
        return []
    community = (evidence.extrainfo or "").strip()
    return [
        Finding(
            key="snmp.v1-v2c",
            title=f"SNMP {match.group(0)} in use",
            severity="medium",
            summary=(
                "The service identified itself as SNMPv1/v2c. Those versions authenticate "
                "with a community string sent in cleartext and provide no integrity "
                "protection, so anyone able to observe or inject traffic on the path can "
                "recover the string and reuse it."
            ),
            evidence=banner,
            recommendation=(
                "Move monitoring to SNMPv3 with authentication and privacy (authPriv), and "
                "while v1/v2c remains, restrict it to a management VLAN by ACL."
            ),
            source="nmap -sV",
            data={"community_seen": community} if community else {},
        )
    ]


# -- parsing -------------------------------------------------------------


def _ran_snmp_script(evidence: ServiceEvidence) -> bool:
    return any(
        key.lower().startswith("snmp-")
        for key in (*evidence.scripts, *evidence.host_scripts)
    )


def _looks_like_data(text: str | None) -> bool:
    """True when a line carries device data rather than a failure note."""
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 2 or not any(char.isalnum() for char in stripped):
        return False
    return not stripped.lower().startswith(_ERROR_PREFIXES)


def _parse_sysdescr(output: str | None) -> tuple[str | None, str | None]:
    """``(sysDescr, uptime)`` from snmp-sysdescr, or ``(None, None)``."""
    if not output:
        return None, None
    description: str | None = None
    uptime: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _UPTIME.search(line)
        if match:
            uptime = match.group(1).strip()
            continue
        if description is None and _looks_like_data(line):
            description = line
    return description, uptime


def _parse_info(output: str | None) -> dict[str, str]:
    """snmp-info engine fields, keeping only keys the script defines."""
    fields: dict[str, str] = {}
    for key, value in _key_values(output).items():
        if key.replace(" ", "").lower() in _INFO_KEYS and _looks_like_data(value):
            fields[key] = value
    return fields


def _system_fields(evidence: ServiceEvidence) -> dict[str, str]:
    """sysContact/sysLocation/sysName, wherever an snmp script reported them."""
    wanted = {"contact": "contact", "location": "location", "name": "name"}
    found: dict[str, str] = {}
    for script_id in ("snmp-sysdescr", "snmp-info"):
        for key, value in _key_values(evidence.script(script_id)).items():
            normalised = key.strip().lower().removeprefix("sys")
            if normalised in wanted and _looks_like_data(value):
                found.setdefault(wanted[normalised], value)
    return found


def _key_values(output: str | None) -> dict[str, str]:
    """``key: value`` pairs from an indented NSE block, first value wins."""
    fields: dict[str, str] = {}
    if not output:
        return fields
    for raw in output.splitlines():
        match = _KEY_VALUE.match(raw.strip())
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        if key and value:
            fields.setdefault(key, value)
    return fields


def _parse_interfaces(output: str | None) -> list[dict[str, Any]]:
    """Interface blocks from snmp-interfaces: a name, then indented fields."""
    interfaces: list[dict[str, Any]] = []
    if not output:
        return interfaces
    current: dict[str, Any] | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _KEY_VALUE.match(line)
        if match and current is not None:
            key = match.group(1).strip().lower()
            value = match.group(2).strip()
            if key.endswith("address") and "mac" in key:
                current["mac"] = value
            elif key.endswith("address"):
                # "192.168.221.128  Netmask: 255.255.255.0" - keep the address.
                current.setdefault("addresses", []).append(value.split()[0])
            else:
                current.setdefault("details", []).append(line)
            continue
        if match:
            # A field before any interface name: truncated output, skip it.
            continue
        # A bare line names a new interface.
        current = {"name": line, "addresses": []}
        interfaces.append(current)
    return [iface for iface in interfaces if _looks_like_data(iface["name"])]


def _describe_interface(interface: dict[str, Any]) -> str:
    parts = [str(interface.get("name", "")).strip()]
    addresses = interface.get("addresses") or []
    if addresses:
        parts.append(", ".join(str(address) for address in addresses))
    if interface.get("mac"):
        parts.append(str(interface["mac"]))
    return " ".join(part for part in parts if part)


def _parse_netstat(output: str | None) -> list[str]:
    """``TCP local remote`` rows from snmp-netstat, as flat strings."""
    rows: list[str] = []
    if not output:
        return rows
    for raw in output.splitlines():
        line = raw.strip()
        match = _NETSTAT_ROW.match(line)
        if match:
            rows.append(" ".join(line.split()))
    return rows


def _parse_processes(output: str | None) -> list[str]:
    """``pid name path`` strings from snmp-processes."""
    processes: list[str] = []
    if not output:
        return processes
    pid: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        header = _PID_HEADER.match(line)
        if header:
            pid = header.group(1)
            continue
        match = _KEY_VALUE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key != "name" or not _looks_like_data(value):
            continue
        processes.append(f"{pid}: {value}" if pid else value)
    return processes


def _parse_lines(output: str | None) -> list[str]:
    """Every non-empty data line, for scripts that just list entries."""
    if not output:
        return []
    return [
        line.strip()
        for line in output.splitlines()
        if line.strip() and _looks_like_data(line)
    ]


def _quote(lines: list[str], limit: int) -> str:
    """Quote at most *limit* lines, saying how many were left out."""
    shown = lines[:limit]
    remaining = len(lines) - len(shown)
    if remaining > 0:
        shown = [*shown, f"... (+{remaining} more)"]
    return "\n".join(shown)
