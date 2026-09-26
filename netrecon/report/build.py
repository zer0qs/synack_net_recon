"""Stage 8: aggregation and reporting.

Produces ``summary.json`` (machine-readable, the primary artifact) and
``report.md`` (host -> open ports -> service/version -> notable findings).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext
from netrecon.core.state import utc_now

NAME = "report"

#: Services worth calling out explicitly in the report. These are exposure
#: observations for the operator to triage - netrecon does not test them.
NOTABLE_SERVICES: dict[int, str] = {
    21: "FTP - often anonymous or cleartext credentials",
    23: "Telnet - cleartext administrative access",
    69: "TFTP - unauthenticated file transfer",
    111: "rpcbind - RPC service enumeration surface",
    135: "MSRPC endpoint mapper",
    139: "NetBIOS session service",
    445: "SMB - review signing and guest access",
    161: "SNMP - review community strings",
    512: "rexec - cleartext remote execution",
    513: "rlogin - cleartext remote login",
    514: "rsh / syslog",
    623: "IPMI - out-of-band management",
    1433: "Microsoft SQL Server exposed",
    1521: "Oracle TNS listener exposed",
    2049: "NFS - review exports",
    2375: "Docker API without TLS",
    3306: "MySQL exposed",
    3389: "RDP - review NLA and exposure",
    5432: "PostgreSQL exposed",
    5900: "VNC - review authentication",
    5985: "WinRM (HTTP)",
    6379: "Redis - frequently unauthenticated",
    9200: "Elasticsearch - frequently unauthenticated",
    11211: "memcached - frequently unauthenticated and UDP-amplifiable",
    27017: "MongoDB - frequently unauthenticated",
}

CLEARTEXT_SERVICE_NAMES = {"telnet", "ftp", "http", "rsh", "rlogin", "rexec", "snmp", "tftp"}


@dataclass
class HostSummary:
    ip: str
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    os_guess: str | None = None
    hostnames: list[str] = field(default_factory=list)
    mac: str | None = None
    notes: list[str] = field(default_factory=list)
    nuclei_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "mac": self.mac,
            "os_guess": self.os_guess,
            "open_port_count": len(self.open_ports),
            "open_ports": self.open_ports,
            "notes": self.notes,
            "nuclei_findings": self.nuclei_findings,
        }


def build(ctx: RunContext) -> dict[str, Any]:
    """Aggregate every stage artifact into summary.json and report.md."""
    log = ctx.logger(NAME)

    live_hosts = ctx.live_hosts()
    sweep = read_json(ctx.paths.open_ports, default={}) or {}
    services = read_json(ctx.paths.services, default={}) or {}
    nuclei_findings = _load_nuclei(ctx)

    summaries: dict[str, HostSummary] = {}

    # Ports from the sweep are the skeleton; service data enriches them.
    for ip, entries in sorted((sweep.get("hosts") or {}).items()):
        if ip not in live_hosts and live_hosts:
            # Keep going but note the inconsistency: never silently expand.
            log.debug("sweep reported %s which is not in live_hosts.txt", ip)
        summary = summaries.setdefault(ip, HostSummary(ip))
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            summary.open_ports.append(
                {
                    "port": entry.get("port"),
                    "protocol": entry.get("protocol", "tcp"),
                    "state": "open",
                    "service": None,
                    "version": None,
                    "scripts": {},
                }
            )

    for host in services.get("hosts") or []:
        ip = host.get("address")
        if not ip:
            continue
        summary = summaries.setdefault(ip, HostSummary(ip))
        summary.hostnames = list(host.get("hostnames") or [])
        summary.mac = host.get("mac")
        os_matches = host.get("os_matches") or []
        if os_matches:
            best = os_matches[0]
            summary.os_guess = f"{best.get('name')} ({best.get('accuracy')}%)"

        indexed = {
            (p.get("protocol", "tcp"), p.get("port")): p for p in summary.open_ports
        }
        for port in host.get("ports") or []:
            if port.get("state") != "open":
                continue
            key = (port.get("protocol", "tcp"), port.get("port"))
            service = port.get("service") or {}
            record = indexed.get(key)
            if record is None:
                record = {
                    "port": port.get("port"),
                    "protocol": port.get("protocol", "tcp"),
                    "state": "open",
                    "service": None,
                    "version": None,
                    "scripts": {},
                }
                summary.open_ports.append(record)
                indexed[key] = record
            record["service"] = service.get("name")
            record["version"] = service.get("label")
            record["cpes"] = service.get("cpes") or []
            record["tunnel"] = service.get("tunnel")
            record["scripts"] = port.get("scripts") or {}

        if host.get("host_scripts"):
            summary.notes.append(
                f"{len(host['host_scripts'])} host-level NSE script output(s) recorded"
            )

    for finding in nuclei_findings:
        ip = _finding_ip(finding)
        if ip is None:
            continue
        summary = summaries.setdefault(ip, HostSummary(ip))
        info = finding.get("info") or {}
        summary.nuclei_findings.append(
            {
                "template": finding.get("template-id") or finding.get("templateID"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched": finding.get("matched-at") or finding.get("host"),
            }
        )

    # Hosts that answered discovery but showed no open ports still get a row.
    for ip in live_hosts:
        summaries.setdefault(ip, HostSummary(ip))

    for summary in summaries.values():
        summary.open_ports.sort(key=lambda p: (p.get("protocol", "tcp"), p.get("port") or 0))
        summary.notes.extend(_notable_notes(summary))

    ordered = [summaries[ip] for ip in sorted(summaries, key=_ip_sort_key)]
    payload = _summary_payload(ctx, ordered, live_hosts, sweep, services, nuclei_findings)

    write_json(ctx.paths.summary, payload)
    ctx.paths.report.write_text(render_markdown(payload, ordered), encoding="utf-8")

    log.info(
        "report written: %d host(s), %d open port(s), %d notable observation(s)",
        payload["totals"]["hosts_reported"],
        payload["totals"]["open_ports"],
        payload["totals"]["notable_observations"],
    )
    return payload


def _summary_payload(
    ctx: RunContext,
    hosts: list[HostSummary],
    live_hosts: list[str],
    sweep: dict[str, Any],
    services: dict[str, Any],
    nuclei_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    open_ports = sum(len(h.open_ports) for h in hosts)
    notable = sum(len(h.notes) for h in hosts)
    return {
        "generated_at": utc_now(),
        "run": {
            "name": ctx.state.run_name,
            "directory": str(ctx.paths.root),
            "started_at": ctx.state.started_at,
            "netrecon_version": ctx.state.netrecon_version,
            "active_stage_enabled": ctx.active,
            "raw_sockets": ctx.privileges.raw_sockets,
        },
        "scope": ctx.scope.summary(),
        "limits": {
            "sweep_rate_pps": ctx.config.limits.masscan_rate,
            "nuclei_rate_rps": ctx.config.limits.nuclei_rate,
            "concurrency": ctx.config.limits.concurrency,
            "nmap_timing": ctx.config.limits.nmap_timing,
        },
        "stages": {name: stage.to_dict() for name, stage in ctx.state.stages.items()},
        "totals": {
            "in_scope_hosts": len(ctx.scope),
            "live_hosts": len(live_hosts),
            "hosts_reported": len(hosts),
            "hosts_with_open_ports": sum(1 for h in hosts if h.open_ports),
            "open_ports": open_ports,
            "services_identified": services.get("services_identified", 0),
            "nuclei_findings": len(nuclei_findings),
            "notable_observations": notable,
        },
        "sweep_backend": sweep.get("backend"),
        "hosts": [h.to_dict() for h in hosts],
    }


def render_markdown(payload: dict[str, Any], hosts: list[HostSummary]) -> str:
    totals = payload["totals"]
    scope = payload["scope"]
    limits = payload["limits"]
    run = payload["run"]

    lines: list[str] = [
        "# netrecon report",
        "",
        "> Reconnaissance output for an authorised engagement. Findings below are",
        "> observations about exposed services, not verified vulnerabilities.",
        "",
        "## Run",
        "",
        f"- **Run name**: `{run['name']}`",
        f"- **Started (UTC)**: {run['started_at']}",
        f"- **Report generated (UTC)**: {payload['generated_at']}",
        f"- **Output directory**: `{run['directory']}`",
        f"- **Scope file**: `{scope.get('source')}`",
        f"- **Raw sockets**: {'yes' if run['raw_sockets'] else 'no (connect-scan fallback)'}",
        f"- **Active stage (nuclei)**: {'enabled' if run['active_stage_enabled'] else 'disabled'}",
        f"- **Sweep backend**: {payload.get('sweep_backend') or 'n/a'}",
        f"- **Rate caps**: {limits['sweep_rate_pps']} pps sweep, "
        f"{limits['nuclei_rate_rps']} rps nuclei, concurrency {limits['concurrency']}",
        "",
        "## Totals",
        "",
        "| Metric | Count |",
        "| --- | --- |",
        f"| In-scope addresses | {totals['in_scope_hosts']} |",
        f"| Live hosts | {totals['live_hosts']} |",
        f"| Hosts with open ports | {totals['hosts_with_open_ports']} |",
        f"| Open ports | {totals['open_ports']} |",
        f"| Services identified | {totals['services_identified']} |",
        f"| nuclei findings | {totals['nuclei_findings']} |",
        f"| Notable observations | {totals['notable_observations']} |",
        "",
        "## Stage timings",
        "",
        "| Stage | Status | Duration (s) | Detail |",
        "| --- | --- | --- | --- |",
    ]

    for name, stage in payload["stages"].items():
        if name == "report":
            # The reporting stage is still running while this table is rendered;
            # its own timing is recorded in state.json instead.
            continue
        duration = stage.get("duration_seconds")
        lines.append(
            f"| {name} | {stage.get('status')} | "
            f"{duration if duration is not None else '-'} | {stage.get('detail') or ''} |"
        )

    lines += ["", "## Hosts", ""]

    if not hosts:
        lines += ["No hosts responded within the authorised scope.", ""]

    for host in hosts:
        title = host.ip
        if host.hostnames:
            title = f"{host.ip} ({', '.join(host.hostnames)})"
        lines += [f"### {title}", ""]
        if host.os_guess:
            lines.append(f"- **OS guess**: {host.os_guess}")
        if host.mac:
            lines.append(f"- **MAC**: {host.mac}")
        lines.append(f"- **Open ports**: {len(host.open_ports)}")
        lines.append("")

        if host.open_ports:
            lines += [
                "| Port | Proto | Service | Version / banner |",
                "| --- | --- | --- | --- |",
            ]
            for port in host.open_ports:
                lines.append(
                    f"| {port.get('port')} | {port.get('protocol')} | "
                    f"{port.get('service') or '-'} | {_escape(port.get('version'))} |"
                )
            lines.append("")
        else:
            lines += ["No open ports found in the scanned port set.", ""]

        script_rows = [
            (port, name, output)
            for port in host.open_ports
            for name, output in (port.get("scripts") or {}).items()
        ]
        if script_rows:
            lines += ["**NSE script output**", ""]
            for port, name, output in script_rows:
                first = (output or "").strip().splitlines()
                preview = first[0][:200] if first else ""
                lines.append(f"- `{port.get('port')}/{port.get('protocol')}` **{name}**: {preview}")
            lines.append("")

        if host.nuclei_findings:
            lines += ["**nuclei findings**", ""]
            for finding in host.nuclei_findings:
                lines.append(
                    f"- [{finding.get('severity') or 'unknown'}] "
                    f"{finding.get('name') or finding.get('template')} "
                    f"(`{finding.get('matched')}`)"
                )
            lines.append("")

        if host.notes:
            lines += ["**Notable**", ""]
            lines += [f"- {note}" for note in host.notes]
            lines.append("")

    lines += [
        "## Next steps",
        "",
        "- Confirm every host above is inside the engagement's authorised scope.",
        "- Triage the notable observations manually; netrecon performs no",
        "  authentication testing, brute forcing or exploitation.",
        "- Raw tool output is under `nmap/` and `raw/` for verification.",
        "",
    ]
    return "\n".join(lines)


def _notable_notes(host: HostSummary) -> list[str]:
    notes: list[str] = []
    for port in host.open_ports:
        number = port.get("port")
        if number in NOTABLE_SERVICES:
            notes.append(f"`{number}/{port.get('protocol')}` {NOTABLE_SERVICES[number]}")
        service_name = (port.get("service") or "").lower()
        if service_name in CLEARTEXT_SERVICE_NAMES and number not in NOTABLE_SERVICES:
            notes.append(
                f"`{number}/{port.get('protocol')}` {service_name} may carry "
                "credentials in cleartext"
            )
    if len(host.open_ports) >= 20:
        notes.append(
            f"{len(host.open_ports)} open ports - unusually broad exposure for one host"
        )
    return notes


def _load_nuclei(ctx: RunContext) -> list[dict[str, Any]]:
    import json

    path = ctx.paths.nuclei
    if not path.is_file():
        return []
    findings: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            findings.append(record)
    return findings


def _finding_ip(finding: dict[str, Any]) -> str | None:
    import ipaddress

    for key in ("ip", "host", "matched-at"):
        value = finding.get(key)
        if not value:
            continue
        text = str(value)
        for candidate in (text, text.split(":")[0], text.strip("[]").split("]")[0]):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return None


def _ip_sort_key(ip: str) -> tuple[int, int, str]:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0, ip)
    return (addr.version, int(addr), ip)


def _escape(value: Any) -> str:
    if value is None:
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def stage_counts(payload: dict[str, Any]) -> dict[str, int]:
    totals = payload["totals"]
    return {
        "hosts_reported": totals["hosts_reported"],
        "open_ports": totals["open_ports"],
        "notable_observations": totals["notable_observations"],
    }


def notable_iter(hosts: Iterable[HostSummary]) -> Iterable[str]:
    for host in hosts:
        for note in host.notes:
            yield f"{host.ip}: {note}"
