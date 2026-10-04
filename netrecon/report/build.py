"""Stage 8: aggregation and reporting.

Produces, from every earlier stage's checkpoint:

* ``summary.json`` - machine-readable, the primary artifact
* ``report.md``    - host -> open ports -> service/version -> notable findings
* ``report.html``  - the same data plus a per-service-category view and the web
  recon results, as one self-contained page
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext
from netrecon.core.state import utc_now
from netrecon.report import categories as categories_mod
from netrecon.report.html import render_html

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
    web_endpoints: list[dict[str, Any]] = field(default_factory=list)
    service_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "mac": self.mac,
            "os_guess": self.os_guess,
            "open_port_count": len(self.open_ports),
            "open_ports": self.open_ports,
            "categories": sorted(
                {
                    categories_mod.categorise(p.get("service"), p.get("port"))
                    for p in self.open_ports
                }
            ),
            "notes": self.notes,
            "nuclei_findings": self.nuclei_findings,
            "web_endpoints": self.web_endpoints,
            "service_findings": self.service_findings,
        }


@dataclass
class Artifacts:
    """Everything the report is built from, as plain data.

    Collecting this is I/O; turning it into a report is not. Keeping the two
    apart means :func:`aggregate` is a pure function that a test can call with
    a literal dict, which is the only way the aggregation logic gets covered
    properly - it is where the cross-stage reasoning lives.
    """

    live_hosts: list[str] = field(default_factory=list)
    sweep: dict[str, Any] = field(default_factory=dict)
    services: dict[str, Any] = field(default_factory=dict)
    nuclei_findings: list[dict[str, Any]] = field(default_factory=list)
    webrecon: dict[str, Any] = field(default_factory=dict)
    service_findings: dict[str, Any] = field(default_factory=dict)
    #: Addresses the run was authorised to touch. Used to re-filter artifacts
    #: on read, so a hand-edited checkpoint cannot introduce a host.
    in_scope: frozenset[str] = frozenset()
    #: Run metadata, already reduced to plain values by :func:`collect`.
    run: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, Any] = field(default_factory=dict)
    stages: dict[str, Any] = field(default_factory=dict)


@dataclass
class Aggregate:
    """The result of aggregation: the payload plus the objects renderers need."""

    payload: dict[str, Any]
    hosts: list[HostSummary]
    categories: list[categories_mod.Category]


def collect(ctx: RunContext) -> Artifacts:
    """Read every stage artifact off disk. This is the only I/O step."""
    return Artifacts(
        live_hosts=ctx.live_hosts(),
        sweep=read_json(ctx.paths.open_ports, default={}) or {},
        services=read_json(ctx.paths.services, default={}) or {},
        nuclei_findings=_load_jsonl(ctx.paths.nuclei),
        webrecon=_load_webrecon(ctx),
        service_findings=read_json(ctx.paths.service_findings, default={}) or {},
        in_scope=frozenset(str(address) for address in ctx.scope.addresses),
        run={
            "name": ctx.state.run_name,
            "directory": str(ctx.paths.root),
            "started_at": ctx.state.started_at,
            "netrecon_version": ctx.state.netrecon_version,
            "active_stage_enabled": ctx.active,
            "web_stage_enabled": ctx.web,
            "raw_sockets": ctx.privileges.raw_sockets,
        },
        scope=ctx.scope.summary(),
        limits={
            "sweep_rate_pps": ctx.config.limits.masscan_rate,
            "nuclei_rate_rps": ctx.config.limits.nuclei_rate,
            "concurrency": ctx.config.limits.concurrency,
            "nmap_timing": ctx.config.limits.nmap_timing,
            "webrecon_rate_rps": ctx.config.webrecon.rate_per_second if ctx.web else None,
        },
        stages={name: stage.to_dict() for name, stage in ctx.state.stages.items()},
    )


def aggregate(artifacts: Artifacts) -> Aggregate:
    """Turn collected artifacts into the report payload.

    Pure: no file access, no clock beyond the generated-at stamp, no network.
    Every cross-stage decision the report makes happens here.
    """
    summaries: dict[str, HostSummary] = {}
    in_scope = artifacts.in_scope

    def authorised(ip: str | None) -> bool:
        """Whether this address may appear in the report at all.

        Every artifact is re-filtered on read, not just the ones produced by a
        stage that talks to the network. A stale or hand-edited services.json
        naming a host the run was never authorised to touch must not be able to
        put that host in the deliverable - that is the invariant the rest of
        the codebase enforces, and the report is the last place it can be lost.
        An empty in-scope set means "not known" (``netrecon report`` on a run
        with no scope snapshot) and disables the filter rather than dropping
        everything.
        """
        return bool(ip) and (not in_scope or ip in in_scope)

    live_hosts = [ip for ip in artifacts.live_hosts if authorised(ip)]

    # Ports from the sweep are the skeleton; service data enriches them.
    sweep_hosts = artifacts.sweep.get("hosts")
    for ip, entries in sorted((sweep_hosts or {}).items() if isinstance(sweep_hosts, dict) else []):
        if not authorised(ip):
            continue
        summary = summaries.setdefault(ip, HostSummary(ip))
        for entry in entries or []:
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

    for host in artifacts.services.get("hosts") or []:
        if not isinstance(host, dict):
            continue
        ip = host.get("address")
        if not authorised(ip):
            continue
        summary = summaries.setdefault(ip, HostSummary(ip))
        summary.hostnames = list(host.get("hostnames") or [])
        summary.mac = host.get("mac")
        os_matches = host.get("os_matches") or []
        if os_matches:
            best = os_matches[0]
            summary.os_guess = f"{best.get('name')} ({best.get('accuracy')}%)"

        indexed = {(p.get("protocol", "tcp"), p.get("port")): p for p in summary.open_ports}
        for port in host.get("ports") or []:
            if not isinstance(port, dict) or port.get("state") != "open":
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

    for finding in artifacts.nuclei_findings:
        if not isinstance(finding, dict):
            continue
        ip = _finding_ip(finding)
        if not authorised(ip):
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

    # Web recon and analyzer findings are re-filtered through the scope here:
    # a hand-edited checkpoint must not be able to introduce a host.
    for result in artifacts.webrecon.get("results") or []:
        if not isinstance(result, dict):
            continue
        ip = result.get("ip")
        if not authorised(ip):
            continue
        summaries.setdefault(ip, HostSummary(ip)).web_endpoints.append(
            _web_endpoint_digest(result)
        )

    from netrecon.stages.servicerecon import findings_by_host

    for ip, findings in findings_by_host(artifacts.service_findings).items():
        if not authorised(ip):
            continue
        summaries.setdefault(ip, HostSummary(ip)).service_findings = findings

    # Hosts that answered discovery but showed no open ports still get a row.
    for ip in live_hosts:
        summaries.setdefault(ip, HostSummary(ip))

    for summary in summaries.values():
        summary.open_ports.sort(key=lambda p: (p.get("protocol", "tcp"), p.get("port") or 0))
        summary.notes.extend(_notable_notes(summary))
        summary.notes.extend(_web_notes(summary))
        summary.notes.extend(_finding_notes(summary))

    ordered = [summaries[ip] for ip in sorted(summaries, key=_ip_sort_key)]
    categories = categories_mod.group_by_category(ordered)
    payload = _summary_payload(artifacts, ordered, categories)
    return Aggregate(payload, ordered, categories)


def build(ctx: RunContext) -> dict[str, Any]:
    """Collect, aggregate and render. The I/O shell around :func:`aggregate`."""
    log = ctx.logger(NAME)

    result = aggregate(collect(ctx))
    payload, ordered, categories = result.payload, result.hosts, result.categories

    write_json(ctx.paths.summary, payload)
    ctx.paths.report.write_text(render_markdown(payload, ordered, categories), encoding="utf-8")
    ctx.paths.report_html.write_text(
        render_html(
            payload,
            ordered,
            categories,
            read_json(ctx.paths.webrecon, default={}) or {},
            read_json(ctx.paths.service_findings, default={}) or {},
        ),
        encoding="utf-8",
    )

    log.info(
        "report written: %d host(s), %d open port(s), %d category/ies, "
        "%d notable observation(s)",
        payload["totals"]["hosts_reported"],
        payload["totals"]["open_ports"],
        len(categories),
        payload["totals"]["notable_observations"],
    )
    return payload


def _summary_payload(
    artifacts: Artifacts,
    hosts: list[HostSummary],
    categories: list[categories_mod.Category],
) -> dict[str, Any]:
    open_ports = sum(len(h.open_ports) for h in hosts)
    notable = sum(len(h.notes) for h in hosts)
    webrecon = artifacts.webrecon
    service_findings = artifacts.service_findings
    web_results = [r for r in (webrecon.get("results") or []) if isinstance(r, dict)]
    return {
        "generated_at": utc_now(),
        "run": dict(artifacts.run),
        "scope": dict(artifacts.scope),
        "limits": dict(artifacts.limits),
        "stages": dict(artifacts.stages),
        "totals": {
            "in_scope_hosts": artifacts.scope.get("total_hosts", len(artifacts.in_scope)),
            "live_hosts": len(artifacts.live_hosts),
            "hosts_reported": len(hosts),
            "hosts_with_open_ports": sum(1 for h in hosts if h.open_ports),
            "open_ports": open_ports,
            "services_identified": artifacts.services.get("services_identified", 0),
            "nuclei_findings": len(artifacts.nuclei_findings),
            "notable_observations": notable,
            "service_categories": len(categories),
            "web_endpoints": len([r for r in web_results if not r.get("error")]),
            "js_scripts_analysed": webrecon.get("scripts_analysed", 0),
            "js_endpoints": webrecon.get("js_endpoints_found", 0),
            "js_secret_candidates": webrecon.get("secret_candidates", 0),
            "js_pii_candidates": webrecon.get("pii_candidates", 0),
            "paths_accessible": webrecon.get("paths_accessible", 0),
            "technologies": len(webrecon.get("technologies") or []),
            "cve_matches": webrecon.get("cve_matches", 0),
            "hosts_referenced": len(webrecon.get("hosts_referenced") or []),
            "api_endpoints": webrecon.get("api_endpoints", 0),
            "api_parameters": webrecon.get("api_parameters", 0),
            "service_findings": service_findings.get("findings", 0),
        },
        "service_findings": {
            "by_severity": service_findings.get("by_severity") or {},
            "by_analyzer": service_findings.get("by_analyzer") or {},
            "analyzers": service_findings.get("analyzers") or [],
            "total": service_findings.get("findings", 0),
        },
        "web": {
            "technologies": webrecon.get("technologies") or [],
            "hosts_referenced": webrecon.get("hosts_referenced") or [],
            "high_value_paths": webrecon.get("high_value_paths") or [],
            "api_structure": webrecon.get("api_structure") or {},
            "parameters": webrecon.get("parameters") or [],
        },
        "sweep_backend": artifacts.sweep.get("backend"),
        "categories": [c.to_dict() for c in categories],
        "hosts": [h.to_dict() for h in hosts],
    }


def render_markdown(
    payload: dict[str, Any],
    hosts: list[HostSummary],
    categories: list[categories_mod.Category] | None = None,
) -> str:
    # Read defensively throughout. `netrecon report` is routinely pointed at an
    # older or partially written run directory, and a missing metadata key must
    # not destroy the deliverable the scan was run to produce.
    totals = payload.get("totals") or {}
    scope = payload.get("scope") or {}
    limits = payload.get("limits") or {}
    run = payload.get("run") or {}

    lines: list[str] = [
        "# netrecon report",
        "",
        "> Reconnaissance output for an authorised engagement. Findings below are",
        "> observations about exposed services, not verified vulnerabilities.",
        "",
        "## Run",
        "",
        f"- **Run name**: `{run.get('name')}`",
        f"- **Started (UTC)**: {run.get('started_at')}",
        f"- **Report generated (UTC)**: {payload['generated_at']}",
        f"- **Output directory**: `{run.get('directory')}`",
        f"- **Scope file**: `{scope.get('source')}`",
        f"- **Raw sockets**: {'yes' if run.get('raw_sockets') else 'no (connect-scan fallback)'}",
        f"- **Active stage (nuclei)**: {'enabled' if run.get('active_stage_enabled') else 'disabled'}",
        f"- **Sweep backend**: {payload.get('sweep_backend') or 'n/a'}",
        f"- **Rate caps**: {limits.get('sweep_rate_pps')} pps sweep, "
        f"{limits.get('nuclei_rate_rps')} rps nuclei, concurrency {limits.get('concurrency')}",
        "",
        "## Totals",
        "",
        "| Metric | Count |",
        "| --- | --- |",
        f"| In-scope addresses | {totals.get('in_scope_hosts')} |",
        f"| Live hosts | {totals.get('live_hosts')} |",
        f"| Hosts with open ports | {totals.get('hosts_with_open_ports')} |",
        f"| Open ports | {totals.get('open_ports')} |",
        f"| Services identified | {totals.get('services_identified')} |",
        f"| nuclei findings | {totals.get('nuclei_findings')} |",
        f"| Notable observations | {totals.get('notable_observations')} |",
    ]

    if totals.get("web_endpoints"):
        lines += [
            f"| Web endpoints probed | {totals.get('web_endpoints')} |",
            f"| JavaScript files analysed | {totals.get('js_scripts_analysed', 0)} |",
            f"| Paths found in JavaScript | {totals.get('js_endpoints', 0)} |",
            f"| JS secret candidates | {totals.get('js_secret_candidates', 0)} |",
        ]

    lines += [
        "",
        "## Stage timings",
        "",
        "| Stage | Status | Duration (s) | Detail |",
        "| --- | --- | --- | --- |",
    ]

    for name, stage in (payload.get("stages") or {}).items():
        if name == "report":
            # The reporting stage is still running while this table is rendered;
            # its own timing is recorded in state.json instead.
            continue
        duration = stage.get("duration_seconds")
        lines.append(
            f"| {name} | {stage.get('status')} | "
            f"{duration if duration is not None else '-'} | {stage.get('detail') or ''} |"
        )

    findings_block = payload.get("service_findings") or {}
    if findings_block.get("total"):
        by_severity = findings_block.get("by_severity") or {}
        lines += [
            "",
            "## Service findings",
            "",
            "Observations derived from the service and NSE output already collected.",
            "Severity is an exposure judgement, not an exploitability rating.",
            "",
            "| Severity | Count |",
            "| --- | --- |",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            if by_severity.get(severity):
                lines.append(f"| {severity} | {by_severity[severity]} |")
        lines.append("")

    web_block = payload.get("web") or {}
    if web_block.get("technologies"):
        lines += ["", "## Technology stack", "", "| Technology |", "| --- |"]
        lines += [f"| {tech} |" for tech in web_block["technologies"][:80]]
        lines.append("")

    if totals.get("cve_matches"):
        lines += [
            "",
            f"**{totals.get('cve_matches')} CVE correlation(s)** from the configured feed.",
            "These are version-to-feed matches, NOT verified exploitable conditions;",
            "confirm the exact build and patch level on each host before reporting.",
            "",
        ]

    api = (web_block.get("api_structure") or {}).get("endpoints") or []
    if api:
        lines += [
            "",
            "## API surface reconstructed from front-end code",
            "",
            "Signatures recovered from JavaScript call sites. Parameters are what the",
            "front-end sends, not a schema the server published - treat them as leads.",
            "",
            "| Signature | Body parameters | Source |",
            "| --- | --- | --- |",
        ]
        for endpoint in api[:60]:
            body_params = ", ".join(endpoint.get("body_params") or []) or "-"
            lines.append(
                f"| `{endpoint.get('signature')}` | {_escape(body_params)} | "
                f"{endpoint.get('source_label')} |"
            )
        lines.append("")

    parameters = web_block.get("parameters") or []
    if parameters:
        lines += [
            "",
            "## Parameter index",
            "",
            f"{len(parameters)} distinct parameter name(s), widest acceptance first.",
            "A plain wordlist is at `parameters.txt`.",
            "",
            "| Parameter | Kinds | Endpoints | Occurrences |",
            "| --- | --- | --- | --- |",
        ]
        for parameter in parameters[:60]:
            kinds = ", ".join(parameter.get("kinds") or [])
            lines.append(
                f"| `{parameter.get('name')}` | {kinds} | "
                f"{parameter.get('endpoint_count')} | {parameter.get('occurrences')} |"
            )
        lines.append("")

    if web_block.get("high_value_paths"):
        lines += ["", "## Sensitive paths accessible", ""]
        lines += [f"- `{url}`" for url in web_block["high_value_paths"][:50]]
        lines.append("")

    if web_block.get("hosts_referenced"):
        lines += [
            "",
            "## Hosts referenced by front-end code",
            "",
            "Discovered in JavaScript. **Out of scope and not contacted** - add them to",
            "the scope file first if they are in fact authorised.",
            "",
        ]
        lines += [f"- `{host}`" for host in web_block["hosts_referenced"][:100]]
        lines.append("")

    if categories:
        lines += ["", "## Services by category", ""]
        lines += ["| Category | Hosts | Ports |", "| --- | --- | --- |"]
        for category in categories:
            lines.append(
                f"| {category.label} | {category.host_count} | {len(category.entries)} |"
            )
        lines.append("")

        for category in categories:
            lines += [f"### {category.label}", "", category.description, ""]
            lines += [
                "| Host | Port | Proto | Service | Version / banner |",
                "| --- | --- | --- | --- | --- |",
            ]
            for entry in category.entries:
                host_label = entry.ip
                if entry.hostnames:
                    host_label = f"{entry.ip} ({', '.join(entry.hostnames)})"
                lines.append(
                    f"| {host_label} | {entry.port} | {entry.protocol} | "
                    f"{entry.service or '-'} | {_escape(entry.version)} |"
                )
            lines.append("")

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

        for endpoint in host.web_endpoints:
            lines += [f"**Web endpoint `{endpoint['base_url']}`**", ""]
            if endpoint.get("error"):
                lines += [f"- Not reachable: {endpoint['error']}", ""]
                continue
            lines.append(
                f"- HTTP {endpoint.get('status')} "
                f"{_escape(endpoint.get('title')) if endpoint.get('title') else ''}".rstrip()
            )
            if endpoint.get("technologies"):
                lines.append(f"- Technologies: {_tech_labels(endpoint['technologies'])}")
            if endpoint.get("missing_security_headers"):
                lines.append(
                    f"- Security headers absent: "
                    f"{', '.join(endpoint['missing_security_headers'])}"
                )
            lines.append(
                f"- JavaScript: {endpoint.get('scripts_analysed', 0)} file(s), "
                f"{endpoint.get('js_endpoints', 0)} path(s), "
                f"{endpoint.get('secret_candidates', 0)} secret candidate(s), "
                f"{endpoint.get('pii_candidates', 0)} personal-data candidate(s)"
            )
            # Secrets belong under the JavaScript line above, not under the
            # paths line that follows.
            for secret in endpoint.get("secrets") or []:
                name = secret.get("name")
                label = f"**{secret.get('kind')}**"
                if name:
                    label += f" `{name}`"
                lines.append(
                    f"  - {label} = `{secret.get('value')}` "
                    f"({_escape(secret.get('source'))}:{secret.get('line')})"
                )
            if endpoint.get("paths_accessible"):
                lines.append(
                    f"- Accessible paths: {endpoint['paths_accessible']} "
                    "(see report.html or webrecon.json for the list)"
                )
                for path in endpoint.get("accessible_paths") or []:
                    marker = "**" if path.get("high_value") else ""
                    lines.append(
                        f"  - {marker}`{path.get('path')}`{marker} "
                        f"(HTTP {path.get('status')}) - {path.get('reason')}"
                    )
            lines.append("")

        if host.service_findings:
            lines += ["**Service findings**", ""]
            for finding in host.service_findings:
                lines.append(
                    f"- `{finding.get('port')}/{finding.get('protocol')}` "
                    f"**[{finding.get('severity')}]** {finding.get('title')} "
                    f"- {_escape(finding.get('summary'))}"
                )
                if finding.get("evidence"):
                    evidence = _escape(finding["evidence"])[:300]
                    lines.append(f"  - evidence: `{evidence}`")
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
    ]
    if totals.get("web_endpoints"):
        lines += [
            "- Verify every JS secret candidate by hand against the saved bodies in",
            "  `webrecon/`; the values in this report are masked and the patterns that",
            "  found them produce false positives.",
            "- Web recon issued GET requests only: no form submission, no redirect",
            "  following, no path brute forcing.",
        ]
    lines += [
        "- `report.html` has the same data with a per-service-category view.",
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


def _load_webrecon(ctx: RunContext) -> dict[str, Any]:
    """Read the web recon checkpoint, if the stage ran."""
    payload = read_json(ctx.paths.webrecon, default={}) or {}
    return payload if isinstance(payload, dict) else {}


def _web_endpoint_digest(result: dict[str, Any]) -> dict[str, Any]:
    """Condense one web recon result into what the reports show per host."""
    root = result.get("root") or {}
    totals = result.get("totals") or {}
    javascript = result.get("javascript") or {}
    # The merged javascript block is authoritative; the per-script lists are a
    # fallback for runs written before that block existed.
    secrets = javascript.get("secret_candidates") or [
        secret
        for script in result.get("scripts") or []
        for secret in (script.get("secret_candidates") or [])
    ]
    return {
        "base_url": result.get("base_url"),
        "port": result.get("port"),
        "scheme": result.get("scheme"),
        "error": result.get("error"),
        "status": root.get("status"),
        "title": root.get("title"),
        "redirect_to": root.get("redirect_to"),
        "disclosure_headers": root.get("disclosure_headers") or {},
        "missing_security_headers": root.get("missing_security_headers") or [],
        "scripts_analysed": totals.get("scripts_analysed", 0),
        "js_endpoints": totals.get("js_endpoints", 0),
        "secret_candidates": totals.get("secret_candidates", 0),
        "pii_candidates": totals.get("pii_candidates", 0),
        "paths_accessible": totals.get("paths_accessible", 0),
        "technologies_detected": totals.get("technologies", 0),
        "cve_match_count": totals.get("cve_matches", 0),
        "cve_matches": result.get("cve_matches") or [],
        "technologies": result.get("technologies") or [],
        "secrets": secrets,
        "pii_summary": javascript.get("pii_summary") or {},
        "accessible_paths": [
            p for p in (result.get("hidden_paths") or [])
            if p.get("classification") == "accessible"
        ][:50],
    }


def _web_notes(host: HostSummary) -> list[str]:
    """Notable observations derived from the web recon stage."""
    notes: list[str] = []
    for endpoint in host.web_endpoints:
        if not isinstance(endpoint, dict):
            continue
        port = endpoint.get("port")
        if endpoint.get("error"):
            continue
        count = endpoint.get("secret_candidates") or 0
        if count:
            notes.append(
                f"`{port}/tcp` {count} string(s) in JavaScript look like embedded "
                "credentials - verify manually"
            )
        pii_count = endpoint.get("pii_candidates") or 0
        if pii_count:
            kinds = ", ".join(sorted((endpoint.get("pii_summary") or {}).keys()))
            notes.append(
                f"`{port}/tcp` {pii_count} personal-data candidate(s) in front-end "
                f"assets ({kinds or 'mixed'}) - verify, then handle the run directory "
                "as personal data"
            )
        for path in _as_dicts(endpoint.get("accessible_paths")):
            if path.get("high_value"):
                notes.append(
                    f"`{port}/tcp` sensitive path accessible: `{path.get('path')}` "
                    f"- {path.get('reason')}"
                )
        for match in _as_dicts(endpoint.get("cve_matches"))[:5]:
            notes.append(
                f"`{port}/tcp` feed correlation {match.get('cve_id')} against "
                f"{match.get('technology')} {match.get('version') or ''} - unverified"
            )
        missing = endpoint.get("missing_security_headers") or []
        if "content-security-policy" in missing:
            notes.append(f"`{port}/tcp` no Content-Security-Policy response header")
        if endpoint.get("scheme") == "https" and "strict-transport-security" in missing:
            notes.append(f"`{port}/tcp` HTTPS without Strict-Transport-Security")
        disclosed = endpoint.get("disclosure_headers") or {}
        if disclosed:
            notes.append(
                f"`{port}/tcp` version disclosed via "
                f"{', '.join(sorted(disclosed))}"
            )
    return notes


def _as_dicts(value: Any) -> list[dict[str, Any]]:
    """Only the mapping entries of *value*, or nothing.

    Checkpoints are read back from disk and may be truncated or hand-edited, so
    a list field can hold anything. Rendering must degrade, not raise.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _tech_labels(technologies: list[Any], limit: int = 25) -> str:
    """``name version`` labels from Technology dicts, for the markdown report."""
    labels: list[str] = []
    for tech in technologies[:limit]:
        if isinstance(tech, str):
            labels.append(tech)
            continue
        name = tech.get("name", "")
        version = tech.get("version")
        labels.append(f"{name} {version}" if version else name)
    return ", ".join(labels)


def _finding_notes(host: HostSummary) -> list[str]:
    """Surface the serious analyzer findings in the per-host notes."""
    notes: list[str] = []
    for finding in host.service_findings:
        if finding.get("severity") not in {"critical", "high"}:
            continue
        port = finding.get("port")
        protocol = finding.get("protocol", "tcp")
        notes.append(f"`{port}/{protocol}` {finding.get('title')}")
    return notes


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL artifact, tolerating a truncated final line."""
    path = Path(path)
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


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
    counts = {
        "hosts_reported": totals["hosts_reported"],
        "open_ports": totals["open_ports"],
        "service_categories": totals.get("service_categories", 0),
        "notable_observations": totals["notable_observations"],
    }
    if totals.get("web_endpoints"):
        counts["web_endpoints"] = totals["web_endpoints"]
        counts["js_secret_candidates"] = totals.get("js_secret_candidates", 0)
    return counts


def notable_iter(hosts: Iterable[HostSummary]) -> Iterable[str]:
    for host in hosts:
        for note in host.notes:
            yield f"{host.ip}: {note}"
