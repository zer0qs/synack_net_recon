"""Stage 9: per-service deep analysis.

This stage sends no packets of its own. It re-reads what earlier stages already
collected - ``nmap -sV`` service records and NSE script output from
``services.json`` and ``scripts.json`` - and runs a set of per-service
analyzers over it, turning raw tool text into structured findings.

Because it is pure analysis, it is cheap, it is safe to re-run, and it works
offline against an old run directory via ``netrecon report``. The one analyzer
allowed to open a connection is TLS, and only when ``--scripts`` did not run so
no ``ssl-cert`` output exists; that probe is opt-in and rate-limited.
"""

from __future__ import annotations

from typing import Any

from netrecon.analyze.base import (
    SEVERITY_ORDER,
    AnalyzerResult,
    Finding,
    ServiceEvidence,
    dedupe_findings,
    severity_counts,
)
from netrecon.analyze.registry import build_analyzers
from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext
from netrecon.core.state import utc_now
from netrecon.stages.base import StageResult, StageSkipped

NAME = "servicerecon"


def load_evidence(ctx: RunContext) -> list[ServiceEvidence]:
    """Build one evidence record per open port, scope-filtered.

    Service data is the primary source; the sweep fills in ports that never
    reached ``-sV``. NSE output from the scripts stage is merged in.
    """
    services = read_json(ctx.paths.services, default={}) or {}
    sweep = read_json(ctx.paths.open_ports, default={}) or {}
    scripts = read_json(ctx.paths.root / "scripts.json", default={}) or {}

    # NSE output, indexed by (ip, protocol, port) and by ip for host scripts.
    port_scripts: dict[tuple[str, str, int], dict[str, str]] = {}
    host_scripts: dict[str, dict[str, str]] = {}
    for source in (scripts, services):
        for host in source.get("hosts") or []:
            ip = host.get("address")
            if not ip:
                continue
            if host.get("host_scripts"):
                host_scripts.setdefault(ip, {}).update(host["host_scripts"])
            for port in host.get("ports") or []:
                number = port.get("port")
                if not isinstance(number, int) or not port.get("scripts"):
                    continue
                key = (ip, port.get("protocol", "tcp"), number)
                port_scripts.setdefault(key, {}).update(port["scripts"])

    records: dict[tuple[str, str, int], ServiceEvidence] = {}

    for host in services.get("hosts") or []:
        ip = host.get("address")
        if not ip:
            continue
        hostnames = tuple(host.get("hostnames") or [])
        for port in host.get("ports") or []:
            number = port.get("port")
            if port.get("state") != "open" or not isinstance(number, int):
                continue
            protocol = port.get("protocol", "tcp")
            service = port.get("service") or {}
            key = (ip, protocol, number)
            records[key] = ServiceEvidence(
                ip=ip,
                port=number,
                protocol=protocol,
                service=service.get("name"),
                product=service.get("product"),
                version=service.get("version"),
                extrainfo=service.get("extrainfo"),
                tunnel=service.get("tunnel"),
                cpes=tuple(service.get("cpes") or []),
                scripts=dict(port_scripts.get(key, {})),
                host_scripts=dict(host_scripts.get(ip, {})),
                hostnames=hostnames,
            )

    for ip, entries in (sweep.get("hosts") or {}).items():
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            number = entry.get("port")
            if not isinstance(number, int):
                continue
            key = (ip, entry.get("protocol", "tcp"), number)
            if key in records:
                continue
            records[key] = ServiceEvidence(
                ip=ip,
                port=number,
                protocol=entry.get("protocol", "tcp"),
                scripts=dict(port_scripts.get(key, {})),
                host_scripts=dict(host_scripts.get(ip, {})),
            )

    # Final scope gate: a hand-edited checkpoint cannot introduce a host.
    allowed = set(ctx.scope.enforce(ip for ip, _, _ in records).allowed_str)
    return [
        evidence
        for key, evidence in sorted(records.items())
        if key[0] in allowed
    ]


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)
    cfg = ctx.config.servicerecon

    evidence_records = load_evidence(ctx)
    if not evidence_records:
        raise StageSkipped("no open ports to analyse")

    analyzers = build_analyzers(cfg.analyzers)
    if not analyzers:
        raise StageSkipped("no analyzers enabled")

    probe_allowed = cfg.allow_tls_probe and not ctx.dry_run
    log.info(
        "analysing %d service(s) with %d analyzer(s): %s%s",
        len(evidence_records),
        len(analyzers),
        ", ".join(a.name for a in analyzers),
        "" if probe_allowed else " (no additional connections)",
    )

    results: list[AnalyzerResult] = []
    all_findings: list[Finding] = []
    errors: list[str] = []

    for evidence in evidence_records:
        for analyzer in analyzers:
            try:
                if not analyzer.applies_to(evidence):
                    continue
                if getattr(analyzer, "needs_probe", False) and not probe_allowed:
                    findings = analyzer.analyse(evidence)
                else:
                    findings = _run_analyzer(ctx, analyzer, evidence, probe_allowed)
            except Exception as exc:  # noqa: BLE001 - one analyzer must not stop the stage
                errors.append(f"{analyzer.name} on {evidence.label}: {exc}")
                log.warning("analyzer %s failed on %s: %s", analyzer.name, evidence.label, exc)
                continue
            findings = dedupe_findings(findings)
            if findings:
                results.append(AnalyzerResult(analyzer.name, evidence, findings))
                all_findings.extend(findings)

    counts = severity_counts(all_findings)
    by_analyzer: dict[str, int] = {}
    for result in results:
        by_analyzer[result.analyzer] = by_analyzer.get(result.analyzer, 0) + len(result.findings)

    write_json(
        ctx.paths.service_findings,
        {
            "generated_at": utc_now(),
            "method": "offline analysis of nmap -sV and NSE output already collected",
            "analyzers": [a.name for a in analyzers],
            "tls_probe_allowed": probe_allowed,
            "services_analysed": len(evidence_records),
            "services_with_findings": len(results),
            "findings": len(all_findings),
            "by_severity": counts,
            "by_analyzer": by_analyzer,
            "errors": errors,
            "results": [r.to_dict() for r in results],
        },
    )

    log.info(
        "%d finding(s) across %d service(s): %s",
        len(all_findings),
        len(results),
        counts or "none",
    )

    return StageResult(
        counts={
            "services_analysed": len(evidence_records),
            "services_with_findings": len(results),
            "findings": len(all_findings),
            **{f"sev_{k}": v for k, v in counts.items()},
        },
        outputs={"service_findings": ctx.paths.service_findings},
        backend="analyzers",
        detail=f"{len(errors)} analyzer error(s)" if errors else None,
    )


def _run_analyzer(ctx: RunContext, analyzer: Any, evidence: ServiceEvidence, probe: bool) -> list[Finding]:
    """Call an analyzer, passing the probe hook only to those that take one."""
    if getattr(analyzer, "needs_probe", False) and probe:
        # The address is re-checked before any connection is opened.
        ctx.scope.enforce_strict([evidence.ip])
        return analyzer.analyse(evidence, probe=_make_probe(ctx))
    return analyzer.analyse(evidence)


def _make_probe(ctx: RunContext):
    """Build the single connection helper a probing analyzer may use."""
    from netrecon.analyze.tls import TlsProbe

    return TlsProbe(
        timeout=ctx.config.servicerecon.probe_timeout_seconds,
        scope=ctx.scope,
    )


def findings_by_host(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Regroup service findings by host, for the report."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for result in payload.get("results") or []:
        # A truncated or hand-edited checkpoint can hold nulls and non-objects;
        # the report must survive reading one.
        if not isinstance(result, dict):
            continue
        ip = result.get("ip")
        if not ip:
            continue
        for finding in result.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            grouped.setdefault(ip, []).append(
                {
                    **finding,
                    "port": result.get("port"),
                    "protocol": result.get("protocol"),
                    "analyzer": result.get("analyzer"),
                }
            )
    for entries in grouped.values():
        entries.sort(key=lambda f: (f.get("severity") == "info", f.get("port") or 0))
    return grouped


def top_findings(payload: dict[str, Any], limit: int = 25) -> list[dict[str, Any]]:
    """Most severe findings across the whole run, for the report summary."""
    flat: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            flat.append(
                {
                    **finding,
                    "ip": result.get("ip"),
                    "port": result.get("port"),
                    "protocol": result.get("protocol"),
                    "analyzer": result.get("analyzer"),
                }
            )
    flat.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "info"), 9),
            f.get("ip") or "",
            f.get("port") or 0,
        )
    )
    return flat[:limit]
