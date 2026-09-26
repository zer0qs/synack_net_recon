"""Stages 4 and 5: service/version detection, optional OS detection and banners.

``nmap -sV`` runs per host, against that host's discovered open ports only -
never a fresh port range, so this stage cannot widen the scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext, run_command, run_parallel
from netrecon.core.state import utc_now
from netrecon.parse.nmap import Host, NmapParseError, parse_nmap_xml
from netrecon.stages.base import StageFailed, StageResult, StageSkipped

NAME = "services"

#: NSE scripts allowed for banner grabbing.  ``banner`` is in the safe and
#: discovery categories; nothing here writes to the target.
BANNER_SCRIPTS = "banner"


@dataclass
class HostTarget:
    ip: str
    tcp_ports: tuple[int, ...]
    udp_ports: tuple[int, ...]

    @property
    def port_spec(self) -> str:
        parts = []
        if self.tcp_ports:
            parts.append("T:" + ",".join(str(p) for p in self.tcp_ports))
        if self.udp_ports:
            parts.append("U:" + ",".join(str(p) for p in self.udp_ports))
        return ",".join(parts)

    @property
    def total(self) -> int:
        return len(self.tcp_ports) + len(self.udp_ports)


def load_targets(ctx: RunContext) -> list[HostTarget]:
    """Read the sweep checkpoint, re-enforcing scope on the way in."""
    payload = read_json(ctx.paths.open_ports, default={}) or {}
    hosts = payload.get("hosts") or {}
    if not isinstance(hosts, dict):
        raise StageFailed(f"{ctx.paths.open_ports} is not in the expected format")

    enforced = ctx.scope.enforce(hosts.keys())
    allowed = set(enforced.allowed_str)

    targets: list[HostTarget] = []
    for ip, entries in sorted(hosts.items()):
        if ip not in allowed:
            continue
        tcp = sorted(
            {
                entry["port"]
                for entry in entries
                if isinstance(entry, dict)
                and isinstance(entry.get("port"), int)
                and entry.get("protocol", "tcp") == "tcp"
            }
        )
        udp = sorted(
            {
                entry["port"]
                for entry in entries
                if isinstance(entry, dict)
                and isinstance(entry.get("port"), int)
                and entry.get("protocol") == "udp"
            }
        )
        if tcp or udp:
            targets.append(HostTarget(ip, tuple(tcp), tuple(udp)))
    return targets


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)

    if not ctx.tools.has("nmap"):
        raise StageFailed("service detection requires nmap")

    targets = load_targets(ctx)
    if not targets:
        raise StageSkipped("no open ports from the sweep stage; nothing to fingerprint")

    os_detect = ctx.config.stages.os_detect
    if os_detect and not ctx.privileges.raw_sockets:
        log.warning(
            "OS detection was requested but needs raw packets; skipping -O for this run"
        )
        os_detect = False

    total_ports = sum(target.total for target in targets)
    log.info(
        "fingerprinting %d port(s) on %d host(s) with %d worker(s)%s",
        total_ports,
        len(targets),
        ctx.config.limits.concurrency,
        " (+OS detection)" if os_detect else "",
    )

    if ctx.dry_run:
        log.warning("dry run: skipping nmap -sV execution")
        return StageResult(
            counts={"hosts": len(targets), "ports": total_ports}, detail="dry run"
        )

    def worker(target: HostTarget) -> tuple[HostTarget, Host | None, str | None]:
        return _scan_host(ctx, target, os_detect=os_detect)

    outcomes = run_parallel(
        targets, worker, concurrency=ctx.config.limits.concurrency, label="sV"
    )

    hosts: list[dict] = []
    failures: list[str] = []
    identified = 0
    for target, host, error in outcomes:
        if error:
            failures.append(f"{target.ip}: {error}")
            log.warning("service detection failed for %s: %s", target.ip, error)
            continue
        if host is None:
            continue
        hosts.append(host.to_dict())
        identified += sum(
            1
            for port in host.open_ports
            if port.service and (port.service.product or port.service.name)
        )

    payload = {
        "generated_at": utc_now(),
        "hosts_scanned": len(targets),
        "hosts_reported": len(hosts),
        "ports_requested": total_ports,
        "services_identified": identified,
        "os_detection": os_detect,
        "banner_grab": ctx.config.services.banner_grab,
        "failures": failures,
        "hosts": hosts,
    }
    write_json(ctx.paths.services, payload)

    log.info(
        "identified %d service(s) on %d host(s)%s",
        identified,
        len(hosts),
        f"; {len(failures)} host(s) failed" if failures else "",
    )

    if not hosts and failures:
        raise StageFailed(
            f"every host failed service detection (first: {failures[0]})"
        )

    return StageResult(
        counts={
            "hosts_scanned": len(targets),
            "hosts_reported": len(hosts),
            "ports": total_ports,
            "services_identified": identified,
            "failures": len(failures),
        },
        outputs={"services": ctx.paths.services},
        backend="nmap",
        detail=f"{len(failures)} host(s) failed" if failures else None,
    )


def _scan_host(
    ctx: RunContext, target: HostTarget, *, os_detect: bool
) -> tuple[HostTarget, Host | None, str | None]:
    # Single-host argv, and the address is re-checked against the scope set
    # immediately before it becomes a command-line argument.
    try:
        address = ctx.scope.enforce_strict([target.ip])[0]
    except Exception as exc:  # ScopeViolation
        return target, None, str(exc)

    prefix = ctx.paths.nmap_dir / f"services_{_slug(target.ip)}"
    argv = [
        ctx.tools.path("nmap"),
        "-sV",
        "--version-intensity", str(ctx.config.services.version_intensity),
        "-Pn",
        "-n",
        "--open",
        f"-T{ctx.config.limits.nmap_timing}",
        "--max-rate", str(ctx.config.limits.masscan_rate),
        "--host-timeout", f"{ctx.config.limits.host_timeout_seconds}s",
        "-p", target.port_spec,
    ]
    if target.udp_ports:
        argv.append("-sU" if ctx.privileges.raw_sockets else "-sT")
    if os_detect:
        argv.append("-O")
    if ctx.config.services.banner_grab:
        argv += ["--script", BANNER_SCRIPTS]
    argv += ["-oA", str(prefix), str(address)]

    result = run_command(argv, timeout=ctx.config.limits.host_timeout_seconds + 120)
    xml_path = prefix.with_suffix(".xml")
    if not xml_path.is_file():
        return target, None, result.tail() or f"nmap exited {result.returncode}"

    try:
        report = parse_nmap_xml(xml_path)
    except NmapParseError as exc:
        return target, None, str(exc)

    host = report.host(str(address)) or (report.hosts[0] if report.hosts else None)
    if host is None:
        return target, None, "nmap reported no host record"
    return target, host, None


def _slug(ip: str) -> str:
    return ip.replace(":", "_").replace(".", "_")


def merge_script_output(services_path: Path, scripts_hosts: list[dict]) -> None:
    """Fold NSE script output from the scripts stage into ``services.json``."""
    payload = read_json(services_path, default=None)
    if not isinstance(payload, dict):
        return
    by_address = {host.get("address"): host for host in payload.get("hosts", [])}
    for host in scripts_hosts:
        existing = by_address.get(host.get("address"))
        if existing is None:
            payload.setdefault("hosts", []).append(host)
            continue
        existing["host_scripts"] = {
            **(existing.get("host_scripts") or {}),
            **(host.get("host_scripts") or {}),
        }
        ports = {(p.get("protocol"), p.get("port")): p for p in existing.get("ports", [])}
        for port in host.get("ports", []):
            key = (port.get("protocol"), port.get("port"))
            if key in ports:
                ports[key]["scripts"] = {
                    **(ports[key].get("scripts") or {}),
                    **(port.get("scripts") or {}),
                }
            else:
                existing.setdefault("ports", []).append(port)
    write_json(services_path, payload)
