"""Stage 3: rate-capped fast port sweep across live hosts.

Backends, in preference order: masscan (raw SYN), naabu, nmap connect scan.
The packet rate is clamped by :mod:`netrecon.core.config` before it gets here,
so no backend can be asked to exceed the hard maximum.
"""

from __future__ import annotations

from pathlib import Path

from netrecon.core.jsonio import write_json
from netrecon.core.runner import RunContext, run_command
from netrecon.core.state import utc_now
from netrecon.parse import masscan as masscan_parse
from netrecon.parse.masscan import OpenPort
from netrecon.parse.nmap import NmapParseError, parse_nmap_xml
from netrecon.stages.base import StageFailed, StageResult, StageSkipped

NAME = "sweep"


def _loopback_count(ctx: RunContext) -> int:
    return len(ctx.scope.notable_addresses().get("loopback", ()))


def choose_backend(ctx: RunContext) -> str:
    """Pick a sweep backend, accounting for what each one physically can do."""
    configured = ctx.config.sweep.backend
    raw = ctx.privileges.raw_sockets
    log = ctx.logger(NAME)

    # masscan builds its own packets and sends them through a network adapter,
    # bypassing the kernel's loopback path, so it finds nothing on 127.0.0.0/8
    # and ::1 and exits successfully while doing it. Reporting that as a clean
    # sweep would be exactly the silent lie the other guards here exist to
    # prevent, so a loopback scope picks a backend that can actually see it.
    loopback = _loopback_count(ctx)

    if configured == "masscan":
        if not ctx.tools.has("masscan"):
            raise StageFailed("sweep.backend=masscan but masscan is not installed")
        if not raw:
            raise StageFailed(
                "sweep.backend=masscan needs raw sockets; re-run with sudo or "
                "CAP_NET_RAW, or set sweep.backend=auto to fall back to a connect scan"
            )
        if loopback:
            log.warning(
                "sweep.backend=masscan was requested explicitly, but masscan cannot "
                "scan the %d loopback address(es) in scope: it sends raw packets "
                "through a network adapter and never reaches 127.0.0.0/8 or ::1. "
                "Those hosts will report zero open ports. Set sweep.backend=nmap "
                "(or naabu) to scan them with a connect scan.",
                loopback,
            )
        return "masscan"
    if configured == "naabu":
        if not ctx.tools.has("naabu"):
            raise StageFailed("sweep.backend=naabu but naabu is not installed")
        return "naabu"
    if configured == "nmap":
        if not ctx.tools.has("nmap"):
            raise StageFailed("sweep.backend=nmap but nmap is not installed")
        return "nmap"

    # auto
    if raw and ctx.tools.has("masscan") and not loopback:
        return "masscan"
    if raw and ctx.tools.has("masscan") and loopback:
        fallback = "naabu" if ctx.tools.has("naabu") else "nmap"
        if ctx.tools.has(fallback):
            log.warning(
                "scope holds %d loopback address(es), which masscan cannot reach; "
                "using %s instead so the sweep can actually see them",
                loopback,
                fallback,
            )
            return fallback
        log.warning(
            "scope holds %d loopback address(es) and only masscan is available; "
            "masscan cannot reach loopback, so expect zero open ports there",
            loopback,
        )
        return "masscan"
    if ctx.tools.has("naabu"):
        return "naabu"
    if ctx.tools.has("nmap"):
        return "nmap"
    raise StageFailed("port sweep needs masscan, naabu or nmap; none is installed")


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)

    live = ctx.live_hosts()
    if not live:
        raise StageSkipped("no live hosts from discovery; nothing to sweep")

    backend = choose_backend(ctx)
    ports = ctx.sweep_ports()
    rate = ctx.config.limits.masscan_rate

    # enforce_strict: these hosts came from our own checkpoint, so an
    # out-of-scope entry here is a bug and must stop the run.
    targets_path, target_count = ctx.targets_file("sweep_targets.txt", live)

    log.info(
        "sweeping %d live host(s) with %s at <=%d pps (tcp ports: %s)",
        target_count,
        backend,
        rate,
        _abbreviate(ports),
    )
    if not ctx.privileges.raw_sockets and backend != "masscan":
        log.warning(
            "unprivileged sweep: %s is using TCP connect probes, which are slower "
            "and more visible in target logs than a SYN scan",
            backend,
        )

    if ctx.dry_run:
        log.warning("dry run: skipping %s execution", backend)
        return StageResult(counts={"live_hosts": target_count}, backend=backend, detail="dry run")

    if backend == "masscan":
        found = _run_masscan(ctx, targets_path, ports, rate)
    elif backend == "naabu":
        found = _run_naabu(ctx, targets_path, ports, rate)
    else:
        found = _run_nmap_sweep(ctx, targets_path, ports, rate)

    enforced = ctx.scope.enforce(entry.ip for entry in found)
    in_scope = set(enforced.allowed_str)
    dropped = len(found) - sum(1 for entry in found if entry.ip in in_scope)
    if dropped:
        log.warning("dropped %d open-port record(s) for out-of-scope addresses", dropped)
    found = [entry for entry in found if entry.ip in in_scope]

    grouped = masscan_parse.group_by_host(found)
    payload = {
        "generated_at": utc_now(),
        "backend": backend,
        "rate_pps": rate,
        "ports_requested": ports,
        "live_hosts_swept": target_count,
        "hosts_with_open_ports": len(grouped),
        "total_open_ports": len(found),
        "hosts": {
            ip: [entry.to_dict() for entry in entries] for ip, entries in grouped.items()
        },
    }
    write_json(ctx.paths.open_ports, payload)

    log.info(
        "found %d open port(s) across %d host(s)", len(found), len(grouped)
    )

    return StageResult(
        counts={
            "live_hosts": target_count,
            "hosts_with_open_ports": len(grouped),
            "open_ports": len(found),
            "out_of_scope_dropped": dropped,
        },
        outputs={"open_ports": ctx.paths.open_ports},
        backend=backend,
    )


def _run_masscan(ctx: RunContext, targets: Path, ports: str, rate: int) -> list[OpenPort]:
    out_path = ctx.paths.raw_dir / "masscan.json"
    argv = [
        ctx.tools.path("masscan"),
        "-iL", str(targets),
        "-p", ports,
        "--rate", str(rate),
        "--open-only",
        "--wait", "3",
        "-oJ", str(out_path),
    ]
    if ctx.config.sweep.retries:
        argv += ["--retries", str(ctx.config.sweep.retries)]

    result = run_command(argv, timeout=ctx.stage_timeout())
    if result.timed_out:
        raise StageFailed("masscan timed out")
    if result.returncode != 0 and not out_path.is_file():
        raise StageFailed(f"masscan failed: {result.tail()}")
    if not out_path.is_file():
        # Exit zero with no output file is not "no open ports": it is a tool
        # that did not run. Reporting it as a clean sweep would be a lie the
        # operator cannot see.
        raise StageFailed(
            f"masscan reported success but wrote no output to {out_path}: {result.tail()}"
        )

    found = masscan_parse.parse_masscan_json(out_path)

    if ctx.config.sweep.udp:
        udp_path = ctx.paths.raw_dir / "masscan_udp.json"
        udp_argv = [
            ctx.tools.path("masscan"),
            "-iL", str(targets),
            "-pU:" + ctx.config.ports.udp,
            "--rate", str(rate),
            "--open-only",
            "--wait", "3",
            "-oJ", str(udp_path),
        ]
        udp_result = run_command(udp_argv, timeout=ctx.stage_timeout())
        if udp_result.timed_out:
            ctx.logger(NAME).warning("masscan UDP sweep timed out; continuing with TCP results")
        elif udp_path.is_file():
            found.extend(masscan_parse.parse_masscan_json(udp_path))

    return found


def _run_naabu(ctx: RunContext, targets: Path, ports: str, rate: int) -> list[OpenPort]:
    out_path = ctx.paths.raw_dir / "naabu.json"
    argv = [
        ctx.tools.path("naabu"),
        "-list", str(targets),
        "-p", ports,
        "-rate", str(rate),
        "-json",
        "-silent",
        "-no-color",
        "-output", str(out_path),
    ]
    # naabu's SYN scan needs raw sockets; -s c selects a connect scan.
    argv += ["-scan-type", "s" if ctx.privileges.raw_sockets else "c"]

    result = run_command(argv, timeout=ctx.stage_timeout())
    if result.timed_out:
        raise StageFailed("naabu timed out")
    if result.returncode != 0 and not out_path.is_file():
        raise StageFailed(f"naabu failed: {result.tail()}")
    if not out_path.is_file():
        # naabu writes no file when it finds nothing, so an exit-zero run with
        # no output is genuinely ambiguous. Say so rather than inventing a
        # clean result: a non-empty stderr means the tool had something to
        # complain about.
        if result.stderr.strip():
            raise StageFailed(
                f"naabu wrote no output and reported: {result.tail()}"
            )
        return []
    return masscan_parse.parse_naabu_json(out_path)


def _run_nmap_sweep(ctx: RunContext, targets: Path, ports: str, rate: int) -> list[OpenPort]:
    prefix = ctx.paths.nmap_dir / "sweep"
    scan_flag = "-sS" if ctx.privileges.raw_sockets else "-sT"
    argv = [
        ctx.tools.path("nmap"),
        scan_flag,
        "-Pn",                       # discovery already happened
        "-n",
        "--open",
        f"-T{ctx.config.limits.nmap_timing}",
        "--max-rate", str(rate),
        "--host-timeout", f"{ctx.config.limits.host_timeout_seconds}s",
        "-p", ports,
        "-iL", str(targets),
        "-oA", str(prefix),
    ]
    result = run_command(argv, timeout=ctx.stage_timeout())
    if result.timed_out:
        raise StageFailed("nmap sweep timed out")

    try:
        report = parse_nmap_xml(prefix.with_suffix(".xml"))
    except NmapParseError as exc:
        raise StageFailed(f"nmap sweep produced no parseable output: {exc}") from exc

    return [
        OpenPort(
            ip=host.address,
            port=port.port,
            protocol=port.protocol,
            reason=port.reason,
            source="nmap",
        )
        for host in report.hosts
        for port in host.open_ports
    ]


def _abbreviate(ports: str, limit: int = 60) -> str:
    return ports if len(ports) <= limit else ports[: limit - 3] + "..."
