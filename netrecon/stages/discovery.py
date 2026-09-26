"""Stage 2: host discovery.

Privileged path uses ``fping`` ICMP echo; unprivileged falls back to
``nmap -sn``, which uses TCP connect probes when it cannot send raw packets.
"""

from __future__ import annotations

from netrecon.core.jsonio import write_lines
from netrecon.core.runner import RunContext, run_command
from netrecon.parse.nmap import NmapParseError, parse_nmap_xml
from netrecon.stages.base import StageFailed, StageResult

NAME = "discovery"


def choose_backend(ctx: RunContext) -> str:
    configured = ctx.config.discovery.method
    if configured == "skip":
        return "skip"
    if configured == "fping":
        if not ctx.tools.has("fping"):
            raise StageFailed("discovery.method=fping but fping is not installed")
        return "fping"
    if configured == "nmap":
        if not ctx.tools.has("nmap"):
            raise StageFailed("discovery.method=nmap but nmap is not installed")
        return "nmap"

    # auto
    if ctx.tools.has("fping") and ctx.privileges.raw_sockets:
        return "fping"
    if ctx.tools.has("nmap"):
        return "nmap"
    if ctx.tools.has("fping"):
        return "fping"
    raise StageFailed("host discovery needs either fping or nmap; neither is installed")


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)
    backend = choose_backend(ctx)

    # The target file is written through Scope, so the tool can only ever be
    # pointed at in-scope addresses.
    targets_path, target_count = ctx.targets_file("discovery_targets.txt")
    log.info(
        "host discovery over %d in-scope address(es) using %s", target_count, backend
    )

    if backend == "skip":
        live = list(ctx.scope.addresses)
        write_lines(ctx.paths.live_hosts, [str(a) for a in live])
        return StageResult(
            counts={"in_scope": target_count, "live": len(live), "probed": 0},
            outputs={"live_hosts": ctx.paths.live_hosts},
            backend=backend,
            detail="discovery disabled; treating every in-scope address as live",
        )

    if ctx.dry_run:
        log.warning("dry run: skipping %s execution", backend)
        return StageResult(
            counts={"in_scope": target_count, "live": 0},
            backend=backend,
            detail="dry run",
        )

    if backend == "fping":
        candidates = _run_fping(ctx, targets_path)
    else:
        candidates = _run_nmap_ping(ctx, targets_path)

    # Re-enforce: a tool must not be able to introduce a host we never listed.
    enforced = ctx.scope.enforce(candidates)
    if enforced.rejected:
        log.warning(
            "%s reported %d address(es) outside the in-scope set; dropped",
            backend,
            len(enforced.rejected),
        )

    live = list(enforced.allowed_str)

    if not live and ctx.config.discovery.assume_live_on_empty:
        log.warning(
            "no hosts answered discovery; discovery.assume_live_on_empty is set, so "
            "continuing against all %d in-scope address(es)",
            target_count,
        )
        live = [str(a) for a in ctx.scope.addresses]

    write_lines(ctx.paths.live_hosts, live)
    log.info("%d of %d in-scope address(es) responded", len(live), target_count)

    return StageResult(
        counts={
            "in_scope": target_count,
            "live": len(live),
            "out_of_scope_dropped": len(enforced.rejected),
        },
        outputs={"live_hosts": ctx.paths.live_hosts},
        backend=backend,
    )


def _run_fping(ctx: RunContext, targets_path) -> list[str]:
    cfg = ctx.config.discovery
    argv = [
        ctx.tools.path("fping"),
        "-a",              # only show alive hosts
        "-q",              # quiet, no per-probe noise
        "-r", str(cfg.fping_retries),
        "-t", str(cfg.fping_timeout_ms),
        "-f", str(targets_path),
    ]
    result = run_command(argv, timeout=ctx.stage_timeout())
    # fping exits 1 when some hosts are unreachable, which is normal here.
    if result.returncode not in (0, 1) or result.timed_out:
        raise StageFailed(f"fping failed: {result.tail()}")
    raw = result.stdout.splitlines()
    (ctx.paths.raw_dir / "fping.txt").write_text(result.stdout, encoding="utf-8")
    return [line.strip() for line in raw if line.strip()]


def _run_nmap_ping(ctx: RunContext, targets_path) -> list[str]:
    prefix = ctx.paths.nmap_dir / "discovery"
    argv = [
        ctx.tools.path("nmap"),
        "-sn",                 # ping scan, no port scan
        "-n",                  # never resolve DNS
        f"-T{ctx.config.limits.nmap_timing}",
        "--max-rate", str(ctx.config.limits.masscan_rate),
        "-iL", str(targets_path),
        "-oA", str(prefix),
    ]
    result = run_command(argv, timeout=ctx.stage_timeout())
    if result.timed_out:
        raise StageFailed("nmap -sn timed out")

    xml_path = prefix.with_suffix(".xml")
    try:
        report = parse_nmap_xml(xml_path)
    except NmapParseError as exc:
        if result.returncode != 0:
            raise StageFailed(f"nmap -sn failed: {result.tail()}") from exc
        raise StageFailed(f"could not parse nmap discovery output: {exc}") from exc

    return [host.address for host in report.up_hosts]
