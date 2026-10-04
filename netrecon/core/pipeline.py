"""Pipeline orchestration: pre-flight banner, stage sequencing, checkpointing."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from netrecon import __version__
from netrecon.core.config import (
    MASSCAN_RATE_HARD_MAX,
    MASSCAN_RATE_WARN_THRESHOLD,
    NUCLEI_RATE_HARD_MAX,
    WEBRECON_RATE_HARD_MAX,
    Config,
)
from netrecon.core.logging_setup import Timer
from netrecon.core.privileges import DEGRADE_MESSAGE, Privileges
from netrecon.core.runner import RunContext, RunPaths
from netrecon.core.scope import Scope
from netrecon.core.state import RunState, timestamp_dirname
from netrecon.core.tools import ToolRegistry
from netrecon.report import build as report_build
from netrecon.stages import (
    discovery,
    nuclei,
    scripts,
    servicerecon,
    services,
    sweep,
    webrecon,
)
from netrecon.stages.base import StageFailed, StageResult, StageSkipped

log = logging.getLogger("netrecon.pipeline")

#: Ordered pipeline. ``config_key`` maps to the ``stages:`` config section.
STAGE_ORDER: tuple[tuple[str, str, Callable[[RunContext], StageResult]], ...] = (
    ("discovery", "discovery", discovery.run),
    ("sweep", "sweep", sweep.run),
    ("services", "services", services.run),
    ("scripts", "scripts", scripts.run),
    ("nuclei", "nuclei", nuclei.run),
    ("webrecon", "webrecon", webrecon.run),
    ("servicerecon", "servicerecon", servicerecon.run),
)


class PipelineError(Exception):
    """The run cannot proceed."""


@dataclass
class RunOutcome:
    context: RunContext
    failed_stages: list[str]
    skipped_stages: list[str]
    report: dict | None

    @property
    def ok(self) -> bool:
        return not self.failed_stages


def prepare_run_dir(config: Config, *, resume_from: Path | None) -> tuple[Path, bool]:
    """Return the run directory and whether we are resuming into it."""
    if resume_from is not None:
        if not resume_from.is_dir():
            raise PipelineError(f"resume directory does not exist: {resume_from}")
        return resume_from, True
    run_dir = Path(config.output_dir) / config.run_name / timestamp_dirname()
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir, False


def build_context(
    *,
    config: Config,
    scope: Scope,
    run_dir: Path,
    resuming: bool,
    tools: ToolRegistry,
    privileges: Privileges,
    active: bool,
    full_ports: bool,
    dry_run: bool,
    web: bool = False,
) -> RunContext:
    paths = RunPaths(run_dir)
    paths.ensure()

    fingerprint = scope.fingerprint()
    if resuming:
        state = RunState.load(run_dir)
        state.check_scope(fingerprint)
        log.info("resuming run in %s", run_dir)
    else:
        state = RunState.create(
            run_dir,
            run_name=config.run_name,
            scope_fingerprint=fingerprint,
            scope_source=scope.source,
            netrecon_version=__version__,
            config_snapshot=config.to_dict(),
        )

    # Snapshot the expanded scope next to the results, so a report can always
    # be audited against exactly what was authorised.
    scope.write_targets(paths.scope_snapshot)

    return RunContext(
        config=config,
        scope=scope,
        paths=paths,
        state=state,
        tools=tools,
        privileges=privileges,
        active=active,
        web=web,
        full_ports=full_ports,
        dry_run=dry_run,
    )


def preflight_summary(ctx: RunContext) -> str:
    """The authorisation reminder and effective settings, shown before scanning."""
    cfg = ctx.config
    scope_summary = ctx.scope.summary()
    enabled = [name for name, key, _ in STAGE_ORDER if getattr(cfg.stages, key)]
    if cfg.stages.os_detect:
        enabled.append("os_detect")

    lines = [
        "",
        "=" * 72,
        " netrecon - authorised reconnaissance only",
        "=" * 72,
        "",
        " You are about to send scan traffic to the hosts listed below. Only run",
        " this against systems you have written authorisation to test, and keep",
        " that authorisation and its date range to hand. Scanning outside an",
        " agreed scope is likely unlawful in most jurisdictions.",
        "",
        f" Scope file        : {scope_summary['source']}",
        f" In-scope hosts    : {scope_summary['total_hosts']} "
        f"(IPv4 {scope_summary['ipv4_hosts']}, IPv6 {scope_summary['ipv6_hosts']})",
        f" Address range     : {scope_summary['first']} .. {scope_summary['last']}",
        f" Scope entries     : {scope_summary['entries']} accepted, "
        f"{scope_summary['rejected_lines']} rejected",
        f" Run directory     : {ctx.paths.root}",
        "",
        f" Sweep rate cap    : {cfg.limits.masscan_rate} pps "
        f"(hard max {MASSCAN_RATE_HARD_MAX})",
        f" nuclei rate cap   : {cfg.limits.nuclei_rate} rps "
        f"(hard max {NUCLEI_RATE_HARD_MAX})",
        f" Concurrency       : {cfg.limits.concurrency}",
        f" nmap timing       : -T{cfg.limits.nmap_timing}",
        f" TCP ports swept   : {_abbrev(ctx.sweep_ports())}",
        f" Stages enabled    : {', '.join(enabled) or 'none'}",
        f" Active stage      : {'ENABLED (nuclei)' if ctx.active else 'disabled'}",
        f" Web recon         : {'ENABLED (GET only)' if ctx.web else 'disabled'}",
        f" Service analysis  : "
        f"{'ENABLED (offline)' if cfg.stages.servicerecon else 'disabled'}",
        f" Privileges        : {ctx.privileges.describe()}",
        f" Tools available   : {', '.join(ctx.tools.available()) or 'none'}",
    ]

    if ctx.tools.missing():
        lines.append(f" Tools missing     : {', '.join(ctx.tools.missing())}")

    notable = ctx.scope.notable_addresses()
    if notable:
        lines.append("")
        for bucket, addresses in notable.items():
            lines.append(
                f" ! scope includes {len(addresses)} {bucket.replace('_', ' ')} "
                f"address(es), e.g. {addresses[0]}"
            )

    if ctx.scope.rejects:
        lines.append("")
        lines.append(f" ! {len(ctx.scope.rejects)} scope line(s) were rejected:")
        for reject in ctx.scope.rejects[:5]:
            lines.append(f"     line {reject.lineno}: {reject.raw!r} - {reject.reason}")
        if len(ctx.scope.rejects) > 5:
            lines.append(f"     ... and {len(ctx.scope.rejects) - 5} more")

    if cfg.limits.masscan_rate > MASSCAN_RATE_WARN_THRESHOLD:
        lines += [
            "",
            f" ! Sweep rate {cfg.limits.masscan_rate} pps is above the safe default",
            f"   {MASSCAN_RATE_WARN_THRESHOLD} pps. High packet rates can disrupt",
            "   fragile hosts and saturate small links. Confirm this is agreed.",
        ]

    for warning in cfg.warnings:
        lines.append(f" ! {warning}")

    if not ctx.privileges.raw_sockets:
        lines += ["", *(f" {line}" for line in DEGRADE_MESSAGE.splitlines())]

    if ctx.active:
        lines += [
            "",
            " ! --active enables nuclei network templates, which send",
            "   template-driven probes rather than passive fingerprinting.",
        ]

    if ctx.web:
        web = cfg.webrecon
        lines += [
            "",
            " ! --web enables application-layer web reconnaissance against any",
            "   in-scope HTTP(S) port that was found open. It issues HTTP GET",
            "   requests only: no form submission, no authentication, no redirect",
            "   following and no path brute forcing. Paths requested are '/',",
            "   robots.txt, sitemap.xml and scripts the page itself links.",
            f"   Rate cap: {web.rate_per_second} rps (hard max {WEBRECON_RATE_HARD_MAX}); "
            f"up to {web.max_endpoints} endpoint(s),",
            f"   {web.max_scripts_per_endpoint} script(s) each, "
            f"{web.max_response_bytes // 1024} KiB per response.",
        ]
        if web.hidden_paths:
            lines += [
                f"   --hidden-paths is ON: up to {web.max_hidden_paths} curated path(s)",
                "   per endpoint will be requested. These are GETs of commonly exposed",
                "   files, not a directory brute-force wordlist, but they WILL appear",
                "   as 404s in the target's access log. Confirm this is agreed.",
            ]
        if web.cve_feed:
            lines.append(f"   CVE feed (local file): {web.cve_feed}")
        if not web.verify_tls:
            lines.append(
                "   TLS certificates are not verified (in-scope hosts often use"
            )
            lines.append("   self-signed certificates); certificate issues are reported.")
        if not web.redact_secrets:
            lines += [
                " ! webrecon.redact_secrets is OFF: any credential-looking string found",
                "   in JavaScript will be written to the report in full. Treat the run",
                "   directory as engagement secrets.",
            ]

    if ctx.dry_run:
        lines += ["", " DRY RUN: no packets will be sent."]

    lines += ["", "=" * 72, ""]
    return "\n".join(lines)


def execute(ctx: RunContext) -> RunOutcome:
    """Run every enabled stage, checkpointing as it goes."""
    failed: list[str] = []
    skipped: list[str] = []

    for name, config_key, runner in STAGE_ORDER:
        if not getattr(ctx.config.stages, config_key):
            if not ctx.state.is_completed(name):
                ctx.state.skip(name, detail="disabled in config")
            continue

        if ctx.state.is_completed(name):
            log.info("stage %s already completed in this run directory; skipping", name)
            continue

        ctx.state.begin(name)
        timer = Timer()
        try:
            with timer:
                result = runner(ctx)
        except StageSkipped as exc:
            ctx.state.skip(name, detail=str(exc))
            skipped.append(name)
            log.warning("stage %s skipped: %s", name, exc)
            continue
        except StageFailed as exc:
            ctx.state.fail(name, duration=timer.elapsed, detail=str(exc))
            failed.append(name)
            log.error("stage %s failed: %s", name, exc)
            if name in {"discovery", "sweep"}:
                log.error("stopping: later stages depend on %s", name)
                break
            continue
        except Exception as exc:  # noqa: BLE001 - checkpoint before re-raising
            ctx.state.fail(name, duration=timer.elapsed, detail=f"{type(exc).__name__}: {exc}")
            log.exception("stage %s raised an unexpected error", name)
            failed.append(name)
            break

        ctx.state.complete(
            name,
            duration=timer.elapsed,
            counts=result.counts,
            outputs=result.outputs,
            detail=result.detail,
            backend=result.backend,
        )
        log.info(
            "stage %s completed in %.1fs",
            name,
            timer.elapsed,
            extra={"counts": result.counts, "backend": result.backend},
        )

    report_payload = None
    if not ctx.dry_run:
        timer = Timer()
        ctx.state.begin("report")
        try:
            with timer:
                report_payload = report_build.build(ctx)
        except Exception as exc:  # noqa: BLE001
            ctx.state.fail("report", duration=timer.elapsed, detail=str(exc))
            log.exception("report generation failed")
            failed.append("report")
        else:
            ctx.state.complete(
                "report",
                duration=timer.elapsed,
                counts=report_build.stage_counts(report_payload),
                outputs={"report": ctx.paths.report, "summary": ctx.paths.summary},
            )

    ctx.state.finish()

    for stage_name, duration in sorted(ctx.state.timings(), key=lambda kv: -kv[1]):
        log.debug("timing %s=%.1fs", stage_name, duration)

    return RunOutcome(ctx, failed, skipped, report_payload)


def _abbrev(value: str, limit: int = 48) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."
