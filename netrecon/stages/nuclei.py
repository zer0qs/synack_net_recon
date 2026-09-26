"""Stage 7: optional nuclei network templates.

Off unless ``--active`` is passed *and* ``stages.nuclei`` is enabled: this is
the only stage that sends template-driven traffic, so it needs two independent
opt-ins. Rate-limited from the same config as every other stage, and pointed
only at ``ip:port`` pairs already confirmed open and in scope.
"""

from __future__ import annotations

from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext, run_command
from netrecon.core.state import utc_now
from netrecon.stages.base import StageFailed, StageResult, StageSkipped

NAME = "nuclei"

#: Template paths netrecon will not pass to nuclei, even if configured.
BLOCKED_TEMPLATE_TOKENS = ("fuzzing", "dos", "brute", "default-logins", "takeovers")


def validate_templates(templates: list[str]) -> list[str]:
    cleaned: list[str] = []
    for template in templates:
        value = template.strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered.startswith("-") or ".." in value:
            raise StageFailed(f"invalid nuclei template path: {template!r}")
        for blocked in BLOCKED_TEMPLATE_TOKENS:
            if blocked in lowered:
                raise StageFailed(
                    f"nuclei template {template!r} matches the blocked pattern "
                    f"{blocked!r}; netrecon does not run intrusive templates"
                )
        cleaned.append(value)
    if not cleaned:
        raise StageFailed("nuclei.templates is empty")
    return cleaned


def build_target_list(ctx: RunContext) -> list[str]:
    """``ip:port`` endpoints from the sweep checkpoint, re-filtered by scope."""
    payload = read_json(ctx.paths.open_ports, default={}) or {}
    hosts = payload.get("hosts") or {}
    enforced = ctx.scope.enforce(hosts.keys())
    allowed = set(enforced.allowed_str)

    endpoints: list[str] = []
    for ip, entries in sorted(hosts.items()):
        if ip not in allowed:
            continue
        host_part = f"[{ip}]" if ":" in ip else ip
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("protocol", "tcp") != "tcp":
                continue
            port = entry.get("port")
            if isinstance(port, int):
                endpoints.append(f"{host_part}:{port}")
    return endpoints


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)

    if not ctx.active:
        raise StageSkipped("nuclei needs --active; skipped")
    if not ctx.tools.has("nuclei"):
        raise StageSkipped("nuclei is not installed; skipped")

    templates = validate_templates(list(ctx.config.nuclei.templates))
    endpoints = build_target_list(ctx)
    if not endpoints:
        raise StageSkipped("no open TCP endpoints to test")

    targets_path = ctx.paths.targets_dir / "nuclei_targets.txt"
    targets_path.parent.mkdir(parents=True, exist_ok=True)
    targets_path.write_text("".join(f"{e}\n" for e in endpoints), encoding="utf-8")

    rate = ctx.config.limits.nuclei_rate
    log.warning(
        "active stage: nuclei against %d endpoint(s), templates=%s, <=%d rps",
        len(endpoints),
        ",".join(templates),
        rate,
    )

    if ctx.dry_run:
        log.warning("dry run: skipping nuclei execution")
        return StageResult(
            counts={"endpoints": len(endpoints)}, detail="dry run", backend="nuclei"
        )

    argv = [
        ctx.tools.path("nuclei"),
        "-list", str(targets_path),
        "-rate-limit", str(rate),
        "-concurrency", str(ctx.config.nuclei.concurrency),
        "-timeout", str(ctx.config.nuclei.timeout_seconds),
        "-severity", ctx.config.nuclei.severity,
        "-jsonl",
        "-output", str(ctx.paths.nuclei),
        "-no-color",
        "-silent",
        "-disable-update-check",
    ]
    for template in templates:
        argv += ["-templates", template]

    result = run_command(argv, timeout=ctx.stage_timeout())
    if result.timed_out:
        raise StageFailed("nuclei timed out")
    if result.returncode != 0 and not ctx.paths.nuclei.is_file():
        raise StageFailed(f"nuclei failed: {result.tail()}")

    findings = _load_findings(ctx)
    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(((finding.get("info") or {}).get("severity")) or "unknown").lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1

    write_json(
        ctx.paths.root / "nuclei_summary.json",
        {
            "generated_at": utc_now(),
            "endpoints_tested": len(endpoints),
            "templates": templates,
            "rate_limit": rate,
            "findings": len(findings),
            "by_severity": by_severity,
        },
    )

    log.info("nuclei reported %d finding(s): %s", len(findings), by_severity or "none")

    return StageResult(
        counts={"endpoints": len(endpoints), "findings": len(findings), **{f"sev_{k}": v for k, v in by_severity.items()}},
        outputs={"nuclei": ctx.paths.nuclei},
        backend="nuclei",
    )


def _load_findings(ctx: RunContext) -> list[dict]:
    """Read nuclei's JSONL output; tolerate a truncated final line."""
    import json

    path = ctx.paths.nuclei
    if not path.is_file():
        return []
    findings: list[dict] = []
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
