"""Stage 7: optional nuclei network templates.

Off unless ``--active`` is passed *and* ``stages.nuclei`` is enabled: this is
the only stage that sends template-driven traffic, so it needs two independent
opt-ins. Rate-limited from the same config as every other stage, and pointed
only at ``ip:port`` pairs already confirmed open and in scope.

Guardrails, in order of strictness:

1. :data:`EXCLUDED_TAGS` is passed to every invocation and cannot be shortened.
   Config may *add* tags via ``nuclei.exclude_tags``; it can never subtract.
   This mirrors :data:`netrecon.stages.scripts.FORBIDDEN_CATEGORIES`.
2. :data:`BLOCKED_TEMPLATE_TOKENS` rejects intrusive template *paths* before
   they reach the argv.
3. ``-no-interactsh`` is unconditional: out-of-band templates make the target
   call back to a third-party interactsh server, which hands target traffic and
   hostnames to infrastructure the client never agreed to involve.
4. Rate limit and concurrency are both passed and both clamped in config.
5. Every finding is re-checked against the scope *after* the scan. Templates
   follow redirects, so nuclei can and does report an address netrecon never
   authorised; such a finding is dropped before it can reach a report.

"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext, run_command
from netrecon.core.state import utc_now
from netrecon.stages.base import StageFailed, StageResult, StageSkipped

NAME = "nuclei"

#: Template paths netrecon will not pass to nuclei, even if configured.
BLOCKED_TEMPLATE_TOKENS = ("fuzzing", "dos", "brute", "default-logins", "takeovers")

#: Template tags excluded on every invocation. Not configurable away: these are
#: the tag families that fuzz parameters, mutate payloads, brute-force
#: credentials or deliberately exhaust the target.
EXCLUDED_TAGS: tuple[str, ...] = ("fuzz", "fuzzing", "intrusive", "dos", "brute-force")


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


def build_excluded_tags(extra: list[str] | None = None) -> list[str]:
    """:data:`EXCLUDED_TAGS` plus any operator additions, in that order.

    The mandatory tags are prepended unconditionally, so no configuration -
    including one that lists them itself - can remove or reorder them away.
    """
    tags = list(EXCLUDED_TAGS)
    for tag in extra or []:
        lowered = str(tag).strip().lower()
        if lowered and lowered not in tags:
            tags.append(lowered)
    return tags


def build_target_list(ctx: RunContext) -> list[str]:
    """``ip:port`` endpoints from the sweep checkpoint, re-filtered by scope."""
    payload = read_json(ctx.paths.open_ports, default={}) or {}
    hosts = payload.get("hosts")
    if not isinstance(hosts, dict):
        # A truncated or hand-edited checkpoint can hold a list here; treat it
        # as no data rather than letting AttributeError escape the stage.
        raise StageFailed(f"{ctx.paths.open_ports} is not in the expected format")
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


def build_argv(ctx: RunContext, templates: list[str], targets_path: Path) -> list[str]:
    """The full nuclei argv, including the non-negotiable safety flags."""
    cfg = ctx.config.nuclei
    argv = [
        ctx.tools.path("nuclei"),
        "-list", str(targets_path),
        "-rate-limit", str(ctx.config.limits.nuclei_rate),
        "-concurrency", str(cfg.concurrency),
        "-timeout", str(cfg.timeout_seconds),
        "-severity", cfg.severity,
        "-exclude-tags", ",".join(build_excluded_tags(list(cfg.exclude_tags))),
        # OOB callbacks route target traffic to a third-party interactsh server;
        # a recon run does not do that without the client agreeing to it.
        "-no-interactsh",
        "-jsonl",
        "-output", str(ctx.paths.nuclei),
        "-no-color",
        "-silent",
        "-disable-update-check",
    ]
    for template in templates:
        argv += ["-templates", template]
    return argv


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

    cfg = ctx.config.nuclei
    rate = ctx.config.limits.nuclei_rate
    excluded = build_excluded_tags(list(cfg.exclude_tags))
    log.warning(
        "active stage: nuclei against %d endpoint(s), templates=%s, severity=%s, "
        "<=%d rps, concurrency=%d, excluding tags=%s",
        len(endpoints),
        ",".join(templates),
        cfg.severity,
        rate,
        cfg.concurrency,
        ",".join(excluded),
    )

    if ctx.dry_run:
        log.warning("dry run: skipping nuclei execution")
        return StageResult(
            counts={"endpoints": len(endpoints)}, detail="dry run", backend="nuclei"
        )

    argv = build_argv(ctx, templates, targets_path)

    result = run_command(argv, timeout=ctx.stage_timeout())

    if result.timed_out:
        raise StageFailed("nuclei timed out")
    if result.returncode != 0 and not ctx.paths.nuclei.is_file():
        raise StageFailed(f"nuclei failed: {result.tail()}")

    findings, dropped = _load_findings(ctx)
    if dropped:
        log.warning(
            "dropped %d nuclei finding(s) for addresses outside the scope "
            "(templates follow redirects; those hosts were never authorised)",
            dropped,
        )
        _rewrite_findings(ctx, findings)

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
            "severity": cfg.severity,
            "excluded_tags": excluded,
            "interactsh": False,
            "rate_limit": rate,
            "concurrency": cfg.concurrency,
            "findings": len(findings),
            "out_of_scope_dropped": dropped,
            "by_severity": by_severity,
        },
    )

    log.info("nuclei reported %d finding(s): %s", len(findings), by_severity or "none")

    return StageResult(
        counts={
            "endpoints": len(endpoints),
            "findings": len(findings),
            "out_of_scope_dropped": dropped,
            **{f"sev_{k}": v for k, v in by_severity.items()},
        },
        outputs={"nuclei": ctx.paths.nuclei},
        backend="nuclei",
    )


def finding_address(record: dict) -> str | None:
    """The address a finding is about, or None if it does not name one.

    Nuclei reports the resolved ``ip`` plus a ``host``/``matched-at`` that may
    be a bare ``ip:port``, a URL, or - after a redirect - a hostname.
    """
    for key in ("ip", "host", "matched-at", "matched_at"):
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = _strip_port(value.strip())
        if candidate:
            return candidate
    return None


def _strip_port(value: str) -> str:
    """Reduce ``host``/``matched-at`` to a bare address or hostname."""
    if "://" in value:
        return urlsplit(value).hostname or ""
    if value.startswith("["):  # [v6]:port
        return value[1:].partition("]")[0]
    if value.count(":") == 1:  # v4:port
        return value.rsplit(":", 1)[0]
    return value  # bare v4 address, bare v6 address, or hostname


def _load_findings(ctx: RunContext) -> tuple[list[dict], int]:
    """Read nuclei's JSONL output, dropping anything outside the scope.

    Tolerates a truncated final line. Returns the kept findings and the number
    dropped; a record that names no address at all is dropped too, since there
    is nothing to check it against.
    """
    path = ctx.paths.nuclei
    if not path.is_file():
        return [], 0
    findings: list[dict] = []
    dropped = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        address = finding_address(record)
        if address is None or address not in ctx.scope:
            dropped += 1
            continue
        findings.append(record)
    return findings, dropped


def _rewrite_findings(ctx: RunContext, findings: list[dict]) -> None:
    """Replace nuclei's output with the scope-filtered findings only."""
    ctx.paths.nuclei.write_text(
        "".join(f"{json.dumps(finding, sort_keys=True)}\n" for finding in findings),
        encoding="utf-8",
    )
