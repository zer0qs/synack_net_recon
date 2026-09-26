"""Stage 6: safe NSE scripts.

Guardrails, in order of strictness:

1. :data:`FORBIDDEN_CATEGORIES` can never be selected, by config or by flag.
2. Only :data:`ALLOWED_CATEGORIES` may be selected at all.
3. The expression handed to nmap *always* ANDs in ``safe`` and negates every
   forbidden category, so even a ``default`` script that nmap classifies as
   intrusive is excluded.
4. ``--script-args`` is not exposed. There is no way to pass credentials,
   wordlists or write operations through netrecon.

The resulting selection is read-only reconnaissance: banner, service and
metadata queries. No brute forcing, no exploitation, no denial of service.
"""

from __future__ import annotations

from netrecon.core.jsonio import write_json
from netrecon.core.runner import RunContext, run_command, run_parallel
from netrecon.core.state import utc_now
from netrecon.parse.nmap import Host, NmapParseError, parse_nmap_xml
from netrecon.stages.base import StageFailed, StageResult, StageSkipped
from netrecon.stages.services import HostTarget, _slug, load_targets, merge_script_output

NAME = "scripts"

#: Categories netrecon refuses to run under any configuration.
FORBIDDEN_CATEGORIES: frozenset[str] = frozenset(
    {
        "intrusive",
        "brute",
        "dos",
        "exploit",
        "malware",
        "vuln",
        "fuzzer",
        "external",
        "broadcast",
        "auth",
    }
)

#: Categories an operator may select.
ALLOWED_CATEGORIES: frozenset[str] = frozenset({"default", "discovery", "safe", "version"})


class ScriptPolicyError(Exception):
    """A script selection violated netrecon's policy."""


def validate_categories(categories: list[str]) -> list[str]:
    """Normalise and policy-check a list of NSE categories."""
    if not categories:
        raise ScriptPolicyError("no NSE categories selected")
    cleaned: list[str] = []
    for category in categories:
        lowered = category.strip().lower()
        if not lowered:
            continue
        if not lowered.isalpha():
            raise ScriptPolicyError(
                f"{category!r} is not a bare NSE category name; script expressions, "
                "file paths and wildcards are not accepted"
            )
        if lowered in FORBIDDEN_CATEGORIES:
            raise ScriptPolicyError(
                f"NSE category {lowered!r} is permanently blocked: netrecon does not "
                "run intrusive, brute-force, denial-of-service or exploit scripts"
            )
        if lowered not in ALLOWED_CATEGORIES:
            raise ScriptPolicyError(
                f"NSE category {lowered!r} is not permitted; allowed: "
                + ", ".join(sorted(ALLOWED_CATEGORIES))
            )
        if lowered not in cleaned:
            cleaned.append(lowered)
    if not cleaned:
        raise ScriptPolicyError("no usable NSE categories after validation")
    return cleaned


def build_script_expression(categories: list[str]) -> str:
    """Build the nmap ``--script`` expression, with the safety clauses forced on.

    Example::

        (default or discovery) and safe and not (brute or dos or exploit or ...)
    """
    cleaned = validate_categories(categories)
    selection = " or ".join(cleaned)
    exclusions = " or ".join(sorted(FORBIDDEN_CATEGORIES))
    return f"({selection}) and safe and not ({exclusions})"


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)

    if not ctx.tools.has("nmap"):
        raise StageFailed("NSE scripts require nmap")

    expression = build_script_expression(list(ctx.config.scripts.categories))

    targets = load_targets(ctx)
    if not targets:
        raise StageSkipped("no open ports from the sweep stage; no scripts to run")

    log.info(
        "running safe NSE scripts on %d host(s); selection: %s",
        len(targets),
        expression,
    )

    if ctx.dry_run:
        log.warning("dry run: skipping NSE execution")
        return StageResult(
            counts={"hosts": len(targets)}, detail="dry run", backend="nmap"
        )

    def worker(target: HostTarget) -> tuple[HostTarget, Host | None, str | None]:
        return _scan_host(ctx, target, expression)

    outcomes = run_parallel(
        targets, worker, concurrency=ctx.config.limits.concurrency, label="nse"
    )

    hosts: list[dict] = []
    failures: list[str] = []
    findings = 0
    for target, host, error in outcomes:
        if error:
            failures.append(f"{target.ip}: {error}")
            log.warning("NSE scripts failed for %s: %s", target.ip, error)
            continue
        if host is None:
            continue
        hosts.append(host.to_dict())
        findings += len(host.host_scripts) + sum(len(p.scripts) for p in host.ports)

    output_path = ctx.paths.root / "scripts.json"
    write_json(
        output_path,
        {
            "generated_at": utc_now(),
            "script_expression": expression,
            "categories": list(ctx.config.scripts.categories),
            "forbidden_categories": sorted(FORBIDDEN_CATEGORIES),
            "hosts_scanned": len(targets),
            "script_outputs": findings,
            "failures": failures,
            "hosts": hosts,
        },
    )

    if hosts and ctx.paths.services.is_file():
        merge_script_output(ctx.paths.services, hosts)

    log.info("collected %d script output(s) across %d host(s)", findings, len(hosts))

    return StageResult(
        counts={
            "hosts_scanned": len(targets),
            "hosts_reported": len(hosts),
            "script_outputs": findings,
            "failures": len(failures),
        },
        outputs={"scripts": output_path},
        backend="nmap",
        detail=f"{len(failures)} host(s) failed" if failures else None,
    )


def _scan_host(
    ctx: RunContext, target: HostTarget, expression: str
) -> tuple[HostTarget, Host | None, str | None]:
    try:
        address = ctx.scope.enforce_strict([target.ip])[0]
    except Exception as exc:  # ScopeViolation
        return target, None, str(exc)

    prefix = ctx.paths.nmap_dir / f"scripts_{_slug(target.ip)}"
    argv = [
        ctx.tools.path("nmap"),
        "-sV",
        "-Pn",
        "-n",
        f"-T{ctx.config.limits.nmap_timing}",
        "--max-rate", str(ctx.config.limits.masscan_rate),
        "--host-timeout", f"{ctx.config.limits.host_timeout_seconds}s",
        "--script", expression,
        "-p", target.port_spec,
        "-oA", str(prefix),
        str(address),
    ]
    result = run_command(argv, timeout=ctx.config.limits.host_timeout_seconds + 300)

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
