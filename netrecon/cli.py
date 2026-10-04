"""netrecon command-line interface."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import typer

from netrecon import __version__
from netrecon.core import logging_setup, pipeline
from netrecon.core import privileges as privileges_mod
from netrecon.core.config import Config, ConfigError
from netrecon.core.jsonio import write_json
from netrecon.core.scope import Scope, ScopeError
from netrecon.core.state import STATE_FILENAME, RunState, StateError, find_latest_run
from netrecon.core.tools import ToolRegistry, check_tools
from netrecon.report import build as report_build
from netrecon.stages.scripts import (
    ALLOWED_CATEGORIES,
    FORBIDDEN_CATEGORIES,
    ScriptPolicyError,
    build_script_expression,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Network reconnaissance for authorised engagements.\n\n"
        "netrecon wraps nmap, masscan/naabu, fping and (optionally) nuclei behind a "
        "scope-enforced, rate-capped pipeline. Every target is checked against the "
        "expanded in-scope set before any packet is sent."
    ),
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_STAGE_FAILED = 3
EXIT_ABORTED = 4


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"netrecon {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """netrecon - scope-enforced network reconnaissance."""


@app.command("check-tools")
def check_tools_command(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """Report which external tools are installed, and their versions."""
    logging_setup.configure()
    statuses = check_tools()
    privs = privileges_mod.detect()

    if json_output:
        typer.echo(
            _dumps(
                {
                    "netrecon_version": __version__,
                    "privileges": privs.to_dict(),
                    "tools": {name: status.to_dict() for name, status in statuses.items()},
                }
            )
        )
    else:
        typer.echo(f"netrecon {__version__}")
        typer.echo(f"privileges: {privs.describe()}")
        typer.echo("")
        typer.echo(f"{'TOOL':<10} {'STATUS':<12} {'VERSION':<16} REQUIRED FOR")
        typer.echo("-" * 72)
        for name, status in statuses.items():
            state = "installed" if status.available else "MISSING"
            typer.echo(
                f"{name:<10} {state:<12} {(status.version or '-'):<16} "
                f"{', '.join(status.spec.required_for)}"
            )
        missing = [s for s in statuses.values() if not s.available]
        if missing:
            typer.echo("")
            typer.echo("Install the missing tools with ./install.sh, or individually:")
            for status in missing:
                typer.echo(f"  {status.name:<10} {status.spec.install_hint}")

    required_missing = [s for s in statuses.values() if not s.available and s.name == "nmap"]
    raise typer.Exit(EXIT_STAGE_FAILED if required_missing else EXIT_OK)


@app.command("show-scope")
def show_scope_command(
    targets: Path = typer.Option(..., "--targets", "-t", help="File of in-scope IPs / CIDRs."),
    config_path: Path | None = typer.Option(None, "--config", "-c", help="YAML config file."),
    expand: bool = typer.Option(False, "--expand", help="Print every expanded address."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Parse and expand a scope file without scanning anything."""
    logging_setup.configure()
    config = _load_config(config_path)
    scope = _load_scope(targets, config)

    if json_output:
        payload = scope.summary()
        payload["rejected"] = [
            {"line": r.lineno, "raw": r.raw, "reason": r.reason} for r in scope.rejects
        ]
        if expand:
            payload["addresses"] = [str(a) for a in scope.addresses]
        typer.echo(_dumps(payload))
        raise typer.Exit(EXIT_OK)

    summary = scope.summary()
    typer.echo(f"scope file      : {summary['source']}")
    typer.echo(f"accepted entries: {summary['entries']}")
    typer.echo(f"rejected lines  : {summary['rejected_lines']}")
    typer.echo(f"in-scope hosts  : {summary['total_hosts']}")
    typer.echo(f"range           : {summary['first']} .. {summary['last']}")
    typer.echo(f"fingerprint     : {scope.fingerprint()[:16]}")

    for entry in scope.entries:
        typer.echo(f"  + line {entry.lineno}: {entry.raw} -> {entry.count} host(s) [{entry.kind}]")
    for reject in scope.rejects:
        typer.echo(f"  - line {reject.lineno}: {reject.raw!r} rejected: {reject.reason}")

    notable = scope.notable_addresses()
    for bucket, addresses in notable.items():
        typer.echo(f"  ! {len(addresses)} {bucket.replace('_', ' ')} address(es) in scope")

    if expand:
        typer.echo("")
        for address in scope.addresses:
            typer.echo(str(address))


@app.command("show-policy")
def show_policy_command() -> None:
    """Print the NSE script policy that netrecon enforces."""
    typer.echo("NSE categories netrecon permits:")
    for category in sorted(ALLOWED_CATEGORIES):
        typer.echo(f"  + {category}")
    typer.echo("")
    typer.echo("NSE categories netrecon refuses (cannot be enabled by config or flag):")
    for category in sorted(FORBIDDEN_CATEGORIES):
        typer.echo(f"  - {category}")
    typer.echo("")
    typer.echo("Effective --script expression for the default selection:")
    typer.echo(f"  {build_script_expression(['default', 'discovery'])}")
    typer.echo("")
    typer.echo("netrecon performs no brute forcing, exploitation or denial of service.")


@app.command("report")
def report_command(
    run_dir: Path = typer.Argument(..., help="A results/<run>/<timestamp>/ directory."),
    targets: Path | None = typer.Option(
        None, "--targets", "-t", help="Scope file (defaults to the run's scope.txt snapshot)."
    ),
) -> None:
    """Rebuild report.md and summary.json from an existing run directory."""
    logging_setup.configure()
    if not (run_dir / STATE_FILENAME).is_file():
        typer.secho(f"{run_dir} does not look like a netrecon run directory", fg="red", err=True)
        raise typer.Exit(EXIT_USAGE)

    try:
        state = RunState.load(run_dir)
    except StateError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    config = Config.from_dict(_strip_runtime_keys(state.config_snapshot))
    scope_file = targets or (run_dir / "scope.txt")
    scope = _load_scope(scope_file, config)

    ctx = pipeline.build_context(
        config=config,
        scope=scope,
        run_dir=run_dir,
        resuming=True,
        tools=ToolRegistry.detect(),
        privileges=privileges_mod.detect(),
        active=False,
        web=(run_dir / "webrecon.json").is_file(),
        full_ports=False,
        dry_run=False,
    )
    payload = report_build.build(ctx)
    typer.echo(f"report : {ctx.paths.report}")
    typer.echo(f"html   : {ctx.paths.report_html}")
    typer.echo(f"summary: {ctx.paths.summary}")
    typer.echo(
        f"{payload['totals']['hosts_reported']} host(s), "
        f"{payload['totals']['open_ports']} open port(s)"
    )


@app.command("scan")
def scan_command(
    targets: Path | None = typer.Option(
        None,
        "--targets",
        "-t",
        help="File of in-scope IPs / CIDRs, one per line. "
        "Optional when resuming: the run's own scope.txt snapshot is used.",
    ),
    config_path: Path | None = typer.Option(
        None, "--config", "-c", help="YAML config file (see configs/default.yaml)."
    ),
    run_name: str | None = typer.Option(None, "--run-name", help="Override config run_name."),
    output_dir: Path | None = typer.Option(None, "--output-dir", "-o", help="Override output dir."),
    rate: int | None = typer.Option(
        None, "--rate", help="Sweep packets per second (clamped to the hard maximum)."
    ),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Worker threads."),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Override the TCP sweep ports."),
    full_ports: bool = typer.Option(False, "--full-ports", help="Sweep 1-65535 instead of the curated set."),
    scripts_flag: bool = typer.Option(False, "--scripts", help="Enable safe NSE scripts (default+discovery)."),
    os_detect: bool = typer.Option(False, "--os-detect", help="Enable OS detection (needs raw sockets)."),
    banners: bool = typer.Option(False, "--banners", help="Grab banners via the safe NSE banner script."),
    active: bool = typer.Option(
        False, "--active", help="Enable the nuclei stage (template-driven probes, rate-capped)."
    ),
    hidden_paths: bool = typer.Option(
        False,
        "--hidden-paths",
        help=(
            "With --web, also GET a curated list of commonly exposed files "
            "(.git/HEAD, .env, backups, Actuator...). Generates 404s in the target's logs."
        ),
    ),
    cve_feed: Path | None = typer.Option(
        None,
        "--cve-feed",
        help=(
            "Local NVD/CVE JSON feed used to correlate detected versions. "
            "netrecon never downloads a feed; point this at a file you fetched."
        ),
    ),
    service_recon: bool = typer.Option(
        False,
        "--service-recon",
        help=(
            "Deep per-service analysis of evidence already collected "
            "(TLS, SMB, SSH, databases, DNS, SNMP, mail, HTTP). Sends no packets."
        ),
    ),
    web: bool = typer.Option(
        False,
        "--web",
        help=(
            "Enable read-only web recon on in-scope HTTP(S) ports: GET only, "
            "plus JavaScript analysis. No form submission or path brute forcing."
        ),
    ),
    skip_discovery: bool = typer.Option(
        False, "--skip-discovery", help="Treat every in-scope address as live."
    ),
    stages: str | None = typer.Option(
        None, "--stages", help="Comma-separated stage allowlist, e.g. 'discovery,sweep'."
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume the latest run for this run name."),
    resume_dir: Path | None = typer.Option(
        None, "--resume-dir", help="Resume a specific run directory."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan the run without sending packets."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the authorisation confirmation prompt."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging on the console."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Warnings and errors only."),
) -> None:
    """Run the reconnaissance pipeline against an authorised scope file."""
    logging_setup.configure(verbose=verbose, quiet=quiet)

    try:
        config = _load_config(config_path)
        _apply_overrides(
            config,
            run_name=run_name,
            output_dir=output_dir,
            rate=rate,
            concurrency=concurrency,
            ports=ports,
            scripts_flag=scripts_flag,
            os_detect=os_detect,
            banners=banners,
            active=active,
            web=web,
            hidden_paths=hidden_paths,
            cve_feed=cve_feed,
            service_recon=service_recon,
            skip_discovery=skip_discovery,
            stages=stages,
        )
    except (ConfigError, ScopeError, ScriptPolicyError) as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    resume_from: Path | None = None
    if resume_dir is not None:
        resume_from = resume_dir
    elif resume:
        base = Path(config.output_dir) / config.run_name
        resume_from = find_latest_run(base)
        if resume_from is None:
            typer.secho(
                f"--resume: no previous run with a checkpoint found under {base}",
                fg="red",
                err=True,
            )
            raise typer.Exit(EXIT_USAGE)

    # Resuming already fixed the scope: it is snapshotted in the run directory,
    # and prepare_run_dir refuses a checkpoint whose scope fingerprint differs.
    # Defaulting to that snapshot is therefore safer than making the operator
    # retype --targets, which is one more chance to resume against the wrong
    # scope file.
    if targets is None:
        if resume_from is None:
            typer.secho(
                "error: --targets is required unless you are resuming a run",
                fg="red",
                err=True,
            )
            raise typer.Exit(EXIT_USAGE)
        snapshot = Path(resume_from) / "scope.txt"
        if not snapshot.is_file():
            typer.secho(
                f"error: {resume_from} has no scope.txt snapshot; "
                "pass --targets with the original scope file",
                fg="red",
                err=True,
            )
            raise typer.Exit(EXIT_USAGE)
        targets = snapshot

    try:
        scope = _load_scope(targets, config)
    except (ConfigError, ScopeError, ScriptPolicyError) as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    try:
        run_dir, resuming = pipeline.prepare_run_dir(config, resume_from=resume_from)
    except (pipeline.PipelineError, OSError) as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    # Re-configure logging now that we know where run.log belongs.
    logging_setup.configure(run_dir / "run.log", verbose=verbose, quiet=quiet)

    try:
        ctx = pipeline.build_context(
            config=config,
            scope=scope,
            run_dir=run_dir,
            resuming=resuming,
            tools=ToolRegistry.detect(),
            privileges=privileges_mod.detect(),
            active=active,
            web=web,
            full_ports=full_ports,
            dry_run=dry_run,
        )
    except StateError as exc:
        typer.secho(f"error: {exc}", fg="red", err=True)
        raise typer.Exit(EXIT_USAGE) from exc

    typer.echo(pipeline.preflight_summary(ctx), err=True)

    if not yes and not dry_run:
        if not sys.stdin.isatty():
            typer.secho(
                "refusing to scan without confirmation: stdin is not a terminal, so "
                "pass --yes to confirm you have written authorisation for this scope.",
                fg="red",
                err=True,
            )
            raise typer.Exit(EXIT_ABORTED)
        confirmed = typer.confirm(
            f"Confirm you are authorised to scan these {len(scope)} host(s)", default=False
        )
        if not confirmed:
            typer.secho("aborted by operator", fg="yellow", err=True)
            raise typer.Exit(EXIT_ABORTED)

    write_json(
        run_dir / "preflight.json",
        {
            "netrecon_version": __version__,
            "scope": scope.summary(),
            "config": config.to_dict(),
            "privileges": ctx.privileges.to_dict(),
            "tools": ctx.tools.to_dict(),
            "active": active,
            "web": web,
            "hidden_paths": hidden_paths,
            "service_recon": config.stages.servicerecon,
            "dry_run": dry_run,
        },
    )

    outcome = pipeline.execute(ctx)

    typer.echo("", err=True)
    typer.echo(f"run directory : {ctx.paths.root}", err=True)
    if outcome.report:
        totals = outcome.report["totals"]
        typer.echo(
            f"results       : {totals['live_hosts']} live host(s), "
            f"{totals['open_ports']} open port(s), "
            f"{totals['notable_observations']} notable observation(s)",
            err=True,
        )
        typer.echo(f"report (md)   : {ctx.paths.report}", err=True)
        typer.echo(f"report (html) : {ctx.paths.report_html}", err=True)
        typer.echo(f"machine JSON  : {ctx.paths.summary}", err=True)
    if outcome.skipped_stages:
        typer.echo(f"skipped stages: {', '.join(outcome.skipped_stages)}", err=True)
    if outcome.failed_stages:
        typer.secho(
            f"failed stages : {', '.join(outcome.failed_stages)} "
            f"(resume with --resume-dir {ctx.paths.root})",
            fg="red",
            err=True,
        )
        raise typer.Exit(EXIT_STAGE_FAILED)

    raise typer.Exit(EXIT_OK)


# -- helpers -------------------------------------------------------------


def _load_config(path: Path | None) -> Config:
    if path is None:
        default = Path("configs/default.yaml")
        if default.is_file():
            return Config.load(default)
        return Config()
    return Config.load(path)


def _load_scope(path: Path, config: Config) -> Scope:
    return Scope.from_file(
        path,
        max_hosts=config.scope.max_hosts,
        include_network_broadcast=config.scope.include_network_broadcast,
    )


def _apply_overrides(
    config: Config,
    *,
    run_name: str | None,
    output_dir: Path | None,
    rate: int | None,
    concurrency: int | None,
    ports: str | None,
    scripts_flag: bool,
    os_detect: bool,
    banners: bool,
    active: bool,
    web: bool,
    hidden_paths: bool,
    cve_feed: Path | None,
    service_recon: bool,
    skip_discovery: bool,
    stages: str | None,
) -> None:
    if run_name:
        config.run_name = run_name
    if output_dir:
        config.output_dir = str(output_dir)
    if rate is not None:
        config.limits.masscan_rate = rate
    if concurrency is not None:
        config.limits.concurrency = concurrency
    if ports:
        config.ports.sweep = ports
    if scripts_flag:
        config.stages.scripts = True
    if os_detect:
        config.stages.os_detect = True
    if banners:
        config.services.banner_grab = True
    # The nuclei stage needs the explicit --active opt-in; without it the stage
    # is off regardless of what the config says. The web stage needs --web the
    # same way: both send application-layer traffic, so neither turns itself on.
    config.stages.nuclei = bool(active)
    config.stages.webrecon = bool(web)
    # Service analysis reads what is already on disk, so it is safe to leave on
    # whenever the config asks for it; the flag only turns it on.
    config.stages.servicerecon = bool(service_recon) or config.stages.servicerecon
    if hidden_paths:
        if not web:
            raise ConfigError("--hidden-paths only applies with --web")
        config.webrecon.hidden_paths = True
    if cve_feed is not None:
        if not Path(cve_feed).is_file():
            raise ConfigError(f"--cve-feed: file not found: {cve_feed}")
        config.webrecon.cve_feed = str(cve_feed)
    if skip_discovery:
        config.discovery.method = "skip"

    if stages:
        requested = {name.strip().lower() for name in stages.split(",") if name.strip()}
        known = {
            "discovery",
            "sweep",
            "services",
            "scripts",
            "nuclei",
            "webrecon",
            "servicerecon",
            "os_detect",
        }
        unknown = requested - known
        if unknown:
            raise ConfigError(
                "unknown stage(s): " + ", ".join(sorted(unknown)) + "; known: " + ", ".join(sorted(known))
            )
        for name in known:
            setattr(config.stages, name, name in requested)
        if "nuclei" in requested and not active:
            raise ConfigError("the nuclei stage also requires --active")
        if "webrecon" in requested and not web:
            raise ConfigError("the webrecon stage also requires --web")
        if "servicerecon" in requested:
            config.stages.servicerecon = True

    # Re-validate so clamping and warnings reflect the overrides.
    config.validate()
    if config.stages.scripts:
        build_script_expression(list(config.scripts.categories))


def _strip_runtime_keys(snapshot: dict) -> dict:
    data = {k: v for k, v in (snapshot or {}).items() if k != "warnings"}
    return data


def _dumps(payload: object) -> str:
    import json

    return json.dumps(payload, indent=2, default=str)


def entrypoint() -> None:  # pragma: no cover - console_scripts shim
    try:
        app()
    except KeyboardInterrupt:
        logging.getLogger("netrecon").warning("interrupted by operator")
        raise SystemExit(EXIT_ABORTED) from None


if __name__ == "__main__":  # pragma: no cover
    entrypoint()
