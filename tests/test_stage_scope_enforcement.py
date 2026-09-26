"""Tests that every stage re-enforces scope on the data it reads.

The threat model: a tool reports a host we never asked about (a broadcast reply,
a misconfigured router, a masscan retransmit against a rewritten address), or a
checkpoint file on disk is edited between stages. Neither may widen the scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netrecon.core.config import Config
from netrecon.core.jsonio import write_json
from netrecon.core.scope import ScopeViolation
from netrecon.stages import discovery, nuclei, services, sweep
from netrecon.stages.base import StageFailed, StageSkipped

OUT_OF_SCOPE = "192.168.99.99"
IN_SCOPE = "10.10.10.5"


def _write_sweep_results(ctx, hosts: dict[str, list[dict]]) -> None:
    write_json(
        ctx.paths.open_ports,
        {
            "generated_at": "2024-05-20T10:13:20Z",
            "backend": "masscan",
            "hosts": hosts,
        },
    )


# -- live_hosts.txt ------------------------------------------------------


def test_live_hosts_reader_filters_a_tampered_file(make_context):
    ctx = make_context()
    ctx.paths.live_hosts.write_text(
        f"{IN_SCOPE}\n{OUT_OF_SCOPE}\n8.8.8.8\n10.10.10.20\n", encoding="utf-8"
    )
    assert ctx.live_hosts() == [IN_SCOPE, "10.10.10.20"]


def test_live_hosts_reader_ignores_junk_lines(make_context):
    ctx = make_context()
    ctx.paths.live_hosts.write_text(
        f"{IN_SCOPE}\nweb01.internal\n\n  \n{IN_SCOPE}:80\n", encoding="utf-8"
    )
    assert ctx.live_hosts() == [IN_SCOPE]


def test_live_hosts_reader_returns_empty_when_absent(make_context):
    assert make_context().live_hosts() == []


# -- discovery -----------------------------------------------------------


def test_discovery_target_file_contains_only_the_scope(make_context):
    ctx = make_context()
    path, count = ctx.targets_file("discovery_targets.txt")
    assert count == len(ctx.scope)
    written = path.read_text().split()
    assert OUT_OF_SCOPE not in written
    assert written == [str(a) for a in ctx.scope.addresses]


def test_discovery_drops_out_of_scope_replies(make_context, monkeypatch):
    ctx = make_context()

    def fake_fping(_ctx, _targets):
        # fping "reports" a host that was never in the target file.
        return [IN_SCOPE, OUT_OF_SCOPE, "10.10.10.20"]

    monkeypatch.setattr(discovery, "_run_fping", fake_fping)
    result = discovery.run(ctx)

    assert result.counts["live"] == 2
    assert result.counts["out_of_scope_dropped"] == 1
    assert OUT_OF_SCOPE not in ctx.paths.live_hosts.read_text()


def test_discovery_skip_mode_marks_whole_scope_live(make_context):
    config = Config()
    config.discovery.method = "skip"
    ctx = make_context(config=config)
    result = discovery.run(ctx)
    assert result.counts["live"] == len(ctx.scope)
    assert result.backend == "skip"
    assert ctx.paths.live_hosts.read_text().split() == [str(a) for a in ctx.scope.addresses]


def test_discovery_backend_prefers_nmap_when_unprivileged(make_context, unprivileged):
    ctx = make_context(privileges=unprivileged)
    assert discovery.choose_backend(ctx) == "nmap"


def test_discovery_backend_prefers_fping_when_privileged(make_context):
    assert discovery.choose_backend(make_context()) == "fping"


def test_discovery_requires_a_tool(make_context, no_tools):
    ctx = make_context(tools=no_tools)
    with pytest.raises(StageFailed, match="fping or nmap"):
        discovery.choose_backend(ctx)


# -- sweep ---------------------------------------------------------------


def test_sweep_skips_when_no_live_hosts(make_context):
    with pytest.raises(StageSkipped, match="no live hosts"):
        sweep.run(make_context())


def test_sweep_refuses_a_tampered_live_hosts_file(make_context, monkeypatch):
    """An out-of-scope host in live_hosts.txt must not reach the tool argv."""
    ctx = make_context()
    ctx.paths.live_hosts.write_text(f"{IN_SCOPE}\n{OUT_OF_SCOPE}\n", encoding="utf-8")

    called: list[str] = []

    def fake_masscan(_ctx, targets: Path, *_args):
        called.append(targets.read_text())
        return []

    monkeypatch.setattr(sweep, "_run_masscan", fake_masscan)
    sweep.run(ctx)

    assert called, "the sweep backend should have been invoked"
    assert OUT_OF_SCOPE not in called[0]
    assert IN_SCOPE in called[0]


def test_sweep_drops_out_of_scope_open_ports(make_context, monkeypatch):
    from netrecon.parse.masscan import OpenPort

    ctx = make_context()
    ctx.paths.live_hosts.write_text(f"{IN_SCOPE}\n", encoding="utf-8")

    monkeypatch.setattr(
        sweep,
        "_run_masscan",
        lambda *_args: [
            OpenPort(IN_SCOPE, 22),
            OpenPort(OUT_OF_SCOPE, 445),
            OpenPort("8.8.8.8", 53),
        ],
    )
    result = sweep.run(ctx)

    payload = json.loads(ctx.paths.open_ports.read_text())
    assert list(payload["hosts"]) == [IN_SCOPE]
    assert result.counts["out_of_scope_dropped"] == 2
    assert result.counts["open_ports"] == 1


def test_sweep_backend_selection(make_context, unprivileged, no_tools):
    assert sweep.choose_backend(make_context()) == "masscan"
    assert sweep.choose_backend(make_context(privileges=unprivileged)) == "naabu"
    with pytest.raises(StageFailed, match="none is installed"):
        sweep.choose_backend(make_context(tools=no_tools))


def test_explicit_masscan_backend_fails_loudly_when_unprivileged(make_context, unprivileged):
    config = Config()
    config.sweep.backend = "masscan"
    ctx = make_context(config=config, privileges=unprivileged)
    with pytest.raises(StageFailed, match="raw sockets"):
        sweep.choose_backend(ctx)


def test_sweep_uses_the_configured_rate_cap(make_context, monkeypatch):
    config = Config.from_dict({"limits": {"masscan_rate": 10_000_000}})
    ctx = make_context(config=config)
    ctx.paths.live_hosts.write_text(f"{IN_SCOPE}\n", encoding="utf-8")

    seen: dict[str, int] = {}

    def fake_masscan(_ctx, _targets, _ports, rate):
        seen["rate"] = rate
        return []

    monkeypatch.setattr(sweep, "_run_masscan", fake_masscan)
    sweep.run(ctx)
    assert seen["rate"] == 20_000, "the clamped rate must be what reaches the backend"


# -- services ------------------------------------------------------------


def test_services_ignores_out_of_scope_hosts_in_the_checkpoint(make_context):
    ctx = make_context()
    _write_sweep_results(
        ctx,
        {
            IN_SCOPE: [{"port": 22, "protocol": "tcp"}, {"port": 80, "protocol": "tcp"}],
            OUT_OF_SCOPE: [{"port": 445, "protocol": "tcp"}],
        },
    )
    targets = services.load_targets(ctx)
    assert [t.ip for t in targets] == [IN_SCOPE]
    assert targets[0].tcp_ports == (22, 80)


def test_services_port_spec_separates_tcp_and_udp(make_context):
    ctx = make_context()
    _write_sweep_results(
        ctx,
        {IN_SCOPE: [{"port": 22, "protocol": "tcp"}, {"port": 161, "protocol": "udp"}]},
    )
    target = services.load_targets(ctx)[0]
    assert target.port_spec == "T:22,U:161"
    assert target.total == 2


def test_services_skips_when_nothing_was_found(make_context):
    ctx = make_context()
    _write_sweep_results(ctx, {})
    with pytest.raises(StageSkipped, match="no open ports"):
        services.run(ctx)


def _fake_nmap(captured: list[tuple[str, ...]], address: str = IN_SCOPE):
    """Stand-in for nmap: records argv and writes a minimal XML report."""

    def _run(argv, **_kwargs):
        argv = tuple(str(a) for a in argv)
        captured.append(argv)
        prefix = Path(argv[argv.index("-oA") + 1])
        prefix.with_suffix(".xml").write_text(
            f'<nmaprun version="7.94"><host><status state="up"/>'
            f'<address addr="{address}" addrtype="ipv4"/><ports><port protocol="tcp" '
            f'portid="22"><state state="open"/><service name="ssh"/></port></ports>'
            f"</host></nmaprun>",
            encoding="utf-8",
        )
        from netrecon.core.runner import CommandResult

        return CommandResult(argv, 0, "", "", 0.0)

    return _run


def test_services_scans_only_discovered_ports(make_context, monkeypatch):
    ctx = make_context()
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 22, "protocol": "tcp"}]})

    captured: list[tuple[str, ...]] = []
    monkeypatch.setattr(services, "run_command", _fake_nmap(captured))
    result = services.run(ctx)
    assert result.counts["failures"] == 0

    assert captured
    argv = captured[0]
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "T:22"
    assert argv[-1] == IN_SCOPE
    assert "1-65535" not in argv


def test_services_skips_os_detection_when_unprivileged(make_context, monkeypatch, unprivileged):
    config = Config()
    config.stages.os_detect = True
    ctx = make_context(config=config, privileges=unprivileged)
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 22, "protocol": "tcp"}]})

    captured: list[tuple[str, ...]] = []
    monkeypatch.setattr(services, "run_command", _fake_nmap(captured))
    services.run(ctx)
    assert "-O" not in captured[0]


def test_services_rejects_a_malformed_checkpoint(make_context):
    ctx = make_context()
    write_json(ctx.paths.open_ports, {"hosts": ["not", "a", "mapping"]})
    with pytest.raises(StageFailed, match="expected format"):
        services.load_targets(ctx)


# -- nuclei --------------------------------------------------------------


def test_nuclei_endpoints_are_scope_filtered(make_context):
    ctx = make_context(active=True)
    _write_sweep_results(
        ctx,
        {
            IN_SCOPE: [{"port": 80, "protocol": "tcp"}, {"port": 161, "protocol": "udp"}],
            OUT_OF_SCOPE: [{"port": 80, "protocol": "tcp"}],
        },
    )
    endpoints = nuclei.build_target_list(ctx)
    assert endpoints == [f"{IN_SCOPE}:80"], "UDP and out-of-scope endpoints excluded"


def test_nuclei_requires_the_active_flag(make_context):
    ctx = make_context(active=False)
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    with pytest.raises(StageSkipped, match="--active"):
        nuclei.run(ctx)


def test_nuclei_skips_when_no_endpoints(make_context):
    ctx = make_context(active=True)
    _write_sweep_results(ctx, {})
    with pytest.raises(StageSkipped, match="no open TCP endpoints"):
        nuclei.run(ctx)


# -- strict enforcement --------------------------------------------------


def test_targets_file_raises_on_internal_scope_violation(make_context):
    ctx = make_context()
    with pytest.raises(ScopeViolation):
        ctx.targets_file("bad.txt", [IN_SCOPE, OUT_OF_SCOPE])
