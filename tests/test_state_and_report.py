"""Tests for checkpoint/resume and report aggregation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netrecon.core.config import Config
from netrecon.core.jsonio import read_json, write_json
from netrecon.core.pipeline import STAGE_ORDER, execute, preflight_summary
from netrecon.core.state import RunState, StateError, find_latest_run
from netrecon.report import build as report_build

FIXTURES = Path(__file__).parent / "fixtures"


# -- checkpoint / resume -------------------------------------------------


def test_state_round_trips(make_context):
    ctx = make_context()
    ctx.state.complete("discovery", duration=1.5, counts={"live": 3}, outputs={"a": "b"})
    reloaded = RunState.load(ctx.paths.root)
    assert reloaded.is_completed("discovery")
    assert reloaded.stages["discovery"].counts == {"live": 3}
    assert reloaded.stages["discovery"].duration_seconds == 1.5


def test_state_file_is_valid_json_after_each_transition(make_context):
    ctx = make_context()
    ctx.state.begin("sweep")
    assert json.loads(ctx.state.path.read_text())["stages"]["sweep"]["status"] == "running"
    ctx.state.fail("sweep", duration=0.2, detail="boom")
    assert json.loads(ctx.state.path.read_text())["stages"]["sweep"]["status"] == "failed"


def test_resume_refuses_a_changed_scope(make_context, scope):
    from netrecon.core.scope import Scope

    ctx = make_context()
    widened = Scope.from_lines(["10.10.10.0/24"])
    reloaded = RunState.load(ctx.paths.root)
    with pytest.raises(StateError, match="scope file has changed"):
        reloaded.check_scope(widened.fingerprint())


def test_resume_accepts_the_same_scope(make_context, scope):
    ctx = make_context()
    RunState.load(ctx.paths.root).check_scope(scope.fingerprint())


def test_completed_stages_are_not_rerun(make_context, monkeypatch):
    ctx = make_context()
    ctx.state.complete("discovery", duration=1.0, counts={"live": 1})
    ctx.paths.live_hosts.write_text("10.10.10.5\n", encoding="utf-8")

    calls: list[str] = []
    for name, _key, _runner in STAGE_ORDER:
        pass

    def fake_discovery(_ctx):
        calls.append("discovery")
        raise AssertionError("discovery must not run again")

    monkeypatch.setattr(
        "netrecon.core.pipeline.STAGE_ORDER",
        (("discovery", "discovery", fake_discovery),),
    )
    config = Config()
    config.stages.sweep = False
    config.stages.services = False
    ctx.config = config

    outcome = execute(ctx)
    assert calls == []
    assert outcome.ok


def test_disabled_stages_are_recorded_as_skipped(make_context):
    config = Config()
    config.stages.discovery = False
    config.stages.sweep = False
    config.stages.services = False
    ctx = make_context(config=config)
    execute(ctx)
    state = RunState.load(ctx.paths.root)
    assert state.stages["discovery"].status == "skipped"
    assert state.stages["discovery"].detail == "disabled in config"


def test_find_latest_run_picks_the_newest_checkpoint(tmp_path: Path):
    base = tmp_path / "results" / "default"
    for name in ("20240101T000000Z", "20240301T000000Z", "20240201T000000Z"):
        (base / name).mkdir(parents=True)
        (base / name / "state.json").write_text("{}", encoding="utf-8")
    assert find_latest_run(base).name == "20240301T000000Z"


def test_find_latest_run_ignores_dirs_without_a_checkpoint(tmp_path: Path):
    base = tmp_path / "results" / "default"
    (base / "20240101T000000Z").mkdir(parents=True)
    assert find_latest_run(base) is None


def test_find_latest_run_handles_a_missing_base(tmp_path: Path):
    assert find_latest_run(tmp_path / "nope") is None


def test_state_version_mismatch_is_refused(tmp_path: Path):
    (tmp_path / "state.json").write_text('{"state_version": 999}', encoding="utf-8")
    with pytest.raises(StateError, match="incompatible"):
        RunState.load(tmp_path)


def test_jsonio_write_is_atomic_and_leaves_no_temp_files(tmp_path: Path):
    target = tmp_path / "out.json"
    write_json(target, {"a": 1})
    assert read_json(target) == {"a": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


def test_read_json_tolerates_corruption(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert read_json(path, default={"fallback": True}) == {"fallback": True}


# -- pre-flight banner ---------------------------------------------------


def test_preflight_includes_the_authorisation_reminder(make_context):
    text = preflight_summary(make_context())
    assert "authorised reconnaissance only" in text
    assert "written authorisation" in text


def test_preflight_reports_scope_rate_and_stages(make_context):
    ctx = make_context()
    text = preflight_summary(ctx)
    assert f"In-scope hosts    : {len(ctx.scope)}" in text
    assert "1000 pps" in text
    assert "10.10.10.5 .. 203.0.113.7" in text
    assert "discovery, sweep, services" in text


def test_preflight_warns_about_a_raised_rate(make_context):
    config = Config.from_dict({"limits": {"masscan_rate": 8000}})
    text = preflight_summary(make_context(config=config))
    assert "above the safe default" in text


def test_preflight_lists_rejected_scope_lines(make_context):
    text = preflight_summary(make_context())
    assert "scope line(s) were rejected" in text
    assert "example.com" in text


def test_preflight_explains_the_unprivileged_fallback(make_context, unprivileged):
    text = preflight_summary(make_context(privileges=unprivileged))
    assert "Raw sockets are not available" in text
    assert "connect scan" in text
    assert "--cap-add=NET_RAW" in text


def test_preflight_flags_public_addresses_in_scope(make_context):
    from netrecon.core.scope import Scope

    text = preflight_summary(
        make_context(scope_override=Scope.from_lines(["10.0.0.1", "8.8.8.8"]))
    )
    assert "public address(es)" in text


def test_preflight_announces_the_active_stage(make_context):
    assert "ENABLED (nuclei)" in preflight_summary(make_context(active=True))
    assert "Active stage      : disabled" in preflight_summary(make_context())


def test_preflight_marks_a_dry_run(make_context):
    assert "DRY RUN" in preflight_summary(make_context(dry_run=True))


# -- report --------------------------------------------------------------


def _seed_results(ctx) -> None:
    ctx.paths.live_hosts.write_text("10.10.10.5\n10.10.10.6\n10.10.10.20\n", encoding="utf-8")
    write_json(
        ctx.paths.open_ports,
        {
            "backend": "masscan",
            "hosts": {
                "10.10.10.5": [
                    {"port": 22, "protocol": "tcp"},
                    {"port": 80, "protocol": "tcp"},
                ],
                "10.10.10.6": [{"port": 3306, "protocol": "tcp"}],
            },
        },
    )
    from netrecon.parse.nmap import parse_nmap_xml

    report = parse_nmap_xml(FIXTURES / "nmap_services.xml")
    write_json(
        ctx.paths.services,
        {
            "services_identified": 3,
            "hosts": [h.to_dict() for h in report.up_hosts],
        },
    )


def test_report_aggregates_ports_and_services(make_context):
    ctx = make_context()
    _seed_results(ctx)
    payload = report_build.build(ctx)

    assert payload["totals"]["live_hosts"] == 3
    assert payload["totals"]["open_ports"] == 3
    hosts = {h["ip"]: h for h in payload["hosts"]}
    ssh = next(p for p in hosts["10.10.10.5"]["open_ports"] if p["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["version"].startswith("OpenSSH 8.9p1")


def test_report_includes_live_hosts_with_no_open_ports(make_context):
    ctx = make_context()
    _seed_results(ctx)
    payload = report_build.build(ctx)
    quiet = next(h for h in payload["hosts"] if h["ip"] == "10.10.10.20")
    assert quiet["open_port_count"] == 0


def test_report_flags_notable_services(make_context):
    ctx = make_context()
    _seed_results(ctx)
    payload = report_build.build(ctx)
    notes = " ".join(
        note for host in payload["hosts"] for note in host["notes"]
    )
    assert "MySQL exposed" in notes


def test_report_hosts_are_sorted_numerically(make_context):
    ctx = make_context()
    _seed_results(ctx)
    payload = report_build.build(ctx)
    assert [h["ip"] for h in payload["hosts"]] == [
        "10.10.10.5",
        "10.10.10.6",
        "10.10.10.20",
    ]


def test_report_markdown_is_written_with_host_sections(make_context):
    ctx = make_context()
    _seed_results(ctx)
    report_build.build(ctx)
    text = ctx.paths.report.read_text()
    assert "# netrecon report" in text
    assert "### 10.10.10.5 (web01.internal)" in text
    assert "| 22 | tcp | ssh | OpenSSH 8.9p1" in text
    assert "authorised engagement" in text


def test_report_records_os_guess_and_scripts(make_context):
    ctx = make_context()
    _seed_results(ctx)
    payload = report_build.build(ctx)
    host = next(h for h in payload["hosts"] if h["ip"] == "10.10.10.5")
    assert host["os_guess"].startswith("Linux 5.0 - 5.14")
    text = ctx.paths.report.read_text()
    assert "http-title" in text


def test_report_summary_json_is_machine_readable(make_context):
    ctx = make_context()
    _seed_results(ctx)
    report_build.build(ctx)
    payload = json.loads(ctx.paths.summary.read_text())
    assert payload["scope"]["total_hosts"] == len(ctx.scope)
    assert payload["limits"]["sweep_rate_pps"] == 1000
    assert isinstance(payload["hosts"], list)


def test_report_handles_a_run_with_no_results(make_context):
    ctx = make_context()
    payload = report_build.build(ctx)
    assert payload["totals"]["hosts_reported"] == 0
    assert "No hosts responded" in ctx.paths.report.read_text()


def test_report_includes_nuclei_findings(make_context):
    ctx = make_context()
    _seed_results(ctx)
    ctx.paths.nuclei.write_text(
        json.dumps(
            {
                "template-id": "mysql-detect",
                "info": {"name": "MySQL detected", "severity": "info"},
                "host": "10.10.10.6:3306",
                "matched-at": "10.10.10.6:3306",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    payload = report_build.build(ctx)
    host = next(h for h in payload["hosts"] if h["ip"] == "10.10.10.6")
    assert host["nuclei_findings"][0]["template"] == "mysql-detect"
    assert "MySQL detected" in ctx.paths.report.read_text()


def test_report_escapes_pipes_in_version_strings(make_context):
    ctx = make_context()
    write_json(
        ctx.paths.open_ports,
        {"hosts": {"10.10.10.5": [{"port": 8080, "protocol": "tcp"}]}},
    )
    write_json(
        ctx.paths.services,
        {
            "hosts": [
                {
                    "address": "10.10.10.5",
                    "ports": [
                        {
                            "port": 8080,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "http", "label": "weird | banner"},
                        }
                    ],
                }
            ]
        },
    )
    report_build.build(ctx)
    assert "weird \\| banner" in ctx.paths.report.read_text()
