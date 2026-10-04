"""Nuclei stage guardrails.

Every test here monkeypatches :func:`netrecon.core.runner.run_command`, so no
subprocess is ever started and no packet leaves the machine.
"""

from __future__ import annotations

import json
import logging

import pytest

from netrecon.core.config import (
    NUCLEI_CONCURRENCY_HARD_MAX,
    NUCLEI_RATE_HARD_MAX,
    Config,
    ConfigError,
)
from netrecon.core.jsonio import write_json
from netrecon.core.runner import CommandResult
from netrecon.core.state import utc_now
from netrecon.stages import nuclei
from netrecon.stages.base import StageFailed, StageSkipped

IN_SCOPE = "10.10.10.5"
OUT_OF_SCOPE = "198.51.100.9"


def _write_sweep_results(ctx, hosts: dict[str, list[dict]]) -> None:
    write_json(ctx.paths.open_ports, {"generated_at": utc_now(), "hosts": hosts})


def _config(**nuclei_kwargs) -> Config:
    return Config.from_dict({"stages": {"nuclei": True}, "nuclei": nuclei_kwargs})


class _Recorder:
    """Stands in for run_command; records the argv and writes findings."""

    def __init__(self, records: list[dict] | None = None) -> None:
        self.argv: list[str] = []
        self.records = records or []

    def __call__(self, argv, **kwargs):
        self.argv = [str(part) for part in argv]
        output = self.argv[self.argv.index("-output") + 1]
        with open(output, "w", encoding="utf-8") as handle:
            for record in self.records:
                handle.write(json.dumps(record) + "\n")
        return CommandResult(tuple(self.argv), 0, "", "", 0.1, False)


def _run(ctx, monkeypatch, records: list[dict] | None = None) -> tuple[_Recorder, object]:
    recorder = _Recorder(records)
    monkeypatch.setattr(nuclei, "run_command", recorder)
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    result = nuclei.run(ctx)
    return recorder, result


def _arg_value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def _finding(host: str, severity: str = "high") -> dict:
    return {
        "template-id": "network-detect",
        "host": f"{host}:80",
        "ip": host,
        "matched-at": f"http://{host}:80/",
        "info": {"severity": severity},
    }


# -- excluded tags -------------------------------------------------------


def test_exclude_tags_argument_lists_every_mandatory_tag(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config())
    recorder, _ = _run(ctx, monkeypatch)

    assert "-exclude-tags" in recorder.argv
    tags = _arg_value(recorder.argv, "-exclude-tags").split(",")
    for tag in ("fuzz", "fuzzing", "intrusive", "dos", "brute-force"):
        assert tag in tags


def test_config_cannot_remove_an_excluded_tag(make_context, monkeypatch):
    # Listing a subset does not narrow the mandatory list.
    ctx = make_context(active=True, config=_config(exclude_tags=["dos"]))
    recorder, _ = _run(ctx, monkeypatch)
    tags = _arg_value(recorder.argv, "-exclude-tags").split(",")

    assert set(nuclei.EXCLUDED_TAGS) <= set(tags)
    assert tags.count("dos") == 1


def test_config_can_add_extra_excluded_tags(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config(exclude_tags=["rce", "sqli"]))
    recorder, _ = _run(ctx, monkeypatch)
    tags = _arg_value(recorder.argv, "-exclude-tags").split(",")

    assert set(nuclei.EXCLUDED_TAGS) <= set(tags)
    assert {"rce", "sqli"} <= set(tags)


def test_build_excluded_tags_keeps_mandatory_tags_first():
    tags = nuclei.build_excluded_tags(["rce"])
    assert tags[: len(nuclei.EXCLUDED_TAGS)] == list(nuclei.EXCLUDED_TAGS)


# -- severity ------------------------------------------------------------


def test_default_severity_drops_info():
    assert Config().nuclei.severity == "low,medium,high,critical"


def test_severity_is_passed_through(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config(severity="high,critical"))
    recorder, _ = _run(ctx, monkeypatch)
    assert _arg_value(recorder.argv, "-severity") == "high,critical"


@pytest.mark.parametrize(
    "severity",
    ["bogus", "high;dos", "", "high,,low", "high -flag", "HIGH critical"],
)
def test_invalid_severity_is_rejected(severity):
    with pytest.raises(ConfigError):
        _config(severity=severity)


def test_severity_is_normalised_and_deduplicated():
    assert _config(severity=" HIGH , high ,Critical").nuclei.severity == "high,critical"


# -- interactsh ----------------------------------------------------------


def test_interactsh_is_always_disabled(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config())
    recorder, _ = _run(ctx, monkeypatch)
    assert "-no-interactsh" in recorder.argv


# -- rate and concurrency ------------------------------------------------


def test_rate_and_concurrency_are_both_passed(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config(concurrency=12))
    recorder, _ = _run(ctx, monkeypatch)

    assert _arg_value(recorder.argv, "-rate-limit") == str(ctx.config.limits.nuclei_rate)
    assert _arg_value(recorder.argv, "-concurrency") == "12"


def test_rate_and_concurrency_are_clamped(make_context, monkeypatch):
    config = Config.from_dict(
        {
            "stages": {"nuclei": True},
            "limits": {"nuclei_rate": NUCLEI_RATE_HARD_MAX * 10},
            "nuclei": {"concurrency": NUCLEI_CONCURRENCY_HARD_MAX * 10},
        }
    )
    assert config.limits.nuclei_rate == NUCLEI_RATE_HARD_MAX
    assert config.nuclei.concurrency == NUCLEI_CONCURRENCY_HARD_MAX
    assert any("nuclei.concurrency" in warning for warning in config.warnings)

    ctx = make_context(active=True, config=config)
    recorder, _ = _run(ctx, monkeypatch)
    assert _arg_value(recorder.argv, "-rate-limit") == str(NUCLEI_RATE_HARD_MAX)
    assert _arg_value(recorder.argv, "-concurrency") == str(NUCLEI_CONCURRENCY_HARD_MAX)


def test_zero_concurrency_is_rejected():
    with pytest.raises(ConfigError):
        _config(concurrency=0)


# -- scope filtering on read ---------------------------------------------


def test_out_of_scope_finding_is_dropped_and_counted(make_context, monkeypatch, caplog):
    ctx = make_context(active=True, config=_config())
    with caplog.at_level(logging.INFO):
        _, result = _run(ctx, monkeypatch, [_finding(OUT_OF_SCOPE)])

    assert result.counts["findings"] == 0
    assert result.counts["out_of_scope_dropped"] == 1
    assert OUT_OF_SCOPE not in ctx.paths.nuclei.read_text(encoding="utf-8")
    summary = json.loads((ctx.paths.root / "nuclei_summary.json").read_text(encoding="utf-8"))
    assert summary["out_of_scope_dropped"] == 1
    assert summary["findings"] == 0
    assert "outside the scope" in caplog.text


def test_in_scope_finding_survives(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config())
    _, result = _run(ctx, monkeypatch, [_finding(IN_SCOPE), _finding(OUT_OF_SCOPE)])

    assert result.counts["findings"] == 1
    assert result.counts["out_of_scope_dropped"] == 1
    kept = ctx.paths.nuclei.read_text(encoding="utf-8")
    assert IN_SCOPE in kept
    assert OUT_OF_SCOPE not in kept


def test_finding_without_an_address_is_dropped(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config())
    _, result = _run(ctx, monkeypatch, [{"template-id": "x", "info": {"severity": "low"}}])

    assert result.counts["findings"] == 0
    assert result.counts["out_of_scope_dropped"] == 1


def test_finding_address_handles_urls_and_ports():
    assert nuclei.finding_address({"host": f"{IN_SCOPE}:8443"}) == IN_SCOPE
    assert nuclei.finding_address({"host": "https://evil.example.com/x"}) == "evil.example.com"
    assert nuclei.finding_address({"host": "[2001:db8::1]:443"}) == "2001:db8::1"
    assert nuclei.finding_address({"ip": IN_SCOPE, "host": "redirected.example"}) == IN_SCOPE
    assert nuclei.finding_address({}) is None


def test_endpoints_are_scope_filtered_before_the_scan(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config())
    recorder = _Recorder()
    monkeypatch.setattr(nuclei, "run_command", recorder)
    _write_sweep_results(
        ctx,
        {
            IN_SCOPE: [{"port": 80, "protocol": "tcp"}, {"port": 161, "protocol": "udp"}],
            OUT_OF_SCOPE: [{"port": 80, "protocol": "tcp"}],
        },
    )
    nuclei.run(ctx)

    targets = (ctx.paths.targets_dir / "nuclei_targets.txt").read_text(encoding="utf-8")
    assert targets.split() == [f"{IN_SCOPE}:80"]


# -- skips ---------------------------------------------------------------


def test_skips_without_the_active_flag(make_context):
    ctx = make_context(active=False, config=_config())
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    with pytest.raises(StageSkipped, match="--active"):
        nuclei.run(ctx)


def test_skips_when_nuclei_is_not_installed(make_context, no_tools):
    ctx = make_context(active=True, config=_config(), tools=no_tools)
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    with pytest.raises(StageSkipped, match="not installed"):
        nuclei.run(ctx)


def test_skips_when_there_are_no_endpoints(make_context):
    ctx = make_context(active=True, config=_config())
    _write_sweep_results(ctx, {})
    with pytest.raises(StageSkipped, match="no open TCP endpoints"):
        nuclei.run(ctx)


def test_dry_run_does_not_execute(make_context, monkeypatch):
    ctx = make_context(active=True, config=_config(), dry_run=True)

    def explode(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("run_command must not be called during a dry run")

    monkeypatch.setattr(nuclei, "run_command", explode)
    _write_sweep_results(ctx, {IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    assert nuclei.run(ctx).detail == "dry run"


# -- template blocklist --------------------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "fuzzing/xss.yaml",
        "network/dos/slowloris.yaml",
        "http/brute/ssh.yaml",
        "http/default-logins/admin.yaml",
        "dns/takeovers/cname.yaml",
    ],
)
def test_intrusive_templates_are_rejected(template):
    with pytest.raises(StageFailed, match="blocked pattern"):
        nuclei.validate_templates([template])


def test_template_paths_cannot_be_flags_or_traversals():
    with pytest.raises(StageFailed, match="invalid nuclei template path"):
        nuclei.validate_templates(["-flag"])
    with pytest.raises(StageFailed, match="invalid nuclei template path"):
        nuclei.validate_templates(["../../etc/passwd"])


def test_empty_template_list_is_rejected():
    with pytest.raises(StageFailed, match="empty"):
        nuclei.validate_templates(["   "])
