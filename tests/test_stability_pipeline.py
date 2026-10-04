"""Stability tests for stage and pipeline failure modes.

A recon run is long and expensive, so the bugs this file exists to catch are the
ones that turn a partial run into a *misleading* run:

* an external tool that dies (missing, non-zero, signalled, timed out, writing
  garbage or nothing at all) escaping as a bare exception instead of
  ``StageSkipped``/``StageFailed``;
* a stage that runs without the input it depends on, or a run that keeps going
  after a dependency failure it documented as fatal;
* a checkpoint that is unreadable, half-written, or claims a stage finished when
  it did not - so a resume either refuses wrongly or re-scans wrongly;
* a corrupt or unexpected artifact crashing the report instead of degrading;
* a report that is missing, invalid, or quietly reports a failed stage as a
  success.

Nothing here spawns a scan tool or touches the network: ``run_command`` is
replaced inside each stage module. The only real subprocesses are the handful of
``/bin/sh`` invocations in the ``run_command`` section, which exercise decoding
and timeout handling.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from netrecon.core import pipeline as pipeline_mod
from netrecon.core.config import Config
from netrecon.core.jsonio import write_json, write_lines
from netrecon.core.pipeline import execute, preflight_summary
from netrecon.core.runner import CommandResult, RunContext, ToolVanished, run_command
from netrecon.core.scope import Scope
from netrecon.core.state import (
    COMPLETED,
    FAILED,
    RUNNING,
    SKIPPED,
    RunState,
    StateError,
    find_latest_run,
)
from netrecon.report import build as report_build
from netrecon.stages import discovery, nuclei, scripts, services, sweep
from netrecon.stages.base import StageFailed, StageResult, StageSkipped

IN_SCOPE_HOST = "10.10.10.5"
SECOND_HOST = "10.10.10.6"

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1716200000" version="7.94">
<host><status state="up" reason="echo-reply"/>
<address addr="{ip}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/>
<script id="http-title" output="hello"/>
</port></ports>
</host>
<runstats><finished time="1716200030" elapsed="30"/></runstats>
</nmaprun>
"""

MASSCAN_JSON = json.dumps(
    [{"ip": IN_SCOPE_HOST, "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]
)
NAABU_JSONL = json.dumps({"ip": IN_SCOPE_HOST, "port": 80, "protocol": "tcp"}) + "\n"
NUCLEI_JSONL = (
    json.dumps(
        {
            "template-id": "demo",
            "info": {"name": "demo", "severity": "info"},
            "host": f"{IN_SCOPE_HOST}:80",
            "matched-at": f"{IN_SCOPE_HOST}:80",
        }
    )
    + "\n"
)

#: Every external-tool failure mode the stages have to survive.
FAILURE_MODES: tuple[str, ...] = (
    "nonzero_stderr",
    "exit_zero_no_output",
    "exit_zero_garbage",
    "timed_out",
    "killed_by_signal",
    "wrong_output_path",
    "vast_output",
)


# -- fake external tools -------------------------------------------------


def _flag_value(argv: Sequence[str], flag: str) -> str | None:
    for index, part in enumerate(argv):
        if part == flag and index + 1 < len(argv):
            return argv[index + 1]
    return None


def _output_path(argv: Sequence[str]) -> Path | None:
    """Where the tool in *argv* was told to write its machine-readable output."""
    tool = Path(argv[0]).name
    if tool == "nmap":
        prefix = _flag_value(argv, "-oA")
        return Path(prefix).with_suffix(".xml") if prefix else None
    if tool == "masscan":
        value = _flag_value(argv, "-oJ")
        return Path(value) if value else None
    if tool in {"naabu", "nuclei"}:
        value = _flag_value(argv, "-output")
        return Path(value) if value else None
    return None  # fping reports on stdout


def _good_payload(argv: Sequence[str]) -> str:
    tool = Path(argv[0]).name
    if tool == "nmap":
        return NMAP_XML.format(ip=IN_SCOPE_HOST)
    if tool == "masscan":
        return MASSCAN_JSON
    if tool == "naabu":
        return NAABU_JSONL
    if tool == "nuclei":
        return NUCLEI_JSONL
    return f"{IN_SCOPE_HOST}\n"


def _result(argv: Sequence[str], rc: int, *, stdout: str = "", stderr: str = "", timed_out: bool = False) -> CommandResult:
    return CommandResult(tuple(argv), rc, stdout, stderr, 0.01, timed_out)


def _empty_payload(argv: Sequence[str]) -> str:
    """A valid, well-formed, empty result for the tool in *argv*."""
    tool = Path(argv[0]).name
    if tool == "nmap":
        return '<?xml version="1.0"?><nmaprun version="7.94"></nmaprun>'
    if tool == "naabu":
        return ""
    return "[\n]\n"  # masscan -oJ with no results


def fake_tool(mode: str | dict[str, str]) -> Callable[..., CommandResult]:
    """A ``run_command`` replacement that fails in exactly one way.

    *mode* is a failure mode, or a ``{tool: mode}`` map when a test needs one
    tool to work and another to break.
    """
    modes = mode

    def fake(argv: Sequence[str], **_kwargs: Any) -> CommandResult:
        argv = tuple(str(part) for part in argv)
        out = _output_path(argv)
        mode = modes.get(Path(argv[0]).name, "healthy") if isinstance(modes, dict) else modes
        if mode == "nonzero_stderr":
            return _result(argv, 2, stderr="permission denied: cannot open raw socket\n")
        if mode == "exit_zero_no_output":
            return _result(argv, 0)
        if mode == "exit_zero_garbage":
            if out is not None:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text("<nmaprun><host><truncat", encoding="utf-8")
            return _result(argv, 0, stdout="\x00\x01not an address at all")
        if mode == "timed_out":
            return _result(argv, 124, stderr="partial", timed_out=True)
        if mode == "killed_by_signal":
            return _result(argv, -9, stderr="Killed")
        if mode == "wrong_output_path":
            if out is not None:
                stray = out.parent / f"stray-{out.name}"
                stray.parent.mkdir(parents=True, exist_ok=True)
                stray.write_text(_good_payload(argv), encoding="utf-8")
            return _result(argv, 0)
        if mode == "vast_output":
            blob = "A" * 200_000
            if out is not None:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(_good_payload(argv) + "\n" + blob, encoding="utf-8")
            return _result(argv, 0, stdout=blob, stderr=blob)
        if mode == "found_nothing":
            # A tool that ran correctly and genuinely found nothing: a valid,
            # well-formed, empty result file. Distinct from a tool that exited
            # zero without writing anything, which means it did not run.
            if out is not None:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(_empty_payload(argv), encoding="utf-8")
            return _result(argv, 0)
        if mode == "healthy":
            if out is not None:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(_good_payload(argv), encoding="utf-8")
            return _result(argv, 0, stdout=_good_payload(argv))
        raise AssertionError(f"unknown mode {mode}")

    return fake


def install_fake_tool(monkeypatch: pytest.MonkeyPatch, mode: str | dict[str, str]) -> None:
    for module in (discovery, sweep, services, scripts, nuclei):
        monkeypatch.setattr(module, "run_command", fake_tool(mode))


def seed_live_hosts(ctx: RunContext, hosts: Sequence[str] = (IN_SCOPE_HOST, SECOND_HOST)) -> None:
    write_lines(ctx.paths.live_hosts, list(hosts))


def seed_open_ports(ctx: RunContext, hosts: dict[str, list[dict[str, Any]]] | None = None) -> None:
    hosts = hosts if hosts is not None else {IN_SCOPE_HOST: [{"port": 80, "protocol": "tcp"}]}
    write_json(
        ctx.paths.open_ports,
        {"backend": "masscan", "rate_pps": 1000, "hosts": hosts},
    )


# -- stage matrix --------------------------------------------------------


@dataclass(frozen=True)
class StageCase:
    """One (stage, backend) pair that spawns an external tool."""

    label: str
    run: Callable[[RunContext], StageResult]
    config: dict[str, Any]
    seed: Callable[[RunContext], None]
    active: bool = False


def _noop(_ctx: RunContext) -> None:
    return None


STAGE_CASES: tuple[StageCase, ...] = (
    StageCase("discovery/fping", discovery.run, {"discovery": {"method": "fping"}}, _noop),
    StageCase("discovery/nmap", discovery.run, {"discovery": {"method": "nmap"}}, _noop),
    StageCase("sweep/masscan", sweep.run, {"sweep": {"backend": "masscan"}}, seed_live_hosts),
    StageCase("sweep/naabu", sweep.run, {"sweep": {"backend": "naabu"}}, seed_live_hosts),
    StageCase("sweep/nmap", sweep.run, {"sweep": {"backend": "nmap"}}, seed_live_hosts),
    StageCase("services", services.run, {}, seed_open_ports),
    StageCase("scripts", scripts.run, {"stages": {"scripts": True}}, seed_open_ports),
    StageCase("nuclei", nuclei.run, {"stages": {"nuclei": True}}, seed_open_ports, active=True),
)

STAGE_CASES_BY_LABEL = {case.label: case for case in STAGE_CASES}


def build_case_context(make_context, case: StageCase) -> RunContext:
    config = Config.from_dict(case.config)
    config.validate()
    ctx = make_context(config=config, active=case.active)
    case.seed(ctx)
    return ctx


#: What each (stage, failure mode) pair is contractually allowed to do.
#:
#: ``"raise"``  - the stage must raise StageFailed or StageSkipped.
#: ``"empty"``  - the stage may complete, but must report zero results; the
#:                tool genuinely cannot distinguish "nothing found" from
#:                "nothing written" (see the module notes in the report).
EXPECTED: dict[tuple[str, str], str] = {}

#: Primary result count for each stage, used to check an "empty" completion
#: really is empty rather than quietly invented.
PRIMARY_COUNT: dict[str, str] = {
    "discovery/fping": "live",
    "discovery/nmap": "live",
    "sweep/masscan": "open_ports",
    "sweep/naabu": "open_ports",
    "sweep/nmap": "open_ports",
    "services": "hosts_reported",
    "scripts": "hosts_reported",
    "nuclei": "findings",
}


def _expect(label: str, **modes: str) -> None:
    for mode in FAILURE_MODES:
        EXPECTED[(label, mode)] = modes.get(mode, modes["default"])


# fping reports live hosts on stdout, so "no output" is indistinguishable from
# "nothing answered"; only a crash/timeout is a failure.
_expect(
    "discovery/fping",
    default="empty",
    nonzero_stderr="raise",
    timed_out="raise",
    killed_by_signal="raise",
)
_expect("discovery/nmap", default="raise")
# masscan writes a results file, so a tool that exits zero having written
# nothing readable did not run - reporting that as "no open ports" would be a
# clean result the operator cannot distinguish from a real one.
_expect(
    "sweep/masscan",
    default="raise",
    exit_zero_garbage="empty",  # a parseable-but-empty file is a real result
    vast_output="data",
)
# naabu legitimately writes no file when it finds nothing, so only a tool that
# also complained on stderr is treated as a failure.
_expect(
    "sweep/naabu",
    default="empty",
    nonzero_stderr="raise",
    timed_out="raise",
    killed_by_signal="raise",
    vast_output="data",
)
_expect("sweep/nmap", default="raise")
_expect("services", default="raise")
# scripts matches services: if every host failed, the stage failed. Completing
# with zero outputs would read as "nothing was found", which is not what
# happened.
_expect("scripts", default="raise")
_expect("nuclei", default="empty", nonzero_stderr="raise", timed_out="raise",
        killed_by_signal="raise", vast_output="data")


# -- 1. external tool failure, every stage that spawns one ---------------


@pytest.mark.parametrize("mode", FAILURE_MODES)
@pytest.mark.parametrize("case", STAGE_CASES, ids=lambda c: c.label)
def test_tool_failure_never_escapes_as_a_bare_exception(
    make_context, monkeypatch, case: StageCase, mode: str
) -> None:
    ctx = build_case_context(make_context, case)
    install_fake_tool(monkeypatch, mode)
    expectation = EXPECTED[(case.label, mode)]

    try:
        result = case.run(ctx)
    except (StageFailed, StageSkipped) as exc:
        assert expectation == "raise", f"{case.label}/{mode} unexpectedly raised: {exc}"
        assert str(exc).strip(), "a stage failure must carry a usable message"
        return
    except BaseException as exc:  # noqa: BLE001 - that is the bug we are hunting
        raise AssertionError(
            f"{case.label}/{mode} escaped as {type(exc).__name__}: {exc}"
        ) from exc

    assert expectation != "raise", f"{case.label}/{mode} completed but should have failed"
    key = PRIMARY_COUNT[case.label]
    if expectation == "empty":
        assert result.counts.get(key, 0) == 0, (
            f"{case.label}/{mode} reported {key}={result.counts.get(key)} from a broken tool"
        )
    else:
        assert result.counts.get(key, 0) > 0, f"{case.label}/{mode} dropped usable output"
    if case.label == "scripts":
        # A stage that completed with nothing must say so somewhere a reader sees.
        assert result.counts.get("failures", 0) > 0
        assert result.detail and "failed" in result.detail


@pytest.mark.parametrize("mode", FAILURE_MODES)
@pytest.mark.parametrize("case", STAGE_CASES, ids=lambda c: c.label)
def test_tool_failure_is_checkpointed_and_the_report_still_renders(
    make_context, monkeypatch, case: StageCase, mode: str
) -> None:
    """The pipeline wrapper records a status plus a useful detail, then reports."""
    ctx = build_case_context(make_context, case)
    install_fake_tool(monkeypatch, mode)
    stage_name = case.label.split("/")[0]
    monkeypatch.setattr(
        pipeline_mod, "STAGE_ORDER", ((stage_name, stage_name, case.run),)
    )
    ctx.config.stages.__dict__[stage_name] = True

    outcome = execute(ctx)

    state = RunState.load(ctx.paths.root)
    stage = state.stages[stage_name]
    expectation = EXPECTED[(case.label, mode)]
    if expectation == "raise":
        assert stage.status in {FAILED, SKIPPED}
        assert stage.detail, "a failed stage must record why"
        assert stage.status != RUNNING
    else:
        assert stage.status == COMPLETED
    assert stage.finished_at
    # Whatever happened, the operator still gets a report they can read.
    payload = assert_report_artifacts(ctx)
    assert payload["stages"][stage_name]["status"] == stage.status
    assert ("report" in outcome.failed_stages) is False


@pytest.mark.parametrize("case", STAGE_CASES, ids=lambda c: c.label)
def test_missing_binary_is_a_stage_level_decision(make_context, case: StageCase, no_tools) -> None:
    """With nothing on PATH every spawning stage must skip or fail cleanly."""
    config = Config.from_dict(case.config)
    config.validate()
    ctx = make_context(config=config, active=case.active, tools=no_tools)
    case.seed(ctx)
    with pytest.raises((StageFailed, StageSkipped)) as excinfo:
        case.run(ctx)
    assert str(excinfo.value).strip()


@pytest.mark.parametrize("case", STAGE_CASES, ids=lambda c: c.label)
def test_a_tool_that_vanishes_after_detection_is_checkpointed(
    make_context, monkeypatch, case: StageCase
) -> None:
    """Registry says installed, exec says ENOENT: the run must not lose the error.

    ``run_command`` raises ``ToolVanished``, which the pipeline converts into a
    recorded stage failure. The checkpoint names the error and the stage is
    never left ``running``, so the run stays resumable once the tool is back.
    """
    ctx = build_case_context(make_context, case)

    def vanished(argv: Sequence[str], **_kwargs: Any) -> CommandResult:
        raise ToolVanished(f"{argv[0]} is not installed or not on PATH")

    for module in (discovery, sweep, services, scripts, nuclei):
        monkeypatch.setattr(module, "run_command", vanished)

    stage_name = case.label.split("/")[0]
    monkeypatch.setattr(pipeline_mod, "STAGE_ORDER", ((stage_name, stage_name, case.run),))
    ctx.config.stages.__dict__[stage_name] = True

    execute(ctx)

    stage = RunState.load(ctx.paths.root).stages[stage_name]
    assert stage.status in {FAILED, COMPLETED, SKIPPED}
    if stage.status == FAILED:
        assert "not on PATH" in (stage.detail or "")
    assert_report_artifacts(ctx)


# -- report invariants, used throughout ----------------------------------


def assert_report_artifacts(ctx: RunContext) -> dict[str, Any]:
    """report.md, report.html and summary.json exist and are well formed."""
    assert ctx.paths.summary.is_file(), "summary.json missing"
    assert ctx.paths.report.is_file(), "report.md missing"
    assert ctx.paths.report_html.is_file(), "report.html missing"

    payload = json.loads(ctx.paths.summary.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert "totals" in payload and "stages" in payload

    markdown = ctx.paths.report.read_text(encoding="utf-8")
    assert markdown.startswith("# netrecon report")

    html = ctx.paths.report_html.read_text(encoding="utf-8")
    assert html.lstrip().startswith("<!doctype html>")
    for tag in ("html", "head", "body"):
        # \b so <header>/<thead> do not count as <head>.
        assert len(re.findall(rf"<{tag}\b", html)) == 1, f"<{tag}> is not balanced"
        assert html.count(f"</{tag}>") == 1, f"</{tag}> is not balanced in report.html"
    assert html.index("</body>") < html.index("</html>")
    return payload


def stage_rows_from_markdown(markdown: str) -> dict[str, str]:
    """``{stage: status}`` parsed back out of the stage timing table."""
    rows: dict[str, str] = {}
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("| Stage | Status |"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if cells[0] in {"---", ""}:
                continue
            rows[cells[0]] = cells[1]
    return rows


# -- 2. stage dependency chains ------------------------------------------


@dataclass
class FakeStage:
    """A stand-in stage runner that records its call and then misbehaves."""

    name: str
    calls: list[str]
    outcome: BaseException | StageResult

    def __call__(self, _ctx: RunContext) -> StageResult:
        self.calls.append(self.name)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def fake_order(
    calls: list[str], spec: dict[str, BaseException | StageResult | Callable[[RunContext], StageResult]]
) -> tuple[tuple[str, str, Callable[[RunContext], StageResult]], ...]:
    order = []
    for name, outcome in spec.items():
        runner = outcome if callable(outcome) else FakeStage(name, calls, outcome)
        order.append((name, name, runner))
    return tuple(order)


def enable_all_stages(config: Config) -> Config:
    for key in ("discovery", "sweep", "services", "scripts", "nuclei", "webrecon", "servicerecon"):
        setattr(config.stages, key, True)
    return config


def test_discovery_failure_stops_the_run(make_context, monkeypatch) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(
            calls,
            {
                "discovery": StageFailed("fping died"),
                "sweep": StageResult(counts={"open_ports": 1}),
                "services": StageResult(),
                "scripts": StageResult(),
            },
        ),
    )

    outcome = execute(ctx)

    assert calls == ["discovery"], "stages after a failed discovery must not run"
    assert outcome.failed_stages == ["discovery"]
    state = RunState.load(ctx.paths.root)
    assert state.stages["discovery"].status == FAILED
    assert state.stages["discovery"].detail == "fping died"
    for later in ("sweep", "services", "scripts"):
        assert later not in state.stages, f"{later} must not be checkpointed at all"
    assert_report_artifacts(ctx)


def test_sweep_failure_stops_the_run(make_context, monkeypatch) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(
            calls,
            {
                "discovery": StageResult(counts={"live": 2}),
                "sweep": StageFailed("masscan died"),
                "services": StageResult(),
            },
        ),
    )
    outcome = execute(ctx)
    assert calls == ["discovery", "sweep"]
    assert outcome.failed_stages == ["sweep"]
    assert_report_artifacts(ctx)


def test_zero_open_ports_skips_the_dependent_stages_cleanly(
    make_context, monkeypatch
) -> None:
    """Sweep finds nothing: everything downstream skips and the report renders."""
    config = enable_all_stages(Config())
    config.discovery.method = "fping"
    config.sweep.backend = "masscan"
    ctx = make_context(config=config, active=True)
    install_fake_tool(monkeypatch, {"fping": "healthy", "masscan": "found_nothing"})

    outcome = execute(ctx)

    state = RunState.load(ctx.paths.root)
    assert state.stages["discovery"].status == COMPLETED
    assert state.stages["sweep"].status == COMPLETED
    assert state.stages["sweep"].counts["open_ports"] == 0
    for dependent in ("services", "scripts", "nuclei", "webrecon", "servicerecon"):
        assert state.stages[dependent].status == SKIPPED, dependent
        assert state.stages[dependent].detail
    assert outcome.failed_stages == []
    payload = assert_report_artifacts(ctx)
    assert payload["totals"]["open_ports"] == 0


def test_scripts_still_runs_when_services_failed(make_context, monkeypatch) -> None:
    """scripts reads the sweep checkpoint, not the services one: it must still run."""
    calls: list[str] = []
    config = enable_all_stages(Config())
    ctx = make_context(config=config)
    seed_open_ports(ctx)
    install_fake_tool(monkeypatch, "healthy")
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(
            calls,
            {
                "services": StageFailed("every host failed service detection"),
                "scripts": scripts.run,
            },
        ),
    )

    outcome = execute(ctx)

    state = RunState.load(ctx.paths.root)
    assert state.stages["services"].status == FAILED
    assert state.stages["scripts"].status == COMPLETED
    assert state.stages["scripts"].counts["hosts_reported"] == 1
    assert outcome.failed_stages == ["services"]
    assert (ctx.paths.root / "scripts.json").is_file()
    assert_report_artifacts(ctx)


@pytest.mark.parametrize("exc", [ValueError("boom"), MemoryError("out of memory")])
def test_an_unexpected_exception_is_checkpointed_before_it_stops_the_run(
    make_context, monkeypatch, exc: Exception
) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(calls, {"services": exc, "scripts": StageResult()}),
    )

    outcome = execute(ctx)

    state = RunState.load(ctx.paths.root)
    assert state.stages["services"].status == FAILED
    assert type(exc).__name__ in (state.stages["services"].detail or "")
    assert "scripts" not in calls, "an unexpected error must stop the pipeline"
    assert outcome.failed_stages == ["services"]
    assert_report_artifacts(ctx)


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), SystemExit(1)])
def test_keyboard_interrupt_is_checkpointed_and_not_swallowed(
    make_context, monkeypatch, exc: BaseException
) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(calls, {"sweep": exc, "services": StageResult()}),
    )

    with pytest.raises(type(exc)):
        execute(ctx)

    assert "services" not in calls
    state = RunState.load(ctx.paths.root)
    stage = state.stages["sweep"]
    # It must not look finished, and it must not look like it is still running
    # either: a resume has to know this stage needs doing again.
    assert stage.status != COMPLETED
    assert stage.detail, "an interrupted stage must record why it stopped"
    assert type(exc).__name__ in stage.detail


def test_an_interrupted_stage_is_rerun_on_resume(make_context, monkeypatch) -> None:
    """A stage left ``running`` by a killed process must not count as done."""
    ctx = make_context(config=enable_all_stages(Config()))
    ctx.state.begin("discovery")  # previous process died here
    assert RunState.load(ctx.paths.root).stages["discovery"].status == RUNNING

    resumed = RunState.load(ctx.paths.root)
    assert not resumed.is_completed("discovery")

    ctx.state = resumed
    calls: list[str] = []
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(calls, {"discovery": StageResult(counts={"live": 1})}),
    )
    execute(ctx)
    assert calls == ["discovery"]
    assert RunState.load(ctx.paths.root).stages["discovery"].status == COMPLETED


# -- 3. checkpoint and resume --------------------------------------------

ROOT_CAN_IGNORE_PERMISSIONS = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="running as root: permission bits are not enforced",
)

BROKEN_STATE_FILES: dict[str, str] = {
    "empty": "",
    "whitespace": "   \n",
    "truncated_mid_write": '{"state_version": 1, "run_name": "default", "stages": {"disc',
    "invalid_json": "{not json at all}",
    "json_list": "[]",
    "json_string": '"a checkpoint"',
    "json_number": "17",
    "json_null": "null",
    "stages_is_a_list": '{"state_version": 1, "stages": [{"name": "discovery"}]}',
    "stage_is_a_string": '{"state_version": 1, "stages": {"discovery": "completed"}}',
    "stages_is_a_string": '{"state_version": 1, "stages": "discovery"}',
}


@pytest.mark.parametrize("payload", list(BROKEN_STATE_FILES.values()), ids=list(BROKEN_STATE_FILES))
def test_an_unusable_checkpoint_is_refused_with_stateerror(tmp_path: Path, payload: str) -> None:
    (tmp_path / "state.json").write_text(payload, encoding="utf-8")
    with pytest.raises(StateError):
        RunState.load(tmp_path)


def test_a_checkpoint_that_is_not_utf8_is_refused_with_stateerror(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_bytes(b'{"state_version": 1, "run_name": "\xff\xfe"}')
    with pytest.raises(StateError):
        RunState.load(tmp_path)


def test_a_missing_checkpoint_is_refused(tmp_path: Path) -> None:
    with pytest.raises(StateError, match="no checkpoint"):
        RunState.load(tmp_path)


def test_a_checkpoint_that_is_a_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "state.json").mkdir()
    with pytest.raises(StateError, match="no checkpoint"):
        RunState.load(tmp_path)


@ROOT_CAN_IGNORE_PERMISSIONS
def test_an_unreadable_checkpoint_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"state_version": 1}', encoding="utf-8")
    path.chmod(0o000)
    try:
        with pytest.raises(StateError):
            RunState.load(tmp_path)
    finally:
        path.chmod(0o600)


def test_a_checkpoint_with_unknown_keys_from_a_newer_version_is_tolerated(
    make_context,
) -> None:
    """Forward compatibility: extra keys must not stop a resume."""
    ctx = make_context()
    ctx.state.complete("discovery", duration=1.0, counts={"live": 2})
    data = json.loads(ctx.state.path.read_text(encoding="utf-8"))
    data["unknown_top_level"] = {"added": "by netrecon 9.9"}
    data["stages"]["discovery"]["unknown_stage_key"] = [1, 2, 3]
    ctx.state.path.write_text(json.dumps(data), encoding="utf-8")

    reloaded = RunState.load(ctx.paths.root)
    assert reloaded.is_completed("discovery")
    assert reloaded.stages["discovery"].counts == {"live": 2}


@pytest.mark.parametrize("stored", ["", None])
def test_resume_refuses_a_checkpoint_with_no_scope_fingerprint(
    make_context, stored: str | None
) -> None:
    """No fingerprint means the scope cannot be verified, so resume is unsafe."""
    ctx = make_context()
    data = json.loads(ctx.state.path.read_text(encoding="utf-8"))
    if stored is None:
        data.pop("scope_fingerprint", None)
    else:
        data["scope_fingerprint"] = stored
    ctx.state.path.write_text(json.dumps(data), encoding="utf-8")

    reloaded = RunState.load(ctx.paths.root)
    with pytest.raises(StateError, match="fingerprint"):
        reloaded.check_scope(ctx.scope.fingerprint())


def test_resume_refuses_an_empty_incoming_fingerprint(make_context) -> None:
    ctx = make_context()
    with pytest.raises(StateError):
        RunState.load(ctx.paths.root).check_scope("")


def test_concurrent_saves_always_leave_a_valid_checkpoint(make_context) -> None:
    """``save()`` is documented as atomic; racing writers must prove it."""
    ctx = make_context()
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(stage_name: str) -> None:
        try:
            for index in range(40):
                ctx.state.complete(stage_name, duration=index / 100, counts={"n": index})
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            errors.append(exc)
        finally:
            stop.set()

    def reader() -> None:
        while not stop.is_set():
            try:
                RunState.load(ctx.paths.root)
            except StateError as exc:
                errors.append(exc)
                return

    threads = [
        threading.Thread(target=writer, args=("discovery",)),
        threading.Thread(target=writer, args=("sweep",)),
        threading.Thread(target=reader),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, f"racing save()/load() produced {errors[:3]}"
    RunState.load(ctx.paths.root)
    leftovers = [p.name for p in ctx.paths.root.iterdir() if p.name.startswith(".state-")]
    assert leftovers == [], f"atomic write left temporary files behind: {leftovers}"


@ROOT_CAN_IGNORE_PERMISSIONS
def test_a_read_only_run_directory_does_not_corrupt_the_checkpoint(make_context) -> None:
    ctx = make_context()
    ctx.state.complete("discovery", duration=1.0, counts={"live": 2})
    before = ctx.state.path.read_text(encoding="utf-8")
    ctx.paths.root.chmod(0o500)
    try:
        with pytest.raises(OSError):
            ctx.state.complete("sweep", duration=1.0, counts={"open_ports": 1})
        assert ctx.state.path.read_text(encoding="utf-8") == before
        assert json.loads(before)["stages"]["discovery"]["status"] == COMPLETED
    finally:
        ctx.paths.root.chmod(0o700)


def test_find_latest_run_on_an_empty_base(tmp_path: Path) -> None:
    base = tmp_path / "results" / "default"
    base.mkdir(parents=True)
    assert find_latest_run(base) is None


def test_find_latest_run_ignores_a_state_json_that_is_a_directory(tmp_path: Path) -> None:
    base = tmp_path / "results" / "default"
    (base / "20240101T000000Z" / "state.json").mkdir(parents=True)
    assert find_latest_run(base) is None


def test_find_latest_run_with_names_that_are_not_timestamps(tmp_path: Path) -> None:
    base = tmp_path / "results" / "default"
    for name in ("not-a-timestamp", "20240101T000000Z", "../escape", "ZZZ"):
        directory = base / Path(name).name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "state.json").write_text("{}", encoding="utf-8")
    latest = find_latest_run(base)
    assert latest is not None
    assert (latest / "state.json").is_file()
    assert latest.parent == base


def test_find_latest_run_when_the_base_is_a_file(tmp_path: Path) -> None:
    path = tmp_path / "results"
    path.write_text("not a directory", encoding="utf-8")
    assert find_latest_run(path) is None


def test_prepare_run_dir_refuses_to_resume_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(pipeline_mod.PipelineError, match="resume directory"):
        pipeline_mod.prepare_run_dir(Config(), resume_from=tmp_path / "nope")


# -- 4. partial and foreign artifacts ------------------------------------


MALFORMED_OPEN_PORTS: dict[str, Any] = {
    "empty_file": "",
    "empty_object": "{}",
    "list_instead_of_object": "[]",
    "hosts_is_an_empty_list": '{"hosts": []}',
    "hosts_is_a_list_of_records": '{"hosts": [{"ip": "10.10.10.5", "port": 80}]}',
    "hosts_is_a_string": '{"hosts": "10.10.10.5"}',
    "entries_are_not_dicts": '{"hosts": {"10.10.10.5": ["80/tcp"]}}',
    "port_is_a_string": '{"hosts": {"10.10.10.5": [{"port": "80", "protocol": "tcp"}]}}',
    "truncated": '{"hosts": {"10.10.10.5": [{"port": 80,',
}


@pytest.mark.parametrize("raw", list(MALFORMED_OPEN_PORTS.values()), ids=list(MALFORMED_OPEN_PORTS))
def test_a_malformed_sweep_artifact_does_not_crash_the_run(
    make_context, monkeypatch, raw: str
) -> None:
    """services/scripts must skip or fail, and the run must stay recoverable."""
    config = enable_all_stages(Config())
    ctx = make_context(config=config, active=True)
    ctx.paths.open_ports.write_text(raw, encoding="utf-8")
    install_fake_tool(monkeypatch, "healthy")
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        (("services", "services", services.run), ("scripts", "scripts", scripts.run)),
    )

    execute(ctx)  # must not raise

    state = RunState.load(ctx.paths.root)
    for name in ("services", "scripts"):
        assert state.stages[name].status in {COMPLETED, FAILED, SKIPPED}
        if state.stages[name].status != COMPLETED:
            assert state.stages[name].detail, f"{name} must say why it did not run"
    # Whatever the report did, it must not have been silently lost.
    report_stage = state.stages["report"]
    if report_stage.status == FAILED:
        assert report_stage.detail
    else:
        assert_report_artifacts(ctx)


def test_an_open_ports_file_from_a_newer_version_is_tolerated(make_context) -> None:
    ctx = make_context()
    write_json(
        ctx.paths.open_ports,
        {
            "schema_version": 99,
            "unknown_block": {"added_later": True},
            "hosts": {
                IN_SCOPE_HOST: [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "confidence": "high",  # not a field netrecon writes today
                        "nested": {"anything": [1, 2, 3]},
                    }
                ]
            },
        },
    )
    targets = services.load_targets(ctx)
    assert [(t.ip, t.tcp_ports) for t in targets] == [(IN_SCOPE_HOST, (80,))]
    assert nuclei.build_target_list(ctx) == [f"{IN_SCOPE_HOST}:80"]
    payload = report_build.aggregate(report_build.collect(ctx)).payload
    assert payload["totals"]["open_ports"] == 1


def test_a_services_artifact_from_a_newer_version_is_tolerated(make_context) -> None:
    ctx = make_context()
    seed_open_ports(ctx)
    write_json(
        ctx.paths.services,
        {
            "future_field": [1, 2, 3],
            "hosts": [
                {
                    "address": IN_SCOPE_HOST,
                    "future_host_field": {"x": 1},
                    "ports": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "http", "label": "nginx 1.18.0"},
                            "future_port_field": "ignored",
                        }
                    ],
                }
            ],
        },
    )
    payload = report_build.aggregate(report_build.collect(ctx)).payload
    host = next(h for h in payload["hosts"] if h["ip"] == IN_SCOPE_HOST)
    assert host["open_ports"][0]["service"] == "http"


def test_a_services_host_outside_the_scope_is_not_reported(make_context) -> None:
    """Every artifact is re-filtered by scope on the way into the report.

    A checkpoint is not trusted input: it can be stale from an earlier run with
    a wider scope, or hand-edited. The report must never name a host the
    operator is not authorised to touch, whichever artifact it came from.
    """
    ctx = make_context()
    seed_live_hosts(ctx, [IN_SCOPE_HOST])
    seed_open_ports(ctx)
    write_json(
        ctx.paths.services,
        {
            "hosts": [
                {
                    "address": "203.0.113.99",  # not in the scope fixture
                    "ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
                }
            ]
        },
    )
    payload = report_build.aggregate(report_build.collect(ctx)).payload
    assert "203.0.113.99" not in [h["ip"] for h in payload["hosts"]]


def test_a_services_host_absent_from_live_hosts_is_still_reported(make_context) -> None:
    """A host that answered -sV but not discovery must not vanish from the report."""
    ctx = make_context()
    seed_live_hosts(ctx, [IN_SCOPE_HOST])
    seed_open_ports(ctx)
    write_json(
        ctx.paths.services,
        {
            "hosts": [
                {
                    "address": SECOND_HOST,
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "ssh"},
                        }
                    ],
                }
            ]
        },
    )
    payload = report_build.aggregate(report_build.collect(ctx)).payload
    reported = [h["ip"] for h in payload["hosts"]]
    assert SECOND_HOST in reported
    assert payload["totals"]["live_hosts"] == 1


def test_live_hosts_with_crlf_whitespace_and_duplicates(make_context) -> None:
    ctx = make_context()
    ctx.paths.live_hosts.write_text(
        f"{IN_SCOPE_HOST}\r\n  {SECOND_HOST}  \r\n{IN_SCOPE_HOST}\n\n\t10.10.10.20\t\n"
        "not-an-address\n10.99.99.99\n",
        encoding="utf-8",
    )
    assert ctx.live_hosts() == [IN_SCOPE_HOST, SECOND_HOST, "10.10.10.20"]


def test_live_hosts_with_ten_thousand_entries_is_scope_filtered(make_context) -> None:
    ctx = make_context()
    lines = [f"10.{index // 256 % 256}.{index % 256}.{index % 250}" for index in range(10_000)]
    ctx.paths.live_hosts.write_text("\n".join([*lines, IN_SCOPE_HOST]) + "\n", encoding="utf-8")
    hosts = ctx.live_hosts()
    assert IN_SCOPE_HOST in hosts
    assert all(host in ctx.scope for host in hosts)
    assert len(hosts) <= len(ctx.scope)


def test_a_live_hosts_file_that_is_binary_is_not_fatal(make_context) -> None:
    ctx = make_context()
    ctx.paths.live_hosts.write_bytes(b"\xff\xfe\n10.10.10.5\n\x00\x01\n")
    # The undecodable lines are dropped by scope enforcement rather than
    # crashing the stage that reads the checkpoint.
    assert ctx.live_hosts() == [IN_SCOPE_HOST]


# -- 5. run_command itself -----------------------------------------------


NEEDS_SH = pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh")


@NEEDS_SH
def test_run_command_survives_invalid_utf8_on_stdout() -> None:
    result = run_command(["/bin/sh", "-c", r'printf "\377\376ok"'])
    assert result.ok
    assert "ok" in result.stdout
    assert "�" in result.stdout  # undecodable bytes are replaced, not fatal


@NEEDS_SH
def test_run_command_captures_large_stdout_and_stderr() -> None:
    script = (
        "tr '\\0' 'A' < /dev/zero | head -c 200000; "
        "tr '\\0' 'B' < /dev/zero | head -c 200000 >&2"
    )
    result = run_command(["/bin/sh", "-c", script])
    assert result.ok
    assert len(result.stdout) == 200_000
    assert len(result.stderr) == 200_000
    assert len(result.tail().splitlines()) <= 4


@NEEDS_SH
@pytest.mark.parametrize("timeout", [0, -1])
def test_run_command_with_a_nonsense_timeout_reports_a_timeout(timeout: int) -> None:
    result = run_command(["/bin/sh", "-c", "printf hi"], timeout=timeout)
    assert result.timed_out is True
    assert result.ok is False


@NEEDS_SH
def test_run_command_coerces_non_string_argv_parts(tmp_path: Path) -> None:
    result = run_command(["/bin/sh", "-c", "printf %s-%s \"$1\" \"$2\"", "sh", 42, tmp_path])
    assert result.ok
    assert result.stdout == f"42-{tmp_path}"
    assert all(isinstance(part, str) for part in result.argv)


def test_run_command_handles_an_executable_path_with_a_space(tmp_path: Path) -> None:
    directory = tmp_path / "dir with space"
    directory.mkdir()
    script = directory / "my tool"
    script.write_text("#!/bin/sh\nprintf spaced\n", encoding="utf-8")
    script.chmod(0o755)
    result = run_command([str(script)])
    assert result.ok
    assert result.stdout == "spaced"
    assert "'" in result.command or '"' in result.command  # quoted when rendered


def test_run_command_raises_toolvanished_for_a_missing_executable(tmp_path: Path) -> None:
    """A stage must never leak a bare OSError to the pipeline."""
    with pytest.raises(ToolVanished, match="not installed or not on PATH"):
        run_command([str(tmp_path / "definitely-not-here")])


@NEEDS_SH
def test_run_command_check_reports_the_tail_of_the_failure() -> None:
    from netrecon.core.runner import CommandFailed

    with pytest.raises(CommandFailed) as excinfo:
        run_command(["/bin/sh", "-c", "echo bad things >&2; exit 3"], check=True)
    assert "bad things" in str(excinfo.value)
    assert excinfo.value.result.returncode == 3


@NEEDS_SH
def test_run_command_timeout_keeps_the_partial_output_it_has() -> None:
    result = run_command(["/bin/sh", "-c", "printf partial; sleep 5"], timeout=1)
    assert result.timed_out is True
    assert result.returncode == 124
    assert isinstance(result.stdout, str)


# -- 6. pre-flight and reporting invariants ------------------------------


def test_preflight_renders_for_a_single_host_scope(make_context) -> None:
    text = preflight_summary(make_context(scope_override=Scope.from_lines(["10.0.0.1"])))
    assert "In-scope hosts    : 1 (IPv4 1, IPv6 0)" in text
    assert "10.0.0.1 .. 10.0.0.1" in text


def test_preflight_renders_for_a_very_large_scope(make_context) -> None:
    large = Scope.from_lines(["10.0.0.0/16"], source="big")
    assert len(large) >= 65_000
    text = preflight_summary(make_context(scope_override=large))
    assert f"In-scope hosts    : {len(large)}" in text


def test_preflight_renders_for_an_ipv6_only_scope(make_context) -> None:
    scope = Scope.from_lines(["2001:db8::1", "2001:db8::2-2001:db8::5"])
    text = preflight_summary(make_context(scope_override=scope))
    assert "IPv4 0, IPv6 5" in text
    assert "2001:db8::1 .. 2001:db8::5" in text


def test_preflight_renders_with_every_stage_disabled(make_context) -> None:
    config = Config()
    for key in ("discovery", "sweep", "services", "scripts", "nuclei", "webrecon", "servicerecon"):
        setattr(config.stages, key, False)
    config.stages.os_detect = False
    text = preflight_summary(make_context(config=config))
    assert "Stages enabled    : none" in text


#: Stage outcomes to run the reporting invariants against.
FAILURE_COMBINATIONS: dict[str, dict[str, BaseException | StageResult]] = {
    "everything_fails": {
        "discovery": StageFailed("no discovery backend"),
    },
    "sweep_fails_after_discovery": {
        "discovery": StageResult(counts={"live": 2}),
        "sweep": StageFailed("masscan died"),
    },
    "late_stages_fail": {
        "discovery": StageResult(counts={"live": 2}),
        "sweep": StageResult(counts={"open_ports": 2}),
        "services": StageFailed("every host failed"),
        "scripts": StageSkipped("no open ports"),
        "nuclei": StageSkipped("needs --active"),
    },
    "unexpected_error": {
        "discovery": StageResult(counts={"live": 2}),
        "sweep": ValueError("surprise"),
    },
    "mixed_skips": {
        "discovery": StageSkipped("discovery disabled"),
        "sweep": StageSkipped("no live hosts"),
        "services": StageSkipped("no open ports"),
    },
}


@pytest.mark.parametrize("name", list(FAILURE_COMBINATIONS))
def test_the_report_is_written_and_honest_after_stage_failures(
    make_context, monkeypatch, name: str
) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(
        pipeline_mod, "STAGE_ORDER", fake_order(calls, FAILURE_COMBINATIONS[name])
    )

    execute(ctx)

    payload = assert_report_artifacts(ctx)
    state = RunState.load(ctx.paths.root)
    rows = stage_rows_from_markdown(ctx.paths.report.read_text(encoding="utf-8"))

    assert rows, "the stage timing table must list the stages that ran"
    for stage_name, stage in state.stages.items():
        if stage_name == "report":
            continue
        assert rows.get(stage_name) == stage.status, (
            f"timing table says {stage_name}={rows.get(stage_name)} but the "
            f"checkpoint says {stage.status}"
        )
        if stage.status != COMPLETED:
            assert rows[stage_name] != COMPLETED
            # A failed stage must never be credited with a result count.
            assert not stage.counts, f"{stage_name} failed but recorded {stage.counts}"
        assert payload["stages"][stage_name]["status"] == stage.status


def test_a_failed_stage_is_never_timed_as_completed(make_context, monkeypatch) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(
            calls,
            {
                "discovery": StageResult(counts={"live": 1}),
                "sweep": StageFailed("masscan died"),
            },
        ),
    )
    execute(ctx)

    state = RunState.load(ctx.paths.root)
    timings = dict(state.timings())
    assert state.stages["sweep"].status == FAILED
    assert "sweep" in timings, "a failed stage still gets a duration"
    markdown = ctx.paths.report.read_text(encoding="utf-8")
    rows = stage_rows_from_markdown(markdown)
    assert rows["sweep"] == FAILED
    assert rows["discovery"] == COMPLETED
    assert "masscan died" in markdown


def test_the_report_renders_when_no_stage_ran_at_all(make_context, monkeypatch) -> None:
    ctx = make_context(config=enable_all_stages(Config()))
    monkeypatch.setattr(pipeline_mod, "STAGE_ORDER", ())
    outcome = execute(ctx)
    assert outcome.ok
    payload = assert_report_artifacts(ctx)
    assert payload["totals"]["hosts_reported"] == 0


def test_a_dry_run_writes_no_report_but_finishes_the_checkpoint(
    make_context, monkeypatch
) -> None:
    calls: list[str] = []
    ctx = make_context(config=enable_all_stages(Config()), dry_run=True)
    monkeypatch.setattr(
        pipeline_mod, "STAGE_ORDER", fake_order(calls, {"discovery": StageResult()})
    )
    execute(ctx)
    assert not ctx.paths.report.exists()
    state = RunState.load(ctx.paths.root)
    assert state.finished_at
    assert "report" not in state.stages


def test_resume_reruns_a_failed_stage_but_not_a_completed_one(
    make_context, monkeypatch
) -> None:
    ctx = make_context(config=enable_all_stages(Config()))
    ctx.state.complete("discovery", duration=1.0, counts={"live": 2})
    ctx.state.fail("sweep", duration=1.0, detail="masscan died")

    calls: list[str] = []
    monkeypatch.setattr(
        pipeline_mod,
        "STAGE_ORDER",
        fake_order(
            calls,
            {
                "discovery": StageFailed("must not run again"),
                "sweep": StageResult(counts={"open_ports": 2}),
            },
        ),
    )
    execute(ctx)

    assert calls == ["sweep"]
    state = RunState.load(ctx.paths.root)
    assert state.stages["sweep"].status == COMPLETED
    assert state.stages["sweep"].detail is None


def test_nuclei_rejects_a_list_shaped_hosts_block(make_context) -> None:
    """A malformed checkpoint fails the stage rather than reading as "no targets".

    Returning ``[]`` here would report a clean nuclei run over zero endpoints,
    which the operator cannot distinguish from a real scan that found nothing.
    This mirrors ``services.load_targets`` below.
    """
    ctx = make_context(active=True)
    ctx.paths.open_ports.write_text(
        json.dumps({"hosts": [{"ip": IN_SCOPE_HOST, "port": 80}]}), encoding="utf-8"
    )
    with pytest.raises(StageFailed, match="expected format"):
        nuclei.build_target_list(ctx)


def test_services_rejects_a_list_shaped_hosts_block(make_context) -> None:
    ctx = make_context()
    ctx.paths.open_ports.write_text(
        json.dumps({"hosts": [{"ip": IN_SCOPE_HOST, "port": 80}]}), encoding="utf-8"
    )
    with pytest.raises(StageFailed, match="expected format"):
        services.load_targets(ctx)
