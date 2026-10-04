"""The scan command's scope resolution, especially on resume.

Found by actually interrupting a run and trying to resume it: --resume-dir
demanded --targets even though the run directory already holds a scope.txt
snapshot of the expanded set. Making the operator retype the scope on resume
is not just friction -- it is one more chance to resume a run against the
wrong scope file, which is the one mistake this tool must not make easy.

The snapshot is the safe default precisely because prepare_run_dir refuses a
checkpoint whose scope fingerprint does not match.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from netrecon import __version__
from netrecon.cli import app
from netrecon.core.scope import Scope
from netrecon.core.state import RunState

runner = CliRunner()

SCOPE = "127.0.0.1\n"


def _run_dir_with_snapshot(tmp_path: Path) -> Path:
    """A resumable run directory: the scope snapshot plus a real checkpoint."""
    run_dir = tmp_path / "results" / "default" / "20240101T000000Z"
    run_dir.mkdir(parents=True)
    (run_dir / "scope.txt").write_text(SCOPE, encoding="utf-8")
    scope = Scope.from_lines(SCOPE.splitlines(), source="snapshot")
    RunState.create(
        run_dir,
        run_name="default",
        scope_fingerprint=scope.fingerprint(),
        scope_source="snapshot",
        netrecon_version=__version__,
        config_snapshot={},
    ).save()
    return run_dir


def test_scan_without_targets_and_without_resume_is_a_usage_error(tmp_path) -> None:
    result = runner.invoke(app, ["scan", "--yes", "-o", str(tmp_path)])
    assert result.exit_code != 0
    assert "--targets is required" in result.output


def test_resuming_a_directory_with_no_snapshot_says_what_to_pass(tmp_path) -> None:
    empty = tmp_path / "run"
    empty.mkdir()
    result = runner.invoke(
        app, ["scan", "--resume-dir", str(empty), "--yes", "-o", str(tmp_path)]
    )
    assert result.exit_code != 0
    assert "no scope.txt snapshot" in result.output
    assert "--targets" in result.output


def test_resuming_defaults_to_the_run_s_own_scope_snapshot(tmp_path) -> None:
    """No --targets, and the run still resolves its scope."""
    run_dir = _run_dir_with_snapshot(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            "--resume-dir",
            str(run_dir),
            "--dry-run",
            "--yes",
            "-o",
            str(tmp_path / "results"),
        ],
    )
    assert result.exit_code == 0, result.output
    # The snapshot held exactly one address, and the pre-flight reports it.
    assert "1" in result.output


def test_an_explicit_targets_file_still_wins_on_resume(tmp_path) -> None:
    """Passing --targets is still allowed; the fingerprint guard judges it."""
    run_dir = _run_dir_with_snapshot(tmp_path)
    other = tmp_path / "other.txt"
    other.write_text(SCOPE, encoding="utf-8")  # same scope, so no fingerprint clash
    result = runner.invoke(
        app,
        [
            "scan",
            "--resume-dir",
            str(run_dir),
            "-t",
            str(other),
            "--dry-run",
            "--yes",
            "-o",
            str(tmp_path / "results"),
        ],
    )
    assert result.exit_code == 0, result.output
