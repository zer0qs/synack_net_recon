"""Artifact file modes.

A run directory holds client-confidential data: service versions, internal
hostnames, the client's authorised address list, fetched response bodies, and
the secret and PII candidates found in front-end code.

Found by looking at a real run directory, not by a unit test. The JSON
artifacts were already 0600, but only as a side effect of writing them through
``tempfile.NamedTemporaryFile``; nothing asked for it and nothing checked it.
Meanwhile ``report.md``, ``report.html``, ``run.log`` and the ``scope.txt``
snapshot -- the files an operator actually opens -- took whatever the umask
gave, which is world-readable on a stock Linux.

Files written by nmap, fping and naabu keep their own mode, because netrecon
does not control those writes. They are protected by their 0700 parent
directory instead, which is the boundary these tests pin.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from netrecon.core.jsonio import (
    ARTIFACT_MODE,
    RUN_DIR_MODE,
    secure_mkdir,
    write_json,
    write_lines,
    write_text,
)
from netrecon.core.scope import Scope


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def group_or_other_can_read(path: Path) -> bool:
    return bool(mode_of(path) & (stat.S_IRGRP | stat.S_IROTH))


# -- the writers netrecon controls -------------------------------------

@pytest.mark.parametrize(
    ("writer", "payload"),
    [
        (write_json, {"secret": "value"}),
        (write_lines, ["10.0.0.1"]),
        (write_text, "# report\n\ninternal.corp\n"),
    ],
)
def test_every_artifact_writer_sets_the_artifact_mode(tmp_path, writer, payload) -> None:
    path = tmp_path / "artifact"
    writer(path, payload)
    assert mode_of(path) == ARTIFACT_MODE
    assert not group_or_other_can_read(path)


def test_a_rewritten_artifact_keeps_the_mode(tmp_path) -> None:
    """The atomic write replaces the file, so the mode must be re-applied."""
    path = tmp_path / "artifact.json"
    write_json(path, {"first": True})
    path.chmod(0o644)  # simulate a file left open by an older run
    write_json(path, {"second": True})
    assert mode_of(path) == ARTIFACT_MODE


def test_the_scope_snapshot_is_not_world_readable(tmp_path) -> None:
    """scope.txt is the client's authorised address list."""
    scope = Scope.from_lines(["10.0.0.1", "10.0.0.2"], source="test")
    path, count = scope.write_targets(tmp_path / "scope.txt")
    assert count == 2
    assert mode_of(path) == ARTIFACT_MODE


# -- directories --------------------------------------------------------

def test_secure_mkdir_locks_every_component_it_creates(tmp_path) -> None:
    """`mkdir(parents=True, mode=...)` applies the mode to the last component
    only, which left intermediate artifact directories world-readable."""
    deep = tmp_path / "webrecon" / "10_0_0_1_443" / "http"
    secure_mkdir(deep)
    for component in (deep, deep.parent, deep.parent.parent):
        assert mode_of(component) == RUN_DIR_MODE, component
        assert not group_or_other_can_read(component)


def test_secure_mkdir_does_not_touch_directories_it_did_not_create(tmp_path) -> None:
    """An operator's chosen output directory is theirs, not netrecon's."""
    existing = tmp_path / "chosen"
    existing.mkdir(mode=0o755)
    secure_mkdir(existing / "run")
    assert mode_of(existing) == 0o755
    assert mode_of(existing / "run") == RUN_DIR_MODE


def test_secure_mkdir_is_idempotent(tmp_path) -> None:
    target = tmp_path / "a" / "b"
    secure_mkdir(target)
    secure_mkdir(target)
    assert mode_of(target) == RUN_DIR_MODE


def test_run_paths_ensure_locks_the_run_directory(tmp_path) -> None:
    from netrecon.core.runner import RunPaths

    paths = RunPaths(tmp_path / "results" / "run" / "20240101T000000Z")
    paths.ensure()
    for directory in (paths.root, paths.nmap_dir, paths.raw_dir, paths.targets_dir):
        assert mode_of(directory) == RUN_DIR_MODE, directory
        assert not group_or_other_can_read(directory)
