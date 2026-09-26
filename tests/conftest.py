"""Shared fixtures. Nothing here touches the network."""

from __future__ import annotations

from pathlib import Path

import pytest

from netrecon.core.config import Config
from netrecon.core.privileges import Privileges
from netrecon.core.runner import RunContext, RunPaths
from netrecon.core.scope import Scope
from netrecon.core.state import RunState
from netrecon.core.tools import TOOL_SPECS, ToolRegistry, ToolStatus

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def scope() -> Scope:
    """10.10.10.5, .6, .20, .30-.32 and 203.0.113.7 (from the fixture file)."""
    return Scope.from_file(FIXTURES / "scope_basic.txt")


@pytest.fixture()
def fake_tools() -> ToolRegistry:
    """All supported tools reported as installed, without probing the system."""
    return ToolRegistry(
        {
            spec.name: ToolStatus(spec, f"/usr/bin/{spec.name}", "9.99")
            for spec in TOOL_SPECS
        }
    )


@pytest.fixture()
def no_tools() -> ToolRegistry:
    return ToolRegistry(
        {spec.name: ToolStatus(spec, None, None, "not found on PATH") for spec in TOOL_SPECS}
    )


@pytest.fixture()
def privileged() -> Privileges:
    return Privileges(euid=0, is_root=True, cap_net_raw=True, cap_net_admin=True)


@pytest.fixture()
def unprivileged() -> Privileges:
    return Privileges(euid=1000, is_root=False, cap_net_raw=False, cap_net_admin=False)


@pytest.fixture()
def make_context(tmp_path: Path, scope: Scope, fake_tools: ToolRegistry, privileged: Privileges):
    """Factory for a RunContext rooted in a temporary run directory."""

    def _factory(
        *,
        config: Config | None = None,
        scope_override: Scope | None = None,
        tools: ToolRegistry | None = None,
        privileges: Privileges | None = None,
        active: bool = False,
        dry_run: bool = False,
    ) -> RunContext:
        config = config or Config()
        config.validate()
        active_scope = scope_override or scope
        run_dir = tmp_path / "results" / config.run_name / "20240520T101320Z"
        paths = RunPaths(run_dir)
        paths.ensure()
        state = RunState.create(
            run_dir,
            run_name=config.run_name,
            scope_fingerprint=active_scope.fingerprint(),
            scope_source=active_scope.source,
            netrecon_version="test",
            config_snapshot=config.to_dict(),
        )
        return RunContext(
            config=config,
            scope=active_scope,
            paths=paths,
            state=state,
            tools=tools or fake_tools,
            privileges=privileges or privileged,
            active=active,
            dry_run=dry_run,
        )

    return _factory
