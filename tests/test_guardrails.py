"""Tests for the safety guardrails: rate caps, NSE policy, privilege detection.

These are the checks that keep netrecon from turning into a denial-of-service
tool or running intrusive scripts, so they are asserted directly rather than
only through the CLI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netrecon.core.config import (
    CONCURRENCY_HARD_MAX,
    MASSCAN_RATE_HARD_MAX,
    MASSCAN_RATE_WARN_THRESHOLD,
    NUCLEI_RATE_HARD_MAX,
    Config,
    ConfigError,
)
from netrecon.core.privileges import CAP_NET_RAW_BIT, Privileges, detect, has_capability
from netrecon.stages.nuclei import validate_templates
from netrecon.stages.scripts import (
    ALLOWED_CATEGORIES,
    FORBIDDEN_CATEGORIES,
    ScriptPolicyError,
    build_script_expression,
    validate_categories,
)

# -- rate caps -----------------------------------------------------------


def test_masscan_rate_above_hard_max_is_clamped():
    config = Config.from_dict({"limits": {"masscan_rate": 10_000_000}})
    assert config.limits.masscan_rate == MASSCAN_RATE_HARD_MAX
    assert any("clamped" in w for w in config.warnings)


def test_masscan_rate_above_warn_threshold_warns_but_is_kept():
    config = Config.from_dict({"limits": {"masscan_rate": 5_000}})
    assert config.limits.masscan_rate == 5_000
    assert any("above the safe default" in w for w in config.warnings)


def test_default_masscan_rate_is_the_safe_default_and_warns_about_nothing():
    config = Config()
    config.validate()
    assert config.limits.masscan_rate == MASSCAN_RATE_WARN_THRESHOLD
    assert config.warnings == []


def test_zero_or_negative_rate_is_rejected():
    with pytest.raises(ConfigError, match="masscan_rate"):
        Config.from_dict({"limits": {"masscan_rate": 0}})


def test_nuclei_rate_is_clamped():
    config = Config.from_dict({"limits": {"nuclei_rate": 100_000}})
    assert config.limits.nuclei_rate == NUCLEI_RATE_HARD_MAX


def test_concurrency_is_clamped():
    config = Config.from_dict({"limits": {"concurrency": 4096}})
    assert config.limits.concurrency == CONCURRENCY_HARD_MAX


def test_nmap_timing_out_of_range_is_rejected():
    with pytest.raises(ConfigError, match="nmap_timing"):
        Config.from_dict({"limits": {"nmap_timing": 9}})


def test_timing_5_warns():
    config = Config.from_dict({"limits": {"nmap_timing": 5}})
    assert any("aggressive" in w for w in config.warnings)


def test_unknown_config_keys_are_rejected():
    with pytest.raises(ConfigError, match="unknown config key"):
        Config.from_dict({"totally_unexpected": 1})


def test_unknown_nested_keys_are_rejected():
    with pytest.raises(ConfigError, match="unknown key"):
        Config.from_dict({"limits": {"masscan_rat": 10}})


def test_run_name_must_be_a_single_path_segment():
    with pytest.raises(ConfigError, match="run_name"):
        Config.from_dict({"run_name": "../../etc"})


def test_shipped_default_config_loads_and_is_conservative():
    config = Config.load(Path("configs/default.yaml"))
    assert config.limits.masscan_rate <= MASSCAN_RATE_WARN_THRESHOLD
    assert config.stages.nuclei is False, "the active stage must be off by default"
    assert config.stages.scripts is False, "NSE scripts must be opt-in"
    assert config.stages.os_detect is False
    assert config.warnings == []


def test_port_specs_are_normalised_and_validated():
    config = Config.from_dict({"ports": {"sweep": "80, 443,\n 8080-8090"}})
    assert config.ports.sweep == "80,443,8080-8090"


@pytest.mark.parametrize("bad", ["80,,443", "0", "70000", "443-80", "http", "80;rm -rf /"])
def test_invalid_port_specs_are_rejected(bad: str):
    with pytest.raises(ConfigError):
        Config.from_dict({"ports": {"sweep": bad}})


# -- NSE policy ----------------------------------------------------------


@pytest.mark.parametrize("category", sorted(FORBIDDEN_CATEGORIES))
def test_forbidden_nse_categories_are_refused(category: str):
    with pytest.raises(ScriptPolicyError, match="blocked"):
        validate_categories([category])


@pytest.mark.parametrize("category", sorted(FORBIDDEN_CATEGORIES))
def test_forbidden_nse_categories_are_refused_via_config(category: str):
    with pytest.raises(ConfigError):
        Config.from_dict({"scripts": {"categories": [category]}})


def test_unknown_categories_are_refused():
    with pytest.raises(ScriptPolicyError, match="not permitted"):
        validate_categories(["safe", "madeupcategory"])


def test_case_and_whitespace_are_normalised():
    assert validate_categories([" Default ", "DISCOVERY"]) == ["default", "discovery"]


def test_duplicate_categories_collapse():
    assert validate_categories(["safe", "safe"]) == ["safe"]


@pytest.mark.parametrize(
    "injection",
    ["default,brute", "http-*", "/tmp/evil.nse", "default or brute", "vuln;default", ""],
)
def test_script_expressions_and_paths_cannot_be_smuggled_in(injection: str):
    with pytest.raises(ScriptPolicyError):
        validate_categories([injection])


def test_expression_forces_safe_and_negates_every_forbidden_category():
    expression = build_script_expression(["default", "discovery"])
    assert expression.startswith("(default or discovery) and safe and not (")
    for category in FORBIDDEN_CATEGORIES:
        assert category in expression, f"{category} must be explicitly excluded"


def test_allowed_and_forbidden_sets_do_not_overlap():
    assert not (ALLOWED_CATEGORIES & FORBIDDEN_CATEGORIES)


def test_empty_category_list_is_refused():
    with pytest.raises(ScriptPolicyError):
        validate_categories([])


# -- nuclei template policy ---------------------------------------------


def test_nuclei_network_templates_are_allowed():
    assert validate_templates(["network/"]) == ["network/"]


@pytest.mark.parametrize(
    "template",
    ["fuzzing/", "dos/cisco-dos.yaml", "default-logins/", "network/../../etc", "-itself"],
)
def test_intrusive_nuclei_templates_are_refused(template: str):
    with pytest.raises(Exception):
        validate_templates([template])


# -- privilege detection -------------------------------------------------


def _write_status(tmp_path: Path, cap_hex: str) -> Path:
    path = tmp_path / "status"
    path.write_text(
        f"Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t{cap_hex}\n",
        encoding="utf-8",
    )
    return path


def test_cap_net_raw_is_detected_when_present(tmp_path: Path):
    status = _write_status(tmp_path, f"{1 << CAP_NET_RAW_BIT:016x}")
    assert has_capability(CAP_NET_RAW_BIT, status) is True


def test_cap_net_raw_absent_when_not_in_mask(tmp_path: Path):
    status = _write_status(tmp_path, "0000000000000000")
    assert has_capability(CAP_NET_RAW_BIT, status) is False


def test_unreadable_status_means_no_capability(tmp_path: Path):
    assert has_capability(CAP_NET_RAW_BIT, tmp_path / "missing") is False


def test_malformed_status_means_no_capability(tmp_path: Path):
    path = tmp_path / "status"
    path.write_text("CapEff:\tnot-hex\n", encoding="utf-8")
    assert has_capability(CAP_NET_RAW_BIT, path) is False


def test_root_implies_raw_sockets():
    privs = Privileges(euid=0, is_root=True, cap_net_raw=False, cap_net_admin=False)
    assert privs.raw_sockets is True
    assert "root" in privs.reason


def test_cap_net_raw_without_root_implies_raw_sockets():
    privs = Privileges(euid=1000, is_root=False, cap_net_raw=True, cap_net_admin=False)
    assert privs.raw_sockets is True
    assert "CAP_NET_RAW" in privs.reason


def test_unprivileged_reports_clearly():
    privs = Privileges(euid=1000, is_root=False, cap_net_raw=False, cap_net_admin=False)
    assert privs.raw_sockets is False
    assert "without CAP_NET_RAW" in privs.reason
    assert "unavailable" in privs.describe()


def test_detect_returns_a_consistent_object():
    privs = detect()
    assert privs.raw_sockets == (privs.is_root or privs.cap_net_raw)
