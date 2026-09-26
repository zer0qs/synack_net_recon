"""Tests for CIDR expansion and scope enforcement.

No live scanning happens anywhere in the suite - scope objects are built from
literal strings and the fixture file.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from netrecon.core.scope import (
    DEFAULT_MAX_HOSTS,
    Scope,
    ScopeParseError,
    ScopeViolation,
)

FIXTURES = Path(__file__).parent / "fixtures"


# -- CIDR expansion ------------------------------------------------------


def test_single_ip_expands_to_one_address():
    scope = Scope.from_lines(["10.0.0.1"])
    assert [str(a) for a in scope.addresses] == ["10.0.0.1"]
    assert len(scope) == 1


def test_slash_32_expands_to_the_host_itself():
    scope = Scope.from_lines(["192.0.2.55/32"])
    assert [str(a) for a in scope.addresses] == ["192.0.2.55"]


def test_slash_31_includes_both_addresses():
    scope = Scope.from_lines(["192.0.2.0/31"])
    assert [str(a) for a in scope.addresses] == ["192.0.2.0", "192.0.2.1"]


def test_slash_30_excludes_network_and_broadcast():
    scope = Scope.from_lines(["10.10.10.4/30"])
    assert [str(a) for a in scope.addresses] == ["10.10.10.5", "10.10.10.6"]


def test_slash_24_expands_to_254_usable_hosts():
    scope = Scope.from_lines(["192.168.1.0/24"])
    assert len(scope) == 254
    assert "192.168.1.0" not in scope, "network address must not be scanned"
    assert "192.168.1.255" not in scope, "broadcast address must not be scanned"
    assert "192.168.1.1" in scope
    assert "192.168.1.254" in scope


def test_include_network_broadcast_opt_in():
    scope = Scope.from_lines(["192.168.1.0/24"], include_network_broadcast=True)
    assert len(scope) == 256
    assert "192.168.1.0" in scope
    assert "192.168.1.255" in scope


def test_non_aligned_cidr_is_accepted_as_its_network():
    # 10.0.0.5/29 is not on a /29 boundary; ip_network(strict=False) -> 10.0.0.0/29
    scope = Scope.from_lines(["10.0.0.5/29"])
    assert len(scope) == 6
    assert "10.0.0.1" in scope
    assert "10.0.0.0" not in scope


def test_dash_range_is_inclusive():
    scope = Scope.from_lines(["10.0.0.10-10.0.0.13"])
    assert [str(a) for a in scope.addresses] == [
        "10.0.0.10",
        "10.0.0.11",
        "10.0.0.12",
        "10.0.0.13",
    ]


def test_single_address_range_is_allowed():
    scope = Scope.from_lines(["10.0.0.10-10.0.0.10"])
    assert len(scope) == 1


def test_overlapping_entries_are_deduplicated():
    scope = Scope.from_lines(["10.0.0.0/30", "10.0.0.1", "10.0.0.1-10.0.0.2"])
    assert [str(a) for a in scope.addresses] == ["10.0.0.1", "10.0.0.2"]


def test_addresses_are_sorted_numerically_not_lexically():
    scope = Scope.from_lines(["10.0.0.20", "10.0.0.3", "10.0.0.100"])
    assert [str(a) for a in scope.addresses] == ["10.0.0.3", "10.0.0.20", "10.0.0.100"]


def test_ipv6_host_and_prefix():
    scope = Scope.from_lines(["2001:db8::1", "2001:db8::10/126"])
    assert len(scope) == 5  # ::1 plus four addresses in the /126
    assert "2001:db8::1" in scope
    assert "2001:db8::11" in scope


def test_mixed_families_are_grouped_v4_first():
    scope = Scope.from_lines(["2001:db8::1", "10.0.0.1"])
    assert [str(a) for a in scope.addresses] == ["10.0.0.1", "2001:db8::1"]
    assert scope.summary()["ipv4_hosts"] == 1
    assert scope.summary()["ipv6_hosts"] == 1


def test_comments_and_blank_lines_are_ignored():
    scope = Scope.from_lines(
        ["# header", "", "   ", "10.0.0.1  # inline comment", "\t10.0.0.2"]
    )
    assert len(scope) == 2


# -- rejection -----------------------------------------------------------


def test_hostnames_are_rejected_not_resolved():
    scope = Scope.from_lines(["10.0.0.1", "target.example.com"])
    assert len(scope) == 1
    assert len(scope.rejects) == 1
    assert "hostname" in scope.rejects[0].reason


def test_garbage_lines_are_rejected_with_line_numbers():
    scope = Scope.from_lines(["10.0.0.1", "10.0.0.999", "999.999.999.999", "::/0zz"])
    assert len(scope) == 1
    assert [r.lineno for r in scope.rejects] == [2, 3, 4]


def test_reversed_range_is_rejected():
    scope = Scope.from_lines(["10.0.0.1", "10.0.0.50-10.0.0.40"])
    assert len(scope) == 1
    assert "lower than" in scope.rejects[0].reason


def test_range_across_families_is_rejected():
    scope = Scope.from_lines(["10.0.0.1", "10.0.0.1-2001:db8::1"])
    assert len(scope) == 1
    assert "same IP version" in scope.rejects[0].reason


def test_empty_scope_raises():
    with pytest.raises(ScopeParseError, match="no in-scope addresses"):
        Scope.from_lines(["# only a comment", "example.com"])


def test_scope_larger_than_max_hosts_raises():
    with pytest.raises(ScopeParseError, match="more than"):
        Scope.from_lines(["10.0.0.0/8"], max_hosts=1024)


def test_max_hosts_boundary_is_allowed():
    scope = Scope.from_lines(["10.0.0.0/24"], max_hosts=254)
    assert len(scope) == 254


def test_missing_file_raises():
    with pytest.raises(ScopeParseError, match="not found"):
        Scope.from_file("/nonexistent/scope.txt")


def test_default_max_hosts_blocks_a_slash_8():
    with pytest.raises(ScopeParseError):
        Scope.from_lines(["10.0.0.0/8"], max_hosts=DEFAULT_MAX_HOSTS)


# -- fixture file --------------------------------------------------------


def test_fixture_scope_file_parses_as_expected():
    scope = Scope.from_file(FIXTURES / "scope_basic.txt")
    assert [str(a) for a in scope.addresses] == [
        "10.10.10.5",
        "10.10.10.6",
        "10.10.10.20",
        "10.10.10.30",
        "10.10.10.31",
        "10.10.10.32",
        "203.0.113.7",
    ]
    reasons = [r.reason for r in scope.rejects]
    assert len(reasons) == 4
    assert any("hostname" in reason for reason in reasons)
    assert scope.summary()["total_hosts"] == 7
    assert scope.source is not None


# -- enforcement ---------------------------------------------------------


@pytest.fixture()
def scope() -> Scope:
    return Scope.from_lines(["10.10.10.4/30", "10.10.10.20"])


def test_enforce_keeps_in_scope_and_drops_the_rest(scope: Scope):
    result = scope.enforce(["10.10.10.5", "192.168.99.99", "10.10.10.20"])
    assert result.allowed_str == ("10.10.10.5", "10.10.10.20")
    assert [candidate for candidate, _ in result.rejected] == ["192.168.99.99"]


def test_enforce_drops_the_network_address_of_an_expanded_prefix(scope: Scope):
    result = scope.enforce(["10.10.10.4", "10.10.10.7"])
    assert result.allowed_str == ()
    assert len(result.rejected) == 2


def test_enforce_rejects_non_addresses(scope: Scope):
    result = scope.enforce(["10.10.10.5:80", "web01.internal", "", "  "])
    assert result.allowed_str == ()
    assert [reason for _, reason in result.rejected] == [
        "not a bare IP address",
        "not a bare IP address",
    ]


def test_enforce_deduplicates_and_sorts(scope: Scope):
    result = scope.enforce(["10.10.10.20", "10.10.10.5", "10.10.10.20"])
    assert result.allowed_str == ("10.10.10.5", "10.10.10.20")


def test_enforce_accepts_ip_objects(scope: Scope):
    result = scope.enforce([ipaddress.ip_address("10.10.10.5")])
    assert result.allowed_str == ("10.10.10.5",)


def test_enforce_strict_raises_on_out_of_scope(scope: Scope):
    with pytest.raises(ScopeViolation, match="out-of-scope"):
        scope.enforce_strict(["10.10.10.5", "8.8.8.8"])


def test_enforce_strict_passes_when_all_in_scope(scope: Scope):
    assert [str(a) for a in scope.enforce_strict(["10.10.10.6"])] == ["10.10.10.6"]


def test_membership_for_unparseable_values_is_false(scope: Scope):
    assert "not-an-ip" not in scope
    assert None not in scope


def test_write_targets_only_writes_in_scope_addresses(scope: Scope, tmp_path: Path):
    path, count = scope.write_targets(tmp_path / "targets.txt", ["10.10.10.5", "10.10.10.20"])
    assert count == 2
    assert path.read_text().splitlines() == ["10.10.10.5", "10.10.10.20"]


def test_write_targets_refuses_out_of_scope(scope: Scope, tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    with pytest.raises(ScopeViolation):
        scope.write_targets(target_file, ["10.10.10.5", "203.0.113.1"])
    assert not target_file.exists(), "no target file may be left behind on violation"


def test_write_targets_defaults_to_the_whole_scope(scope: Scope, tmp_path: Path):
    _, count = scope.write_targets(tmp_path / "all.txt")
    assert count == len(scope)


# -- reporting helpers ---------------------------------------------------


def test_fingerprint_is_stable_and_order_independent():
    first = Scope.from_lines(["10.0.0.1", "10.0.0.2"])
    second = Scope.from_lines(["10.0.0.2", "10.0.0.1"])
    assert first.fingerprint() == second.fingerprint()


def test_fingerprint_changes_when_scope_changes():
    first = Scope.from_lines(["10.0.0.1"])
    second = Scope.from_lines(["10.0.0.1", "10.0.0.2"])
    assert first.fingerprint() != second.fingerprint()


def test_notable_addresses_flags_loopback_and_public():
    scope = Scope.from_lines(["127.0.0.1", "8.8.8.8", "10.0.0.1"])
    notable = scope.notable_addresses()
    assert [str(a) for a in notable["loopback"]] == ["127.0.0.1"]
    assert [str(a) for a in notable["public"]] == ["8.8.8.8"]
    assert "10.0.0.1" not in [str(a) for group in notable.values() for a in group]


def test_summary_reports_counts_and_bounds():
    summary = Scope.from_lines(["10.0.0.1-10.0.0.3"]).summary()
    assert summary["total_hosts"] == 3
    assert summary["first"] == "10.0.0.1"
    assert summary["last"] == "10.0.0.3"
    assert summary["entries"] == 1
