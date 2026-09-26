"""Tests for the masscan / naabu output parsers."""

from __future__ import annotations

from pathlib import Path

from netrecon.parse.masscan import (
    group_by_host,
    parse_masscan_json,
    parse_masscan_list,
    parse_naabu_json,
    port_spec,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_masscan_json_parses_open_ports():
    ports = parse_masscan_json(FIXTURES / "masscan.json")
    assert [(p.ip, p.port, p.protocol) for p in ports] == [
        ("10.10.10.5", 22, "tcp"),
        ("10.10.10.5", 80, "tcp"),
        ("10.10.10.6", 3306, "tcp"),
        ("192.168.99.99", 445, "tcp"),
    ]


def test_masscan_json_skips_non_open_status():
    ports = parse_masscan_json(FIXTURES / "masscan.json")
    assert 9999 not in {p.port for p in ports}


def test_masscan_json_deduplicates_repeated_records():
    ports = parse_masscan_json(FIXTURES / "masscan.json")
    assert sum(1 for p in ports if p.ip == "10.10.10.6" and p.port == 3306) == 1


def test_masscan_json_keeps_reason_and_ttl():
    ssh = next(p for p in parse_masscan_json(FIXTURES / "masscan.json") if p.port == 22)
    assert ssh.reason == "syn-ack"
    assert ssh.ttl == 64
    assert ssh.source == "masscan"


def test_truncated_masscan_json_still_yields_complete_records():
    ports = parse_masscan_json(FIXTURES / "masscan_truncated.json")
    assert [(p.ip, p.port, p.protocol) for p in ports] == [
        ("10.10.10.5", 22, "tcp"),
        ("10.10.10.6", 161, "udp"),
    ]


def test_missing_masscan_file_returns_empty(tmp_path: Path):
    assert parse_masscan_json(tmp_path / "absent.json") == []


def test_empty_masscan_file_returns_empty(tmp_path: Path):
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")
    assert parse_masscan_json(path) == []


def test_masscan_list_format():
    ports = parse_masscan_list(FIXTURES / "masscan.list")
    assert [(p.ip, p.port) for p in ports] == [
        ("10.10.10.5", 22),
        ("10.10.10.6", 8080),
        ("192.168.99.99", 445),
    ]


def test_naabu_json_handles_both_port_shapes():
    ports = parse_naabu_json(FIXTURES / "naabu.json")
    assert [(p.ip, p.port, p.protocol) for p in ports] == [
        ("10.10.10.5", 22, "tcp"),
        ("10.10.10.5", 443, "tcp"),
        ("10.10.10.6", 3306, "tcp"),
        ("192.168.99.99", 445, "tcp"),
    ]
    assert all(p.source == "naabu" for p in ports)


def test_naabu_json_skips_unparseable_lines():
    # The fixture contains a 'not-json-at-all' line; parsing must not raise.
    assert len(parse_naabu_json(FIXTURES / "naabu.json")) == 4


def test_group_by_host_sorts_hosts_and_ports():
    ports = parse_masscan_json(FIXTURES / "masscan.json")
    grouped = group_by_host(ports)
    assert list(grouped) == ["10.10.10.5", "10.10.10.6", "192.168.99.99"]
    assert [p.port for p in grouped["10.10.10.5"]] == [22, 80]


def test_port_spec_builds_an_nmap_port_list():
    ports = parse_masscan_json(FIXTURES / "masscan.json")
    assert port_spec(ports) == "22,80,445,3306"


def test_port_spec_filters_by_protocol():
    ports = parse_masscan_json(FIXTURES / "masscan_truncated.json")
    assert port_spec(ports, "udp") == "161"
    assert port_spec(ports, "tcp") == "22"


def test_parsers_do_not_apply_scope_filtering():
    # Scope filtering is the caller's job (stages do it via Scope.enforce);
    # the parser must report everything the tool said so nothing is hidden.
    ports = parse_masscan_json(FIXTURES / "masscan.json")
    assert "192.168.99.99" in {p.ip for p in ports}
