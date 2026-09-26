"""Tests for the nmap XML parser, using recorded fixture output."""

from __future__ import annotations

from pathlib import Path

import pytest

from netrecon.parse.nmap import NmapParseError, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def report():
    return parse_nmap_xml(FIXTURES / "nmap_services.xml")


def test_run_metadata(report):
    assert report.version == "7.94"
    assert report.exit_status == "success"
    assert report.elapsed == pytest.approx(41.12)
    assert "nmap -sV" in report.args


def test_all_hosts_parsed_including_down(report):
    assert report.addresses() == ["10.10.10.5", "10.10.10.6", "10.10.10.7"]
    assert [h.address for h in report.up_hosts] == ["10.10.10.5", "10.10.10.6"]


def test_down_host_has_no_ports(report):
    host = report.host("10.10.10.7")
    assert host.status == "down"
    assert host.is_up is False
    assert host.ports == []


def test_host_addresses_hostnames_and_mac(report):
    host = report.host("10.10.10.5")
    assert host.address_type == "ipv4"
    assert host.hostnames == ("web01.internal",)
    assert host.mac == "00:0c:29:1a:2b:3c"
    assert host.vendor == "VMware"


def test_mac_address_does_not_become_the_host_address(report):
    # A <address addrtype="mac"> must never be mistaken for the scan target.
    assert report.host("10.10.10.5").address == "10.10.10.5"


def test_open_ports_exclude_closed(report):
    host = report.host("10.10.10.5")
    assert [p.port for p in host.ports] == [22, 80, 443]
    assert [p.port for p in host.open_ports] == [22, 80]


def test_service_version_fields(report):
    ssh = next(p for p in report.host("10.10.10.5").ports if p.port == 22)
    assert ssh.state == "open"
    assert ssh.reason == "syn-ack"
    assert ssh.service.name == "ssh"
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "8.9p1 Ubuntu 3ubuntu0.6"
    assert ssh.service.extrainfo == "Ubuntu Linux; protocol 2.0"
    assert ssh.service.confidence == 10
    assert ssh.service.method == "probed"
    assert "cpe:/a:openbsd:openssh:8.9p1" in ssh.service.cpes


def test_service_label_combines_product_version_and_extrainfo(report):
    ssh = next(p for p in report.host("10.10.10.5").ports if p.port == 22)
    assert ssh.service.label == "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)"


def test_service_label_falls_back_to_service_name(report):
    https = next(p for p in report.host("10.10.10.5").ports if p.port == 443)
    assert https.service.label == "https"


def test_port_scripts_are_captured(report):
    host = report.host("10.10.10.5")
    ssh = next(p for p in host.ports if p.port == 22)
    http = next(p for p in host.ports if p.port == 80)
    assert ssh.scripts["banner"] == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    assert http.scripts["http-title"] == "Welcome to nginx!"


def test_host_scripts_are_captured(report):
    assert report.host("10.10.10.5").host_scripts["smb2-time"] == "date: 2024-05-20T10:13:30"


def test_os_matches_sorted_by_accuracy(report):
    matches = report.host("10.10.10.5").os_matches
    assert [m.accuracy for m in matches] == [95, 90]
    assert matches[0].name == "Linux 5.0 - 5.14"
    assert matches[0].families == ("Linux",)


def test_udp_port_state_is_preserved(report):
    host = report.host("10.10.10.6")
    snmp = next(p for p in host.ports if p.protocol == "udp")
    assert snmp.port == 161
    assert snmp.state == "open|filtered"
    assert snmp not in host.open_ports, "open|filtered must not count as open"


def test_ports_sorted_by_protocol_then_number(report):
    host = report.host("10.10.10.6")
    assert [(p.protocol, p.port) for p in host.ports] == [("tcp", 3306), ("udp", 161)]


def test_discovery_fixture_reports_up_hosts_only():
    report = parse_nmap_xml(FIXTURES / "nmap_discovery.xml")
    assert [h.address for h in report.up_hosts] == [
        "10.10.10.5",
        "10.10.10.6",
        "192.168.99.99",
    ]


def test_to_dict_round_trip_is_json_safe(report):
    import json

    payload = report.to_dict()
    assert json.loads(json.dumps(payload))["hosts"][0]["address"] == "10.10.10.5"


def test_parse_from_xml_string():
    xml = (
        '<?xml version="1.0"?><nmaprun version="7.94" args="nmap -sn 10.0.0.1">'
        '<host><status state="up" reason="echo-reply"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>'
    )
    report = parse_nmap_xml(xml)
    assert report.addresses() == ["10.0.0.1"]


def test_missing_file_raises():
    with pytest.raises(NmapParseError, match="not found"):
        parse_nmap_xml(FIXTURES / "does_not_exist.xml")


def test_malformed_xml_raises(tmp_path: Path):
    broken = tmp_path / "broken.xml"
    broken.write_text('<nmaprun><host><status state="up"', encoding="utf-8")
    with pytest.raises(NmapParseError, match="malformed"):
        parse_nmap_xml(broken)


def test_wrong_root_element_raises(tmp_path: Path):
    other = tmp_path / "other.xml"
    other.write_text("<somethingelse/>", encoding="utf-8")
    with pytest.raises(NmapParseError, match="nmaprun"):
        parse_nmap_xml(other)


def test_host_without_ip_is_skipped(tmp_path: Path):
    path = tmp_path / "no_ip.xml"
    path.write_text(
        '<nmaprun version="7.94">'
        '<host><status state="up"/><address addr="00:11:22:33:44:55" addrtype="mac"/></host>'
        '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'
        "</nmaprun>",
        encoding="utf-8",
    )
    assert parse_nmap_xml(path).addresses() == ["10.0.0.1"]


def test_empty_nmaprun_yields_no_hosts(tmp_path: Path):
    path = tmp_path / "empty.xml"
    path.write_text('<nmaprun version="7.94"/>', encoding="utf-8")
    report = parse_nmap_xml(path)
    assert report.hosts == []
    assert report.host("10.0.0.1") is None
