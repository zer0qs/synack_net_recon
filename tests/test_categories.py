"""Tests for service categorisation and the per-category report view."""

from __future__ import annotations

import pytest

from netrecon.report.build import HostSummary
from netrecon.report.categories import (
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    PORT_CATEGORIES,
    SERVICE_NAME_CATEGORIES,
    categorise,
    group_by_category,
    is_tls,
    is_web_service,
    web_endpoints,
)


def _host(ip: str, ports: list[dict]) -> HostSummary:
    return HostSummary(ip=ip, open_ports=ports)


def _port(number: int, service: str | None = None, **extra) -> dict:
    return {"port": number, "protocol": "tcp", "service": service, "version": None, **extra}


# -- categorise ----------------------------------------------------------


@pytest.mark.parametrize(
    ("service", "port", "expected"),
    [
        ("http", 80, "web"),
        ("https", 443, "web"),
        ("mysql", 3306, "database"),
        ("postgresql", 5432, "database"),
        ("ssh", 22, "remote_access"),
        ("ms-wbt-server", 3389, "remote_access"),
        ("microsoft-ds", 445, "file_sharing"),
        ("ldap", 389, "directory"),
        ("smtp", 25, "mail"),
        ("snmp", 161, "management"),
        ("amqp", 5672, "messaging"),
        ("domain", 53, "infrastructure"),
    ],
)
def test_known_services_land_in_the_right_category(service, port, expected):
    assert categorise(service, port) == expected


def test_service_name_beats_the_port_number():
    # A web server on 3306 is a web service, not a database.
    assert categorise("http", 3306) == "web"
    # And a database on 80 is a database.
    assert categorise("mysql", 80) == "database"


def test_port_is_used_when_the_service_name_is_missing():
    assert categorise(None, 3306) == "database"
    assert categorise("", 443) == "web"


def test_tunnelled_service_names_are_resolved():
    assert categorise("ssl/http", 8443) == "web"
    assert categorise("ssl/https", 9999) == "web"


def test_anything_containing_http_is_web():
    assert categorise("http-alt", 7777) == "web"
    assert categorise("soap-http", 7777) == "web"


def test_unknown_service_and_port_is_other():
    assert categorise("completely-made-up", 64999) == "other"
    assert categorise(None, None) == "other"


def test_service_name_matching_is_case_insensitive():
    assert categorise("HTTP", 80) == "web"
    assert categorise("  MySQL  ", 3306) == "database"


def test_every_mapped_category_is_a_known_category():
    known = set(CATEGORY_ORDER)
    assert set(SERVICE_NAME_CATEGORIES.values()) <= known
    assert set(PORT_CATEGORIES.values()) <= known
    assert set(CATEGORY_LABELS) == known


# -- web / TLS detection -------------------------------------------------


def test_is_web_service():
    assert is_web_service("http", 80) is True
    assert is_web_service(None, 8080) is True
    assert is_web_service("ssh", 22) is False
    assert is_web_service("mysql", 3306) is False


@pytest.mark.parametrize(
    ("service", "port", "tunnel", "expected"),
    [
        ("http", 443, None, True),
        ("https", 8443, None, True),
        ("http", 8080, None, False),
        ("http", 8080, "ssl", True),
        (None, 80, None, False),
        (None, 443, None, True),
    ],
)
def test_tls_detection(service, port, tunnel, expected):
    assert is_tls(service, port, tunnel) is expected


# -- grouping ------------------------------------------------------------


def test_group_by_category_buckets_ports():
    hosts = [
        _host("10.0.0.1", [_port(80, "http"), _port(3306, "mysql")]),
        _host("10.0.0.2", [_port(22, "ssh"), _port(443, "https")]),
    ]
    grouped = {c.key: c for c in group_by_category(hosts)}

    assert set(grouped) == {"web", "database", "remote_access"}
    assert len(grouped["web"].entries) == 2
    assert grouped["web"].host_count == 2
    assert [e.port for e in grouped["database"].entries] == [3306]


def test_empty_categories_are_dropped():
    grouped = group_by_category([_host("10.0.0.1", [_port(80, "http")])])
    assert [c.key for c in grouped] == ["web"]


def test_categories_come_back_in_the_declared_order():
    hosts = [_host("10.0.0.1", [_port(22, "ssh"), _port(80, "http"), _port(3306, "mysql")])]
    assert [c.key for c in group_by_category(hosts)] == ["web", "database", "remote_access"]


def test_entries_are_sorted_by_ip_then_port():
    hosts = [
        _host("10.0.0.20", [_port(443, "https")]),
        _host("10.0.0.3", [_port(8080, "http"), _port(80, "http")]),
    ]
    web = group_by_category(hosts)[0]
    assert [(e.ip, e.port) for e in web.entries] == [
        ("10.0.0.3", 80),
        ("10.0.0.3", 8080),
        ("10.0.0.20", 443),
    ]


def test_notes_follow_their_port_into_the_category():
    host = _host("10.0.0.1", [_port(3306, "mysql"), _port(80, "http")])
    host.notes = ["`3306/tcp` MySQL exposed", "unrelated host-level note"]
    grouped = {c.key: c for c in group_by_category([host])}
    assert grouped["database"].entries[0].notes == ["`3306/tcp` MySQL exposed"]
    assert grouped["web"].entries[0].notes == []


def test_host_with_no_open_ports_contributes_nothing():
    assert group_by_category([_host("10.0.0.1", [])]) == []


def test_category_to_dict_is_json_safe():
    import json

    grouped = group_by_category([_host("10.0.0.1", [_port(80, "http")])])
    payload = json.loads(json.dumps([c.to_dict() for c in grouped]))
    assert payload[0]["key"] == "web"
    assert payload[0]["port_count"] == 1


# -- web endpoints -------------------------------------------------------


def test_web_endpoints_picks_scheme_per_port():
    hosts = [_host("10.0.0.1", [_port(80, "http"), _port(443, "https"), _port(22, "ssh")])]
    endpoints = web_endpoints(hosts)
    assert endpoints == [
        {"ip": "10.0.0.1", "port": 80, "scheme": "http", "service": "http"},
        {"ip": "10.0.0.1", "port": 443, "scheme": "https", "service": "https"},
    ]


def test_web_endpoints_honours_the_tls_tunnel_flag():
    hosts = [_host("10.0.0.1", [_port(8080, "http", tunnel="ssl")])]
    assert web_endpoints(hosts)[0]["scheme"] == "https"


def test_web_endpoints_skips_udp():
    host = _host("10.0.0.1", [{"port": 80, "protocol": "udp", "service": "http"}])
    assert web_endpoints([host]) == []
