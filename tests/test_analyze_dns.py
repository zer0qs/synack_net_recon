"""Tests for the DNS analyzer. Fixtures are real dns-* NSE output shapes.

Nothing here opens a socket or runs a subprocess: the analyzer is a pure
function over a ServiceEvidence record, and these tests build those by hand.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import ServiceEvidence
from netrecon.analyze.dns import DnsAnalyzer

RECURSION_ENABLED = "Recursion appears to be enabled"

NSID_FULL = """
NSID dns.example.com (646E732E6578616D706C652E636F6D)
id.server: dns.example.com
bind.version: 9.7.3-P3
""".strip()

NSID_NO_VERSION = """
NSID ns1.example.com (6E73312E6578616D706C652E636F6D)
id.server: ns1.example.com
""".strip()

CACHE_SNOOP_HIT = """
10 of 100 tested domains are cached.
www.google.com
facebook.com
www.youtube.com
twitter.com
www.linkedin.com
""".strip()

CACHE_SNOOP_CLEAN = "0 of 100 tested domains are cached."

CACHE_SNOOP_ERROR = 'Error: "sideways" is not a known mode. Use "nonrecursive" or "timed".'

SRV_ENUM = """
Active Directory Global Catalog
  service   prio  weight  host
  3268/tcp  0     100     stodc01.example.com
Kerberos KDC Service
  service  prio  weight  host
  88/tcp   0     100     stodc01.example.com
  88/udp   0     100     stodc01.example.com
LDAP
  service  prio  weight  host
  389/tcp  0     100     stodc01.example.com
""".strip()

SERVICE_DISCOVERY = """
548/tcp afpovertcp
  model=MacBook5,1
  Address=192.168.0.2 fe80:0:0:0:223:6cff:1234:5678
3689/tcp daap
  txtvers=1
  Machine Name=Example Library
  Address=192.168.0.2
""".strip()


def _dns(**overrides) -> ServiceEvidence:
    fields = {
        "ip": "10.10.10.20",
        "port": 53,
        "protocol": "udp",
        "service": "domain",
    }
    fields.update(overrides)
    return ServiceEvidence(**fields)


def _keys(findings) -> set[str]:
    return {finding.key for finding in findings}


def _by_key(findings, key: str):
    matches = [finding for finding in findings if finding.key == key]
    assert len(matches) == 1, f"expected exactly one {key}, got {len(matches)}"
    return matches[0]


# -- applies_to ----------------------------------------------------------


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        (_dns(), True),
        (_dns(protocol="tcp"), True),
        (_dns(service="dns"), True),
        (_dns(service=None), True),
        (_dns(port=5353, service="zeroconf", scripts={"dns-service-discovery": SERVICE_DISCOVERY}), True),
        (_dns(port=80, protocol="tcp", service="http"), False),
        (_dns(port=443, protocol="tcp", service=None), False),
    ],
)
def test_applies_to(evidence, expected):
    assert DnsAnalyzer().applies_to(evidence) is expected


def test_applies_to_host_script_also_counts():
    evidence = _dns(port=9999, service=None, host_scripts={"dns-nsid": NSID_FULL})
    assert DnsAnalyzer().applies_to(evidence) is True


# -- open recursion (the high one) ---------------------------------------


def test_open_recursion_fires_on_the_script_sentence():
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-recursion": RECURSION_ENABLED}))
    finding = _by_key(findings, "dns.open-recursion")
    assert finding.severity == "high"
    assert finding.source == "dns-recursion"
    assert RECURSION_ENABLED in finding.evidence
    assert "recursion" in finding.recommendation.lower()


@pytest.mark.parametrize(
    "output",
    ["", "   ", "Recursion appears to be disabled", "no answer", "|_dns-recursion:"],
)
def test_open_recursion_does_not_fire_without_a_positive_result(output):
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-recursion": output}))
    assert "dns.open-recursion" not in _keys(findings)


def test_open_recursion_does_not_fire_on_a_bare_open_port():
    findings = DnsAnalyzer().analyse(_dns())
    assert findings == []


def test_bare_open_port_with_a_banner_yields_only_one_info_finding():
    findings = DnsAnalyzer().analyse(_dns(product="ISC BIND", version="9.11.3-1ubuntu1.2"))
    assert len(findings) == 1
    assert findings[0].key == "dns.server"
    assert findings[0].severity == "info"
    assert findings[0].source == "nmap -sV"
    assert "9.11.3" in findings[0].evidence
    assert "advisories" in findings[0].recommendation


# -- version disclosure --------------------------------------------------


def test_version_disclosed_from_nsid():
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-nsid": NSID_FULL}))
    finding = _by_key(findings, "dns.version-disclosed")
    assert finding.severity == "low"
    assert "9.7.3-P3" in finding.evidence
    assert finding.data["bind.version"] == "9.7.3-P3"
    assert finding.data["id.server"] == "dns.example.com"
    assert finding.data["nsid"] == "dns.example.com"


def test_nsid_without_a_version_discloses_nothing():
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-nsid": NSID_NO_VERSION}))
    assert "dns.version-disclosed" not in _keys(findings)
    assert "dns.server" not in _keys(findings)


def test_server_identity_falls_back_to_bind_version():
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-nsid": NSID_FULL}))
    finding = _by_key(findings, "dns.server")
    assert finding.severity == "info"
    assert finding.source == "dns-nsid"
    assert "9.7.3-P3" in finding.evidence


# -- cache snooping ------------------------------------------------------


def test_cache_snooping_fires_only_when_names_were_cached():
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-cache-snoop": CACHE_SNOOP_HIT}))
    finding = _by_key(findings, "dns.cache-snooping")
    assert finding.severity == "medium"
    assert finding.data["cached_count"] == 10
    assert finding.data["tested_count"] == 100
    assert "www.google.com" in finding.data["cached_domains"]
    assert "10 of 100" in finding.evidence


@pytest.mark.parametrize("output", [CACHE_SNOOP_CLEAN, CACHE_SNOOP_ERROR, "", "cached"])
def test_cache_snooping_silent_without_support(output):
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-cache-snoop": output}))
    assert "dns.cache-snooping" not in _keys(findings)


# -- service records -----------------------------------------------------


def test_srv_enum_records_are_grouped_and_recorded():
    findings = DnsAnalyzer().analyse(_dns(protocol="tcp", scripts={"dns-srv-enum": SRV_ENUM}))
    finding = _by_key(findings, "dns.service-records")
    assert finding.severity == "info"
    records = finding.data["records"]
    assert finding.data["record_count"] == 4
    assert finding.data["truncated"] is False
    assert "Kerberos KDC Service: 88/tcp   0     100     stodc01.example.com" in records
    # The column header is not mistaken for a group name or a record.
    assert not any("prio" in record for record in records)


def test_service_discovery_records_ignore_txt_attributes():
    evidence = _dns(port=5353, service="zeroconf", scripts={"dns-service-discovery": SERVICE_DISCOVERY})
    finding = _by_key(DnsAnalyzer().analyse(evidence), "dns.service-records")
    assert finding.data["record_count"] == 2
    assert all(record.startswith(("548/tcp", "3689/tcp")) for record in finding.data["records"])


def test_service_records_are_capped_in_data():
    many = "Kerberos KDC Service\n" + "\n".join(
        f"  88/tcp  0  100  dc{index:03d}.example.com" for index in range(60)
    )
    finding = _by_key(DnsAnalyzer().analyse(_dns(scripts={"dns-srv-enum": many})), "dns.service-records")
    assert len(finding.data["records"]) == 50
    assert finding.data["record_count"] == 60
    assert finding.data["truncated"] is True
    assert finding.evidence.count("\n") <= 8


def test_no_service_record_finding_when_the_script_returned_nothing_usable():
    findings = DnsAnalyzer().analyse(_dns(scripts={"dns-srv-enum": "No Answer"}))
    assert "dns.service-records" not in _keys(findings)


# -- robustness ----------------------------------------------------------


@pytest.mark.parametrize(
    "output",
    [
        "",
        "\n\n",
        "|_dns-nsid:",
        "NSID",
        "bind.version:",
        "truncated out",
        "10 of",
        "548/tcp",
        ":::::",
        "service  prio  weight  host",
    ],
)
def test_malformed_output_never_raises(output):
    scripts = {
        script_id: output
        for script_id in (
            "dns-recursion",
            "dns-nsid",
            "dns-cache-snoop",
            "dns-srv-enum",
            "dns-service-discovery",
        )
    }
    findings = DnsAnalyzer().analyse(_dns(scripts=scripts))
    assert all(finding.severity in {"critical", "high", "medium", "low", "info"} for finding in findings)
    assert "dns.open-recursion" not in _keys(findings)


def test_full_evidence_set_produces_every_finding_once():
    evidence = _dns(
        product="ISC BIND",
        version="9.11.3",
        scripts={
            "dns-recursion": RECURSION_ENABLED,
            "dns-nsid": NSID_FULL,
            "dns-cache-snoop": CACHE_SNOOP_HIT,
            "dns-srv-enum": SRV_ENUM,
        },
    )
    findings = DnsAnalyzer().analyse(evidence)
    assert _keys(findings) == {
        "dns.open-recursion",
        "dns.version-disclosed",
        "dns.cache-snooping",
        "dns.service-records",
        "dns.server",
    }
    # Every finding quotes something a reader can check without rescanning.
    assert all(finding.evidence for finding in findings)
