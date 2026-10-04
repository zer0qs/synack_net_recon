"""Tests for the SNMP analyzer, over real snmp-* NSE output shapes.

No sockets and no subprocesses: ServiceEvidence records are built by hand. The
important negative case is an open 161/udp with no script data - UDP ports are
reported open on no reply at all, so that must never produce the high finding.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import ServiceEvidence
from netrecon.analyze.snmp import SnmpAnalyzer

SYSDESCR = """
HP ETHERNET MULTI-ENVIRONMENT,ROM A.25.80,JETDIRECT,JD117,EEPROM V.28.22,CIDATE 08/09/2006
  System uptime: 28 days, 17:18:59 (248153900 timeticks)
""".strip()

SYSDESCR_LINUX = """
Linux fw01 3.16.0-4-amd64 #1 SMP Debian 3.16.51-3 x86_64
  System uptime: 112 days, 03:11:07 (968466700 timeticks)
  sysContact: netops@example.com
  sysLocation: DC2 rack B14
""".strip()

SNMP_INFO = """
enterprise: ciscoSystems
engineIDFormat: mac
engineIDData: 00:d4:8c:00:11:22
snmpEngineBoots: 6
snmpEngineTime: 358d01h13m46s
""".strip()

INTERFACES = """
eth0
  IP address: 192.168.221.128  Netmask: 255.255.255.0
  MAC address: 00:0c:29:01:e2:74 (VMware)
  Type: ethernetCsmacd  Speed: 1 Gbps
  Traffic stats: 6.45 Mb sent, 15.01 Mb received
eth1
  IP address: 10.250.0.4  Netmask: 255.255.255.240
  MAC address: 00:0c:29:01:e2:7e (VMware)
  Type: ethernetCsmacd  Speed: 1 Gbps
""".strip()

NETSTAT = """
TCP  0.0.0.0:21           0.0.0.0:2256
TCP  0.0.0.0:445          0.0.0.0:49158
TCP  127.0.0.1:389        127.0.0.1:1045
UDP  192.168.56.3:137     *:*
""".strip()

PROCESSES = """
1:
  Name: System Idle Process
256:
  Name: smss.exe
  Path: \\SystemRoot\\System32\\
392:
  Name: lsass.exe
  Path: C:\\WINDOWS\\system32\\
""".strip()

SOFTWARE = """
Apache Tomcat 5.5 (remove only); 2007-09-15T15:13:18
Security Update for Windows Media Player (KB911564); 2007-09-15T15:13:18
Windows Internet Explorer 7; 2007-09-15T15:13:18
""".strip()


def _snmp(**overrides) -> ServiceEvidence:
    fields = {
        "ip": "10.10.10.30",
        "port": 161,
        "protocol": "udp",
        "service": "snmp",
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
        (_snmp(), True),
        (_snmp(service=None), True),
        (_snmp(port=162, service="snmptrap"), True),
        (_snmp(port=16161, service=None, scripts={"snmp-info": SNMP_INFO}), True),
        (_snmp(port=80, protocol="tcp", service="http"), False),
        (_snmp(port=53, service="domain"), False),
    ],
)
def test_applies_to(evidence, expected):
    assert SnmpAnalyzer().applies_to(evidence) is expected


# -- the high finding ----------------------------------------------------


def test_readable_fires_when_sysdescr_returned_device_data():
    findings = SnmpAnalyzer().analyse(_snmp(scripts={"snmp-sysdescr": SYSDESCR}))
    finding = _by_key(findings, "snmp.readable-with-default-community")
    assert finding.severity == "high"
    assert "JETDIRECT" in finding.evidence
    assert finding.source == "snmp-sysdescr"
    assert "public" in finding.data["community_used"]


def test_readable_fires_on_snmp_info_engine_fields():
    findings = SnmpAnalyzer().analyse(_snmp(extrainfo="public", scripts={"snmp-info": SNMP_INFO}))
    finding = _by_key(findings, "snmp.readable-with-default-community")
    assert "enterprise: ciscoSystems" in finding.evidence
    assert finding.data["community_used"] == "public"


def test_readable_does_not_fire_for_a_bare_open_port():
    findings = SnmpAnalyzer().analyse(_snmp())
    assert findings == []


def test_bare_open_port_with_a_banner_yields_only_the_version_finding():
    findings = SnmpAnalyzer().analyse(_snmp(product="SNMPv1 server", extrainfo="public"))
    assert _keys(findings) == {"snmp.v1-v2c"}


@pytest.mark.parametrize(
    "output",
    [
        "",
        "   ",
        "Error: no response from the agent",
        "timeout",
        "false",
        "Could not read sysDescr",
    ],
)
def test_readable_does_not_fire_on_an_empty_or_failed_query(output):
    findings = SnmpAnalyzer().analyse(
        _snmp(scripts={"snmp-sysdescr": output, "snmp-info": output})
    )
    assert "snmp.readable-with-default-community" not in _keys(findings)


def test_unrelated_key_values_in_snmp_info_do_not_count_as_a_reply():
    findings = SnmpAnalyzer().analyse(_snmp(scripts={"snmp-info": "note: script ran"}))
    assert "snmp.readable-with-default-community" not in _keys(findings)


# -- system information --------------------------------------------------


def test_system_information_collects_descr_uptime_contact_location():
    findings = SnmpAnalyzer().analyse(_snmp(scripts={"snmp-sysdescr": SYSDESCR_LINUX}))
    finding = _by_key(findings, "snmp.system-information")
    assert finding.severity == "info"
    assert finding.data["sysdescr"].startswith("Linux fw01")
    assert finding.data["uptime"].startswith("112 days")
    assert finding.data["contact"] == "netops@example.com"
    assert finding.data["location"] == "DC2 rack B14"


def test_no_system_information_without_any_fields():
    findings = SnmpAnalyzer().analyse(_snmp(scripts={"snmp-sysdescr": ""}))
    assert "snmp.system-information" not in _keys(findings)


# -- interfaces and the socket table -------------------------------------


def test_interfaces_disclosed():
    findings = SnmpAnalyzer().analyse(_snmp(scripts={"snmp-interfaces": INTERFACES}))
    finding = _by_key(findings, "snmp.interfaces-disclosed")
    assert finding.severity == "medium"
    assert finding.data["interface_count"] == 2
    names = [interface["name"] for interface in finding.data["interfaces"]]
    assert names == ["eth0", "eth1"]
    assert finding.data["addresses"] == ["10.250.0.4", "192.168.221.128"]
    assert finding.data["interfaces"][0]["mac"].startswith("00:0c:29:01:e2:74")
    assert "192.168.221.128" in finding.evidence


def test_netstat_alone_also_shows_reachable_addresses():
    finding = _by_key(
        SnmpAnalyzer().analyse(_snmp(scripts={"snmp-netstat": NETSTAT})),
        "snmp.interfaces-disclosed",
    )
    assert finding.data["socket_entry_count"] == 4
    assert "TCP 0.0.0.0:445 0.0.0.0:49158" in finding.data["socket_entries"]
    assert finding.data["interface_count"] == 0


def test_interface_list_is_capped_in_data():
    many = "\n".join(
        f"eth{index}\n  IP address: 10.0.{index}.1  Netmask: 255.255.255.0" for index in range(45)
    )
    finding = _by_key(
        SnmpAnalyzer().analyse(_snmp(scripts={"snmp-interfaces": many})),
        "snmp.interfaces-disclosed",
    )
    assert finding.data["interface_count"] == 45
    assert len(finding.data["interfaces"]) == 30
    assert finding.data["truncated"] is True


def test_no_interface_finding_without_interface_data():
    findings = SnmpAnalyzer().analyse(_snmp(scripts={"snmp-interfaces": "", "snmp-netstat": ""}))
    assert "snmp.interfaces-disclosed" not in _keys(findings)


# -- processes and software ----------------------------------------------


def test_processes_disclosed():
    finding = _by_key(
        SnmpAnalyzer().analyse(_snmp(scripts={"snmp-processes": PROCESSES})),
        "snmp.processes-disclosed",
    )
    assert finding.severity == "medium"
    assert finding.data["process_count"] == 3
    assert "392: lsass.exe" in finding.data["processes"]


def test_software_disclosed():
    finding = _by_key(
        SnmpAnalyzer().analyse(_snmp(scripts={"snmp-win32-software": SOFTWARE})),
        "snmp.software-disclosed",
    )
    assert finding.severity == "medium"
    assert finding.data["software_count"] == 3
    assert any("Tomcat" in entry for entry in finding.data["software"])
    assert "advisories" in finding.summary


@pytest.mark.parametrize("script", ["snmp-processes", "snmp-win32-software"])
def test_process_and_software_findings_need_content(script):
    findings = SnmpAnalyzer().analyse(_snmp(scripts={script: ""}))
    assert findings == []


# -- protocol version ----------------------------------------------------


@pytest.mark.parametrize(
    ("product", "fires"),
    [
        ("SNMPv1 server", True),
        ("SNMPv2c server", True),
        ("SNMPv3 server", False),
        ("net-snmp agent", False),
        (None, False),
    ],
)
def test_v1_v2c_only_when_the_banner_says_so(product, fires):
    findings = SnmpAnalyzer().analyse(_snmp(product=product, extrainfo="public"))
    assert ("snmp.v1-v2c" in _keys(findings)) is fires


def test_v1_v2c_quotes_the_banner():
    finding = _by_key(
        SnmpAnalyzer().analyse(_snmp(product="SNMPv1 server", extrainfo="public")),
        "snmp.v1-v2c",
    )
    assert finding.severity == "medium"
    assert "SNMPv1" in finding.evidence
    assert finding.data["community_seen"] == "public"


# -- robustness ----------------------------------------------------------


#: Every snmp script this analyzer reads, for the truncated-output sweep.
_ALL_SCRIPTS = (
    "snmp-info",
    "snmp-sysdescr",
    "snmp-interfaces",
    "snmp-netstat",
    "snmp-processes",
    "snmp-win32-software",
)


@pytest.mark.parametrize(
    "output",
    ["", "\n\n", ":", "::::", "  Name:", "TCP", "1:", "IP address: ", "eth0\n  IP addr"],
)
def test_malformed_output_never_raises(output):
    """Truncated or nonsense output must parse without blowing up."""
    scripts = dict.fromkeys(_ALL_SCRIPTS, output)
    findings = SnmpAnalyzer().analyse(_snmp(scripts=scripts))
    assert all(finding.key.startswith("snmp.") and finding.evidence for finding in findings)


@pytest.mark.parametrize("output", ["", "   ", "\n\n", ":", "::::"])
def test_contentless_output_produces_nothing_at_all(output):
    scripts = dict.fromkeys(_ALL_SCRIPTS, output)
    assert SnmpAnalyzer().analyse(_snmp(scripts=scripts)) == []


def test_full_evidence_set_produces_every_finding_once():
    evidence = _snmp(
        product="SNMPv1 server",
        extrainfo="public",
        scripts={
            "snmp-sysdescr": SYSDESCR_LINUX,
            "snmp-info": SNMP_INFO,
            "snmp-interfaces": INTERFACES,
            "snmp-netstat": NETSTAT,
            "snmp-processes": PROCESSES,
            "snmp-win32-software": SOFTWARE,
        },
    )
    findings = SnmpAnalyzer().analyse(evidence)
    assert _keys(findings) == {
        "snmp.readable-with-default-community",
        "snmp.system-information",
        "snmp.interfaces-disclosed",
        "snmp.processes-disclosed",
        "snmp.software-disclosed",
        "snmp.v1-v2c",
    }
    assert all(finding.evidence for finding in findings)
