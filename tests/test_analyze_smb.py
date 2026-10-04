"""Tests for the SMB analyzer.

Fixtures are real ``smb*`` NSE output shapes (taken from the @output blocks in
the scripts themselves), built straight into :class:`ServiceEvidence`. Nothing
here touches the network or spawns a process - the analyzer is a pure function
over text, and these tests keep it that way.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import SEVERITIES, ServiceEvidence
from netrecon.analyze.smb import SmbAnalyzer

# -- fixtures: real NSE output shapes ------------------------------------

OS_DISCOVERY_2008 = """OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
  OS CPE: cpe:/o:microsoft:windows_2008::sp1
  Computer name: Sql2008
  NetBIOS computer name: SQL2008
  Domain name: lab.test.local
  Forest name: test.local
  FQDN: Sql2008.lab.test.local
  NetBIOS domain name: LAB
  System time: 2011-04-20T13:34:06-05:00"""

OS_DISCOVERY_2019 = """OS: Windows Server 2019 Datacenter 17763 (Windows Server 2019 Datacenter 6.3)
  Computer name: dc01
  NetBIOS computer name: DC01
  Domain name: corp.example
  Forest name: corp.example
  FQDN: dc01.corp.example
  System time: 2024-05-20T10:13:20+00:00"""

OS_DISCOVERY_SAMBA = """OS: Windows 6.1 (Samba 4.5.16-Debian)
  Computer name: fileserver
  NetBIOS computer name: FILESERVER
  Workgroup: WORKGROUP
  System time: 2024-05-20T11:13:20+01:00"""

SECURITY_MODE_DISABLED = """account_used: <blank>
  authentication_level: user
  challenge_response: supported
  message_signing: disabled (dangerous, but default)"""

SECURITY_MODE_SUPPORTED = """account_used: <blank>
  authentication_level: user
  challenge_response: supported
  message_signing: supported"""

SECURITY_MODE_REQUIRED = """account_used: <blank>
  authentication_level: user
  challenge_response: supported
  message_signing: required"""

SECURITY_MODE_GUEST = """account_used: guest
  authentication_level: user
  challenge_response: supported
  message_signing: required"""

SMB2_SIGNING_NOT_REQUIRED = """3.1.1:
    Message signing enabled but not required"""

SMB2_SIGNING_REQUIRED = """3.1.1:
    Message signing enabled and required"""

SMB2_SIGNING_DISABLED = """2.0.2:
    Message signing is disabled and not required!"""

PROTOCOLS_WITH_SMBV1 = """dialects:
    NT LM 0.12 (SMBv1) [dangerous, but default]
    2.0.2
    2.1
    3.0
    3.0.2
    3.1.1"""

PROTOCOLS_MODERN = """dialects:
    2.0.2
    2.1
    3.0
    3.0.2
    3.1.1"""

CAPABILITIES = """2.0.2:
    Distributed File System
  2.1:
    Distributed File System
    Leasing
    Multi-credit operations"""

ENUM_SHARES_ANONYMOUS = r"""account_used: <blank>
  ADMIN$
    Type: STYPE_DISKTREE_HIDDEN
    Comment: Remote Admin
    Users: 0
    Max Users: <unlimited>
    Path: C:\WINNT
    Anonymous access: <none>
    Current user access: READ/WRITE
  backups
    Type: STYPE_DISKTREE
    Comment: nightly dumps
    Users: 0
    Max Users: <unlimited>
    Path: D:\backups
    Anonymous access: READ
    Current user access: READ
  dropbox
    Type: STYPE_DISKTREE
    Comment:
    Path: D:\dropbox
    Anonymous access: READ/WRITE
    Current user access: READ/WRITE
  IPC$
    Type: STYPE_IPC_HIDDEN
    Comment: Remote IPC
    Users: 1
    Max Users: <unlimited>
    Path:
    Anonymous access: READ
    Current user access: READ"""

ENUM_SHARES_LOCKED_DOWN = r"""account_used: WORKGROUP\Administrator
  ADMIN$
    Type: STYPE_DISKTREE_HIDDEN
    Comment: Remote Admin
    Path: C:\WINNT
    Anonymous access: <none>
    Current user access: READ/WRITE
  C$
    Type: STYPE_DISKTREE_HIDDEN
    Comment: Default share
    Path: C:\
    Anonymous access: <none>
    Current user access: READ"""

ENUM_SHARES_IPC_ONLY = r"""account_used: <blank>
  IPC$
    Type: STYPE_IPC_HIDDEN
    Comment: Remote IPC
    Path:
    Anonymous access: READ
    Current user access: READ"""

#: Output shapes that must never raise: empty, failed, truncated, mangled.
BROKEN_OUTPUTS = (
    "",
    "   ",
    "ERROR: Script execution failed (use -d to debug)",
    "OS:",
    "Couldn't enumerate shares: NT_STATUS_ACCESS_DENIED",
    "No dialects accepted. Something may be blocking the responses",
    "OS: Windows Server 2019 Datacenter 17763\n  Computer name:",   # truncated mid-record
    "::::\n|_\n|\n",
    "message_signing:",
    "\x00\x01 binary noise \xff",
)

ALL_SCRIPTS = (
    "smb-os-discovery",
    "smb-security-mode",
    "smb2-security-mode",
    "smb-protocols",
    "smb2-capabilities",
    "smb-enum-shares",
)


def analyser() -> SmbAnalyzer:
    return SmbAnalyzer()


def evidence(
    *,
    port: int = 445,
    service: str | None = "microsoft-ds",
    host_scripts: dict[str, str] | None = None,
    scripts: dict[str, str] | None = None,
) -> ServiceEvidence:
    """Most smb* scripts are host-level, so they default to ``host_scripts``."""
    return ServiceEvidence(
        ip="10.10.10.5",
        port=port,
        service=service,
        host_scripts=dict(host_scripts or {}),
        scripts=dict(scripts or {}),
    )


def keys(findings) -> set[str]:
    return {finding.key for finding in findings}


def find(findings, key: str):
    matches = [finding for finding in findings if finding.key == key]
    assert len(matches) == 1, f"expected exactly one {key}, got {len(matches)}"
    return matches[0]


# -- applies_to ----------------------------------------------------------


@pytest.mark.parametrize("service", ["microsoft-ds", "netbios-ssn", "smb", "MICROSOFT-DS"])
def test_applies_to_smb_service_names(service):
    assert analyser().applies_to(evidence(port=4445, service=service))


@pytest.mark.parametrize("port", [139, 445])
def test_applies_to_smb_ports_without_a_service_name(port):
    assert analyser().applies_to(evidence(port=port, service=None))


def test_applies_to_any_port_with_a_host_level_smb_script():
    # smb-os-discovery is a host script: it must be found even on an odd port.
    assert analyser().applies_to(
        evidence(port=10445, service=None, host_scripts={"smb-os-discovery": OS_DISCOVERY_2019})
    )


def test_applies_to_port_level_smb2_script():
    assert analyser().applies_to(
        evidence(port=10445, service=None, scripts={"smb2-security-mode": SMB2_SIGNING_REQUIRED})
    )


@pytest.mark.parametrize(
    ("port", "service"),
    [(80, "http"), (22, "ssh"), (3306, "mysql"), (161, "snmp")],
)
def test_does_not_apply_to_unrelated_services(port, service):
    assert not analyser().applies_to(evidence(port=port, service=service))


# -- smb.host-information ------------------------------------------------


def test_host_information_is_always_emitted_when_os_discovery_ran():
    findings = analyser().analyse(
        evidence(host_scripts={"smb-os-discovery": OS_DISCOVERY_2019})
    )
    finding = find(findings, "smb.host-information")
    assert finding.severity == "info"
    assert finding.source == "smb-os-discovery"
    assert finding.data["computer_name"] == "dc01"
    assert finding.data["domain"] == "corp.example"
    assert finding.data["forest"] == "corp.example"
    assert finding.data["fqdn"] == "dc01.corp.example"
    assert finding.data["system_time"] == "2024-05-20T10:13:20+00:00"
    assert finding.data["os"].startswith("Windows Server 2019 Datacenter")
    # The raw text is quoted so a reader can verify without rescanning.
    assert "Domain name: corp.example" in finding.evidence


def test_host_information_includes_netbios_names_and_cpe():
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-os-discovery": OS_DISCOVERY_2008})),
        "smb.host-information",
    )
    assert finding.data["netbios_computer_name"] == "SQL2008"
    assert finding.data["netbios_domain"] == "LAB"
    assert finding.data["os_cpe"] == "cpe:/o:microsoft:windows_2008::sp1"


def test_host_information_records_a_workgroup_instead_of_a_domain():
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-os-discovery": OS_DISCOVERY_SAMBA})),
        "smb.host-information",
    )
    assert finding.data["workgroup"] == "WORKGROUP"
    assert "domain" not in finding.data


def test_host_information_carries_the_dialects_when_they_are_known():
    finding = find(
        analyser().analyse(
            evidence(
                host_scripts={
                    "smb-os-discovery": OS_DISCOVERY_2019,
                    "smb-protocols": PROTOCOLS_MODERN,
                }
            )
        ),
        "smb.host-information",
    )
    assert finding.data["dialects"] == ["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"]


def test_no_host_information_without_smb_os_discovery():
    findings = analyser().analyse(
        evidence(host_scripts={"smb-security-mode": SECURITY_MODE_REQUIRED})
    )
    assert "smb.host-information" not in keys(findings)


# -- smb.signing-not-required --------------------------------------------


@pytest.mark.parametrize(
    "output", [SECURITY_MODE_DISABLED, SECURITY_MODE_SUPPORTED], ids=["disabled", "supported"]
)
def test_signing_fires_for_smb_security_mode_shapes(output):
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-security-mode": output})),
        "smb.signing-not-required",
    )
    assert finding.severity == "medium"
    assert finding.source == "smb-security-mode"
    assert "message_signing" in finding.evidence


@pytest.mark.parametrize(
    "output",
    [SMB2_SIGNING_NOT_REQUIRED, SMB2_SIGNING_DISABLED],
    ids=["enabled-not-required", "disabled"],
)
def test_signing_fires_for_smb2_security_mode_shapes(output):
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb2-security-mode": output})),
        "smb.signing-not-required",
    )
    assert finding.source == "smb2-security-mode"
    assert "Message signing" in finding.evidence
    assert finding.data["dialects"]


def test_signing_does_not_fire_when_signing_is_required():
    findings = analyser().analyse(
        evidence(
            host_scripts={
                "smb-security-mode": SECURITY_MODE_REQUIRED,
                "smb2-security-mode": SMB2_SIGNING_REQUIRED,
            }
        )
    )
    assert "smb.signing-not-required" not in keys(findings)


def test_signing_does_not_fire_without_security_mode_output():
    findings = analyser().analyse(
        evidence(host_scripts={"smb-os-discovery": OS_DISCOVERY_2019})
    )
    assert "smb.signing-not-required" not in keys(findings)


def test_signing_is_reported_once_across_both_scripts():
    findings = analyser().analyse(
        evidence(
            host_scripts={
                "smb-security-mode": SECURITY_MODE_DISABLED,
                "smb2-security-mode": SMB2_SIGNING_NOT_REQUIRED,
            }
        )
    )
    finding = find(findings, "smb.signing-not-required")
    assert finding.data["sources"] == ["smb-security-mode", "smb2-security-mode"]
    assert len(finding.data["observations"]) == 2


def test_signing_records_a_dialect_that_does_enforce():
    finding = find(
        analyser().analyse(
            evidence(
                host_scripts={
                    "smb2-security-mode": (
                        "2.0.2:\n    Message signing is disabled!\n"
                        "  3.1.1:\n    Message signing enabled and required"
                    )
                }
            )
        ),
        "smb.signing-not-required",
    )
    assert finding.data["dialects"] == ["2.0.2"]
    assert finding.data["signing_enforced_on"] == ["3.1.1: Message signing enabled and required"]


# -- smb.smbv1-enabled ---------------------------------------------------


def test_smbv1_fires_when_nt_lm_012_is_offered():
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-protocols": PROTOCOLS_WITH_SMBV1})),
        "smb.smbv1-enabled",
    )
    assert finding.severity == "medium"
    assert "NT LM 0.12" in finding.evidence
    assert finding.data["dialects"][0].startswith("NT LM 0.12")


def test_smbv1_does_not_fire_for_a_modern_dialect_list():
    findings = analyser().analyse(evidence(host_scripts={"smb-protocols": PROTOCOLS_MODERN}))
    assert "smb.smbv1-enabled" not in keys(findings)


def test_smbv1_does_not_fire_from_smb2_capabilities_alone():
    findings = analyser().analyse(evidence(host_scripts={"smb2-capabilities": CAPABILITIES}))
    assert "smb.smbv1-enabled" not in keys(findings)


def test_smbv1_does_not_fire_when_no_dialect_script_ran():
    findings = analyser().analyse(
        evidence(host_scripts={"smb-security-mode": SECURITY_MODE_REQUIRED})
    )
    assert "smb.smbv1-enabled" not in keys(findings)


# -- smb.anonymous-shares ------------------------------------------------


def test_anonymous_shares_fires_for_shares_a_null_session_can_read():
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-enum-shares": ENUM_SHARES_ANONYMOUS})),
        "smb.anonymous-shares",
    )
    assert finding.severity == "high"
    assert set(finding.data["anonymous_shares"]) == {"backups", "dropbox"}
    assert finding.data["anonymous_writable"] == ["dropbox"]
    # Shares that were not anonymous are still recorded for context.
    assert finding.data["all_shares"]["ADMIN$"] == "<none>"
    assert "Anonymous access: READ/WRITE" in finding.evidence


def test_anonymous_shares_does_not_fire_when_every_share_is_restricted():
    findings = analyser().analyse(
        evidence(host_scripts={"smb-enum-shares": ENUM_SHARES_LOCKED_DOWN})
    )
    assert "smb.anonymous-shares" not in keys(findings)


def test_anonymous_shares_ignores_ipc_only_access():
    # Anonymous READ on IPC$ is the Windows default and not a share exposure.
    findings = analyser().analyse(
        evidence(host_scripts={"smb-enum-shares": ENUM_SHARES_IPC_ONLY})
    )
    assert "smb.anonymous-shares" not in keys(findings)


def test_anonymous_shares_is_silent_when_the_intrusive_script_was_not_run():
    # netrecon does not run smb-enum-shares by default; absence is the norm.
    findings = analyser().analyse(
        evidence(
            host_scripts={
                "smb-os-discovery": OS_DISCOVERY_2019,
                "smb-security-mode": SECURITY_MODE_REQUIRED,
            }
        )
    )
    assert "smb.anonymous-shares" not in keys(findings)


def test_anonymous_shares_handles_unc_style_share_names():
    output = (
        "account_used: <blank>\n"
        r"  \\10.10.10.5\reports" "\n"
        "    Type: STYPE_DISKTREE\n"
        "    Anonymous access: READ\n"
    )
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-enum-shares": output})),
        "smb.anonymous-shares",
    )
    assert list(finding.data["anonymous_shares"]) == [r"\\10.10.10.5\reports"]


# -- smb.guest-account ---------------------------------------------------


def test_guest_account_fires_when_the_session_used_guest():
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-security-mode": SECURITY_MODE_GUEST})),
        "smb.guest-account",
    )
    assert finding.severity == "medium"
    assert finding.evidence == "account_used: guest"


def test_guest_account_fires_for_a_domain_qualified_guest():
    finding = find(
        analyser().analyse(
            evidence(host_scripts={"smb-enum-shares": "account_used: WORKGROUP\\guest"})
        ),
        "smb.guest-account",
    )
    assert finding.data["account_used"] == "WORKGROUP\\guest"


@pytest.mark.parametrize(
    "account", ["<blank>", "WORKGROUP\\Administrator", "CORP\\svc_scan", "<unknown>"]
)
def test_guest_account_does_not_fire_for_other_accounts(account):
    findings = analyser().analyse(
        evidence(host_scripts={"smb-security-mode": f"account_used: {account}\n  message_signing: required"})
    )
    assert "smb.guest-account" not in keys(findings)


# -- smb.outdated-windows ------------------------------------------------


@pytest.mark.parametrize(
    ("os_string", "release"),
    [
        ("Windows XP Professional 2600 Service Pack 3", "Windows XP"),
        ("Windows 2000 Server 2195", "Windows 2000"),
        ("Windows Server 2003 3790 Service Pack 2", "Windows Server 2003"),
        ("Windows Vista (TM) Ultimate 6000", "Windows Vista"),
        ("Windows 7 Professional 7601 Service Pack 1", "Windows 7"),
        ("Windows Server (R) 2008 Standard 6001 Service Pack 1", "Windows Server 2008 / 2008 R2"),
        ("Windows 8.1 Pro 9600", "Windows 8.1"),
        ("Windows Server 2012 R2 Standard 9600", "Windows Server 2012 / 2012 R2"),
    ],
)
def test_outdated_windows_fires_for_releases_past_end_of_support(os_string, release):
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-os-discovery": f"OS: {os_string}"})),
        "smb.outdated-windows",
    )
    assert finding.severity == "low"
    assert finding.data["release"] == release
    assert "no longer receiving security updates" in finding.summary
    assert "lifecycle" in finding.summary
    assert finding.evidence == f"OS: {os_string}"


@pytest.mark.parametrize(
    "os_string",
    [
        "Windows Server 2019 Datacenter 17763 (Windows Server 2019 Datacenter 6.3)",
        "Windows 10 Pro 19041 (Windows 10 Pro 6.3)",
        "Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)",
        "Windows 11 Pro 22621",
        "Windows Server 2022 Datacenter 20348",
        "Windows Embedded Standard 7601 Service Pack 1",
        "Unix (Samba 4.3.11-Ubuntu)",
        "Windows 6.1 (Samba 4.5.16-Debian)",
    ],
)
def test_outdated_windows_does_not_fire_for_supported_or_unclear_strings(os_string):
    findings = analyser().analyse(evidence(host_scripts={"smb-os-discovery": f"OS: {os_string}"}))
    assert "smb.outdated-windows" not in keys(findings)


def test_outdated_windows_never_mentions_a_cve():
    finding = find(
        analyser().analyse(evidence(host_scripts={"smb-os-discovery": OS_DISCOVERY_2008})),
        "smb.outdated-windows",
    )
    blob = " ".join(
        str(part) for part in (finding.summary, finding.recommendation, finding.title)
    )
    assert "CVE" not in blob.upper()


# -- robustness ----------------------------------------------------------


@pytest.mark.parametrize("broken", BROKEN_OUTPUTS)
def test_broken_output_in_every_script_does_not_raise(broken):
    findings = analyser().analyse(
        evidence(host_scripts=dict.fromkeys(ALL_SCRIPTS, broken))
    )
    # Whatever survives parsing must still be a well-formed finding.
    for finding in findings:
        assert finding.severity in SEVERITIES
        assert finding.summary


@pytest.mark.parametrize("broken", BROKEN_OUTPUTS)
def test_broken_output_never_invents_a_weakness(broken):
    findings = analyser().analyse(
        evidence(host_scripts=dict.fromkeys(ALL_SCRIPTS, broken))
    )
    assert not keys(findings) & {
        "smb.signing-not-required",
        "smb.smbv1-enabled",
        "smb.anonymous-shares",
        "smb.guest-account",
    }


def test_an_open_port_with_no_scripts_yields_nothing():
    assert analyser().analyse(evidence(port=445, service="microsoft-ds")) == []


def test_nmap_stdout_with_the_pipe_gutter_is_parsed_too():
    # Operators paste console output into a run directory; accept both shapes.
    gutter = "\n".join(
        ["| smb-security-mode: ", "|   account_used: guest", "|_  message_signing: supported"]
    )
    findings = analyser().analyse(evidence(host_scripts={"smb-security-mode": gutter}))
    assert {"smb.signing-not-required", "smb.guest-account"} <= keys(findings)


def test_every_finding_quotes_evidence_and_names_its_source():
    findings = analyser().analyse(
        evidence(
            host_scripts={
                "smb-os-discovery": OS_DISCOVERY_2008,
                "smb-security-mode": SECURITY_MODE_GUEST,
                "smb2-security-mode": SMB2_SIGNING_NOT_REQUIRED,
                "smb-protocols": PROTOCOLS_WITH_SMBV1,
                "smb-enum-shares": ENUM_SHARES_ANONYMOUS,
            }
        )
    )
    assert keys(findings) == {
        "smb.host-information",
        "smb.outdated-windows",
        "smb.signing-not-required",
        "smb.smbv1-enabled",
        "smb.anonymous-shares",
        "smb.guest-account",
    }
    for finding in findings:
        assert finding.evidence and finding.evidence.strip()
        assert finding.source
        assert finding.recommendation
        assert finding.severity in SEVERITIES


def test_the_analyzer_declares_itself_correctly():
    analyzer = analyser()
    assert analyzer.name == "smb"
    assert analyzer.needs_probe is False
