"""Tests for the SSH analyzer.

The fixtures are real ``ssh-hostkey`` / ``ssh2-enum-algos`` / ``sshv1`` output,
fed straight into :class:`ServiceEvidence`. No sockets, no subprocesses: the
analyzer is a pure function over text and these tests hold it to that.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import SEVERITIES, ServiceEvidence
from netrecon.analyze.ssh import SshAnalyzer, parse_algorithms, parse_host_keys

MODERN_HOST_KEYS = """3072 SHA256:1Lh8kgQEMMLFOTJ9mXzFBtMEr1qRAX0XLXrPTN3rcC8 (RSA)
256 SHA256:ulgPG4Qeqd3dhVbBoCTa5FQc7USQKJ2YqHTCRnlPVHo (ECDSA)
256 SHA256:3ryGS0UDLZ4MqtyLBDiQkKIyGY1b9KDLBTXu4WhSsFw (ED25519)"""

LEGACY_HOST_KEYS = """1024 60:ac:3a:6b:aa:1f:9a:5e:2b:dc:ef:11:22:33:44:55 (DSA)
1024 f0:58:ce:f4:aa:a4:59:1c:8e:dd:4d:07:44:c8:25:11 (RSA)"""

#: ssh-hostkey at higher verbosity, with the full key dumped after each line.
VERBOSE_HOST_KEYS = """2048 f0:58:ce:f4:aa:a4:59:1c:8e:dd:4d:07:44:c8:25:11 (RSA)
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwVuv2gcr0maaKQ69VVIEv2ob4OxnuI64fkeOnCXD1lUx5tTA
256 SHA256:3ryGS0UDLZ4MqtyLBDiQkKIyGY1b9KDLBTXu4WhSsFw (ED25519)
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3Fv2gcr0maaKQ69VVIEv2ob4OxnuI64fkeOnCXD1lU"""

#: The known-hosts comparison block the script prints with its argument set.
KNOWN_HOSTS_HOST_KEYS = """Key comparison with known_hosts file:
  GOOD Matches in known_hosts file:
      L7: 199.19.117.60
  WRONG Matches in known_hosts file:
      L3: 199.19.117.60
3072 SHA256:1Lh8kgQEMMLFOTJ9mXzFBtMEr1qRAX0XLXrPTN3rcC8 (RSA)"""

LEGACY_ALGOS = """
  kex_algorithms (4)
      diffie-hellman-group-exchange-sha256
      diffie-hellman-group-exchange-sha1
      diffie-hellman-group14-sha1
      diffie-hellman-group1-sha1
  server_host_key_algorithms (2)
      ssh-rsa
      ssh-dss
  encryption_algorithms (6)
      aes128-ctr
      arcfour256
      arcfour
      aes128-cbc
      3des-cbc
      blowfish-cbc
  mac_algorithms (4)
      hmac-md5
      hmac-sha1
      hmac-sha1-96
      hmac-ripemd160
  compression_algorithms (2)
      none
      zlib@openssh.com
"""

MODERN_ALGOS = """
  kex_algorithms (3)
      curve25519-sha256@libssh.org
      diffie-hellman-group-exchange-sha256
      diffie-hellman-group16-sha512
  server_host_key_algorithms (2)
      rsa-sha2-512
      ssh-ed25519
  encryption_algorithms (3)
      chacha20-poly1305@openssh.com
      aes256-gcm@openssh.com
      aes256-ctr
  mac_algorithms (2)
      hmac-sha2-256-etm@openssh.com
      hmac-sha2-512-etm@openssh.com
  compression_algorithms (1)
      none
"""

#: Nmap splits a section in two when the directions differ.
SPLIT_DIRECTION_ALGOS = """
  encryption_algorithms_client_to_server (2)
      aes256-ctr
      3des-cbc
  encryption_algorithms_server_to_client (1)
      aes256-ctr
"""


def _evidence(**overrides) -> ServiceEvidence:
    fields: dict = {"ip": "10.10.10.6", "port": 22, "service": "ssh"}
    fields.update(overrides)
    return ServiceEvidence(**fields)


def _keys(findings) -> set[str]:
    return {finding.key for finding in findings}


def _analyse(**overrides):
    return SshAnalyzer().analyse(_evidence(**overrides))


def _by_key(findings, key):
    matches = [finding for finding in findings if finding.key == key]
    assert matches, f"expected a {key} finding, got {sorted(_keys(findings))}"
    return matches


# -- applies_to ----------------------------------------------------------


@pytest.mark.parametrize(
    "evidence",
    [
        ServiceEvidence(ip="10.0.0.1", port=2222, service="ssh"),
        ServiceEvidence(ip="10.0.0.1", port=22),
        ServiceEvidence(ip="10.0.0.1", port=22, service="unknown"),
        ServiceEvidence(ip="10.0.0.1", port=8022, scripts={"ssh-hostkey": MODERN_HOST_KEYS}),
        ServiceEvidence(ip="10.0.0.1", port=8022, scripts={"ssh2-enum-algos": MODERN_ALGOS}),
        ServiceEvidence(ip="10.0.0.1", port=8022, scripts={"sshv1": "Server supports SSHv1"}),
    ],
)
def test_applies_to_ssh_ports(evidence):
    assert SshAnalyzer().applies_to(evidence) is True


@pytest.mark.parametrize(
    "evidence",
    [
        ServiceEvidence(ip="10.0.0.1", port=80, service="http"),
        ServiceEvidence(ip="10.0.0.1", port=443, service="https"),
        ServiceEvidence(ip="10.0.0.1", port=23, service="telnet"),
        ServiceEvidence(ip="10.0.0.1", port=8022, scripts={"ssl-cert": "Subject: commonName=x"}),
    ],
)
def test_does_not_apply_to_other_services(evidence):
    assert SshAnalyzer().applies_to(evidence) is False


# -- parsing -------------------------------------------------------------


def test_parses_host_key_lines():
    keys = parse_host_keys(MODERN_HOST_KEYS)
    assert [key.key_type for key in keys] == ["RSA", "ECDSA", "ED25519"]
    assert [key.bits for key in keys] == [3072, 256, 256]
    assert keys[0].fingerprint.startswith("SHA256:")


def test_full_key_dumps_and_comparison_blocks_are_skipped():
    assert [key.key_type for key in parse_host_keys(VERBOSE_HOST_KEYS)] == ["RSA", "ED25519"]
    keys = parse_host_keys(KNOWN_HOSTS_HOST_KEYS)
    assert [key.key_type for key in keys] == ["RSA"]


def test_parses_algorithm_sections():
    algorithms = parse_algorithms(LEGACY_ALGOS)
    assert "diffie-hellman-group1-sha1" in algorithms.sections["kex_algorithms"]
    assert len(algorithms.sections["encryption_algorithms"]) == 6
    assert algorithms.headers["mac_algorithms"] == "mac_algorithms (4)"


def test_direction_split_sections_are_both_read():
    algorithms = parse_algorithms(SPLIT_DIRECTION_ALGOS)
    offered = [name for _, name in algorithms.of_kind("encryption_algorithms")]
    assert "3des-cbc" in offered
    assert len(algorithms.sections) == 2


@pytest.mark.parametrize(
    "text",
    [
        "",
        "2048",
        "2048 (RSA",
        "(RSA)",
        "ssh-rsa AAAAB3NzaC1yc2E",
        "kex_algorithms (4)",
        "      diffie-hellman-group1-sha1",  # entries with no section header
        "kex_algorithms (",
        "Key comparison with known_hosts file:",
    ],
)
def test_malformed_output_never_raises(text):
    assert parse_host_keys(text) == [] or parse_host_keys(text)
    parse_algorithms(text)
    findings = _analyse(scripts={"ssh-hostkey": text, "ssh2-enum-algos": text})
    # Unparsable text justifies nothing beyond the info record.
    assert _keys(findings) <= {"ssh.host-key"}


# -- host keys -----------------------------------------------------------


def test_dsa_host_key_is_medium():
    findings = _analyse(scripts={"ssh-hostkey": LEGACY_HOST_KEYS})
    weak = _by_key(findings, "ssh.weak-host-key")
    assert {finding.severity for finding in weak} == {"medium"}
    assert any("DSA" in finding.evidence for finding in weak)


def test_short_rsa_host_key_is_medium():
    findings = _analyse(scripts={"ssh-hostkey": "1024 aa:bb:cc:dd (RSA)"})
    finding = _by_key(findings, "ssh.weak-host-key")[0]
    assert finding.severity == "medium"
    assert finding.data["bits"] == 1024
    assert finding.evidence == "1024 aa:bb:cc:dd (RSA)"


def test_modern_host_keys_are_not_reported():
    findings = _analyse(scripts={"ssh-hostkey": MODERN_HOST_KEYS})
    assert _keys(findings) == {"ssh.host-key"}


def test_short_ed25519_key_is_not_mistaken_for_a_short_rsa_key():
    # Ed25519 keys are 256 bits by definition; the RSA threshold must not apply.
    findings = _analyse(scripts={"ssh-hostkey": "256 SHA256:abc (ED25519)"})
    assert "ssh.weak-host-key" not in _keys(findings)


def test_dsa_host_key_algorithm_offer_is_reported():
    findings = _analyse(scripts={"ssh2-enum-algos": LEGACY_ALGOS})
    assert any("ssh-dss" in finding.evidence for finding in _by_key(findings, "ssh.weak-host-key"))


# -- algorithms ----------------------------------------------------------


def test_weak_kex_is_medium():
    findings = _analyse(scripts={"ssh2-enum-algos": LEGACY_ALGOS})
    finding = _by_key(findings, "ssh.weak-kex")[0]
    assert finding.severity == "medium"
    assert "diffie-hellman-group1-sha1" in finding.data["algorithms"]
    assert "diffie-hellman-group-exchange-sha1" in finding.evidence
    # group14-sha1 is not on the list, so it must not be claimed as a finding.
    assert "diffie-hellman-group14-sha1" not in finding.data["algorithms"]


def test_weak_ciphers_are_medium():
    findings = _analyse(scripts={"ssh2-enum-algos": LEGACY_ALGOS})
    finding = _by_key(findings, "ssh.weak-cipher")[0]
    assert finding.severity == "medium"
    assert {"arcfour", "3des-cbc", "aes128-cbc", "blowfish-cbc"} <= set(finding.data["algorithms"])


def test_weak_macs_are_medium():
    findings = _analyse(scripts={"ssh2-enum-algos": LEGACY_ALGOS})
    finding = _by_key(findings, "ssh.weak-mac")[0]
    assert finding.severity == "medium"
    assert "hmac-md5" in finding.data["algorithms"]
    assert "hmac-sha1-96" in finding.data["algorithms"]
    # Untruncated hmac-sha1 is not in the list this analyzer reports on.
    assert "hmac-sha1" not in finding.data["algorithms"]


def test_cbc_cipher_in_one_direction_only_is_still_reported():
    findings = _analyse(scripts={"ssh2-enum-algos": SPLIT_DIRECTION_ALGOS})
    finding = _by_key(findings, "ssh.weak-cipher")[0]
    assert finding.data["algorithms"] == ["3des-cbc"]


def test_modern_algorithm_lists_produce_no_findings():
    assert _analyse(scripts={"ssh2-enum-algos": MODERN_ALGOS}) == []


def test_absent_algorithm_script_produces_no_algorithm_findings():
    findings = _analyse(scripts={"ssh-hostkey": MODERN_HOST_KEYS})
    assert not {"ssh.weak-kex", "ssh.weak-cipher", "ssh.weak-mac"} & _keys(findings)


# -- protocol version 1 --------------------------------------------------


def test_sshv1_script_result_is_high():
    findings = _analyse(scripts={"sshv1": "Server supports SSHv1"})
    finding = _by_key(findings, "ssh.protocol-v1")[0]
    assert finding.severity == "high"
    assert finding.evidence == "Server supports SSHv1"


def test_protocol_v1_host_key_is_high():
    findings = _analyse(scripts={"ssh-hostkey": "1024 aa:bb:cc:dd (RSA1)"})
    assert _by_key(findings, "ssh.protocol-v1")[0].severity == "high"


def test_protocol_1_99_banner_is_high():
    findings = _analyse(
        product="OpenSSH", version="9.6p1", extrainfo="Ubuntu; protocol 1.99"
    )
    assert _by_key(findings, "ssh.protocol-v1")[0].severity == "high"


def test_protocol_2_only_is_not_reported():
    findings = _analyse(
        product="OpenSSH",
        version="9.6p1",
        extrainfo="Ubuntu-3ubuntu13; protocol 2.0",
        scripts={"ssh-hostkey": MODERN_HOST_KEYS, "ssh2-enum-algos": MODERN_ALGOS},
    )
    assert _keys(findings) == {"ssh.host-key"}


# -- version age ---------------------------------------------------------


def test_old_openssh_is_low_and_points_at_vendor_advisories():
    findings = _analyse(product="OpenSSH", version="6.6.1p1", extrainfo="Ubuntu; protocol 2.0")
    finding = _by_key(findings, "ssh.outdated-openssh")[0]
    assert finding.severity == "low"
    assert "older than OpenSSH 8.0" in finding.summary
    assert "advisories" in finding.summary
    assert "CVE" not in (finding.summary + (finding.recommendation or ""))


def test_current_openssh_is_not_reported():
    findings = _analyse(product="OpenSSH", version="9.6p1")
    assert "ssh.outdated-openssh" not in _keys(findings)


def test_unknown_version_is_not_reported():
    findings = _analyse(product="OpenSSH", version=None)
    assert "ssh.outdated-openssh" not in _keys(findings)


def test_other_ssh_products_are_not_called_outdated_openssh():
    findings = _analyse(product="Dropbear sshd", version="2012.55")
    assert "ssh.outdated-openssh" not in _keys(findings)


# -- info record ---------------------------------------------------------


def test_host_key_info_lists_the_keys_found():
    findings = _analyse(scripts={"ssh-hostkey": MODERN_HOST_KEYS})
    finding = _by_key(findings, "ssh.host-key")[0]
    assert finding.severity == "info"
    assert "3072-bit RSA" in finding.summary
    assert "ED25519" in finding.summary
    assert finding.evidence.count("\n") == 2
    assert len(finding.data["keys"]) == 3


def test_evidence_without_relevant_scripts_yields_nothing():
    assert _analyse() == []
    assert _analyse(product="OpenSSH", version="9.6p1") == []


# -- house rules ---------------------------------------------------------


def test_findings_never_claim_a_cve_or_exploitability():
    findings = _analyse(
        product="OpenSSH",
        version="4.3",
        extrainfo="protocol 1.99",
        scripts={
            "ssh-hostkey": LEGACY_HOST_KEYS,
            "ssh2-enum-algos": LEGACY_ALGOS,
            "sshv1": "Server supports SSHv1",
        },
    )
    assert len(findings) >= 6
    for finding in findings:
        text = " ".join(filter(None, (finding.summary, finding.recommendation, finding.title)))
        assert "CVE-" not in text.upper()
        assert "exploit" not in text.lower()
        assert finding.severity in SEVERITIES
        if finding.severity != "info":
            # Every non-info finding has to quote what the tool actually returned.
            assert finding.evidence
