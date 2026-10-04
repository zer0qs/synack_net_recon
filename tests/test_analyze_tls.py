"""Tests for the TLS analyzer.

Every fixture here is a string: real ``ssl-cert`` / ``ssl-date`` NSE output, fed
straight into :class:`ServiceEvidence`. Nothing in this file opens a socket or
runs a subprocess, which is also the property the analyzer itself has to keep.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netrecon.analyze.base import SEVERITIES, ServiceEvidence
from netrecon.analyze.tls import (
    TlsAnalyzer,
    TlsProbe,
    evaluate_certificate,
    facts_from_probe,
    parse_certificate,
    parse_clock_skew,
)
from netrecon.core.scope import ScopeViolation

NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S")


def _cert_output(
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    subject: str = "commonName=portal.example.com/organizationName=Acme/countryName=US",
    issuer: str = "commonName=Acme Issuing CA/organizationName=Acme",
    san: str | None = "DNS:portal.example.com, DNS:www.example.com",
    key_type: str | None = "rsa",
    key_bits: int | None = 2048,
    signature: str | None = "sha256WithRSAEncryption",
) -> str:
    """Build ssl-cert output in the shape and order nmap emits it."""
    not_before = not_before or NOW - timedelta(days=100)
    not_after = not_after or NOW + timedelta(days=200)
    lines = [f"Subject: {subject}"]
    if san:
        lines.append(f"Subject Alternative Name: {san}")
    lines.append(f"Issuer: {issuer}")
    if key_type:
        lines.append(f"Public Key type: {key_type}")
    if key_bits:
        lines.append(f"Public Key bits: {key_bits}")
    if signature:
        lines.append(f"Signature Algorithm: {signature}")
    lines.append(f"Not valid before: {_stamp(not_before)}")
    lines.append(f"Not valid after:  {_stamp(not_after)}")
    lines.append("MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b")
    lines.append("SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68")
    return "\n".join(lines)


def _evidence(**overrides) -> ServiceEvidence:
    fields: dict = {
        "ip": "10.10.10.5",
        "port": 443,
        "service": "https",
        "tunnel": "ssl",
        "hostnames": ("portal.example.com",),
    }
    fields.update(overrides)
    return ServiceEvidence(**fields)


def _keys(findings) -> set[str]:
    return {finding.key for finding in findings}


def _findings(cert_output: str, **overrides):
    evidence = _evidence(**overrides)
    return evaluate_certificate(evidence, parse_certificate(cert_output), now=NOW)


def _by_key(findings, key):
    matches = [finding for finding in findings if finding.key == key]
    assert matches, f"expected a {key} finding"
    return matches[0]


# -- applies_to ----------------------------------------------------------


@pytest.mark.parametrize(
    "evidence",
    [
        ServiceEvidence(ip="10.0.0.1", port=8080, tunnel="ssl"),
        ServiceEvidence(ip="10.0.0.1", port=8080, service="ssl/http"),
        ServiceEvidence(ip="10.0.0.1", port=993, service="imaps"),
        ServiceEvidence(ip="10.0.0.1", port=636, service="ldaps"),
        ServiceEvidence(ip="10.0.0.1", port=465, service="smtps"),
        ServiceEvidence(ip="10.0.0.1", port=443),
        ServiceEvidence(ip="10.0.0.1", port=8443),
        ServiceEvidence(ip="10.0.0.1", port=9999, scripts={"ssl-cert": "Subject: commonName=x"}),
        ServiceEvidence(ip="10.0.0.1", port=9999, scripts={"ssl-date": "..."}),
    ],
)
def test_applies_to_tls_looking_ports(evidence):
    assert TlsAnalyzer().applies_to(evidence) is True


@pytest.mark.parametrize(
    "evidence",
    [
        ServiceEvidence(ip="10.0.0.1", port=80, service="http"),
        ServiceEvidence(ip="10.0.0.1", port=22, service="ssh"),
        ServiceEvidence(ip="10.0.0.1", port=3306, service="mysql"),
        ServiceEvidence(ip="10.0.0.1", port=9999, scripts={"ssh-hostkey": "2048 aa (RSA)"}),
    ],
)
def test_does_not_apply_to_plaintext_ports(evidence):
    assert TlsAnalyzer().applies_to(evidence) is False


# -- parsing -------------------------------------------------------------


def test_parses_a_full_ssl_cert_record():
    facts = parse_certificate(_cert_output())
    assert facts.subject_cn == "portal.example.com"
    assert facts.subject["organizationName"] == "Acme"
    assert facts.issuer_cn == "Acme Issuing CA"
    assert facts.sans == ("DNS:portal.example.com", "DNS:www.example.com")
    assert facts.key_type == "rsa"
    assert facts.key_bits == 2048
    assert facts.signature_algorithm == "sha256WithRSAEncryption"
    assert facts.not_before == NOW - timedelta(days=100)
    assert facts.not_after == NOW + timedelta(days=200)
    assert facts.fingerprints["sha1"].startswith("d846")


def test_parses_reordered_and_partial_output():
    text = "\n".join(
        [
            "Not valid after:  2030-01-01T00:00:00",
            "Issuer: commonName=Other CA",
            "Subject: commonName=host.example.com",
        ]
    )
    facts = parse_certificate(text)
    assert facts.subject_cn == "host.example.com"
    assert facts.issuer_cn == "Other CA"
    assert facts.not_after is not None
    assert facts.not_before is None
    assert facts.key_bits is None


def test_tolerates_the_nmap_output_gutter_and_old_date_format():
    text = "\n".join(
        [
            "| ssl-cert: Subject: commonName=www.example.com",
            "| Not valid before: 2011-03-23 00:00:00",
            "|_Not valid after:  2013-04-01 23:59:59",
        ]
    )
    facts = parse_certificate(text)
    assert facts.not_before is not None
    assert facts.not_after is not None
    assert facts.not_after.year == 2013


@pytest.mark.parametrize(
    "text",
    [
        "",
        "Subject:",
        "Subject: commonName=",
        "Not valid after:",
        "Not valid after:  not-a-date",
        "Public Key bits: many",
        "Subject Alternative Name:",
        "OpenSSL required to parse certificate.",
        "Subject: commonName=x/organizationName",  # truncated mid-field
        "Signature Algorithm",  # truncated mid-label, no colon
    ],
)
def test_malformed_output_never_raises(text):
    facts = parse_certificate(text)
    # No hostnames, so the only finding a half-parsed record could justify is the
    # info record: nothing is invented from text that did not parse.
    findings = evaluate_certificate(_evidence(hostnames=()), facts, now=NOW)
    assert _keys(findings) <= {"tls.certificate"}


def test_date_only_timestamps_are_treated_as_utc():
    facts = parse_certificate("Not valid after:  2024-01-01T00:00:00")
    assert facts.not_after is not None
    assert facts.not_after.tzinfo is not None


# -- certificate findings ------------------------------------------------


def test_clean_certificate_yields_only_the_info_finding():
    findings = _findings(_cert_output())
    assert _keys(findings) == {"tls.certificate"}
    info = _by_key(findings, "tls.certificate")
    assert info.severity == "info"
    assert "portal.example.com" in info.summary
    assert "Acme Issuing CA" in info.summary
    # The evidence quotes the tool's own lines, verbatim.
    assert "Not valid after:" in (info.evidence or "")


def test_expired_certificate_is_high():
    findings = _findings(
        _cert_output(not_before=NOW - timedelta(days=400), not_after=NOW - timedelta(days=5))
    )
    finding = _by_key(findings, "tls.expired-certificate")
    assert finding.severity == "high"
    assert "5 day(s) ago" in finding.summary
    assert "Not valid after:" in finding.evidence


def test_valid_certificate_does_not_report_expiry():
    findings = _findings(_cert_output(not_after=NOW + timedelta(days=200)))
    assert "tls.expired-certificate" not in _keys(findings)
    assert "tls.expiring-soon" not in _keys(findings)


def test_certificate_expiring_within_thirty_days_is_low():
    findings = _findings(_cert_output(not_after=NOW + timedelta(days=10)))
    finding = _by_key(findings, "tls.expiring-soon")
    assert finding.severity == "low"
    assert finding.data["days_remaining"] == 10
    assert "tls.expired-certificate" not in _keys(findings)


def test_certificate_well_inside_its_window_is_not_expiring_soon():
    findings = _findings(_cert_output(not_after=NOW + timedelta(days=31)))
    assert "tls.expiring-soon" not in _keys(findings)


def test_not_yet_valid_certificate_is_medium():
    findings = _findings(
        _cert_output(not_before=NOW + timedelta(days=3), not_after=NOW + timedelta(days=300))
    )
    finding = _by_key(findings, "tls.not-yet-valid")
    assert finding.severity == "medium"
    assert "Not valid before:" in finding.evidence


def test_self_signed_certificate_is_medium():
    same = "commonName=box.local/organizationName=Internal"
    findings = _findings(_cert_output(subject=same, issuer=same, san="DNS:box.local"), hostnames=())
    finding = _by_key(findings, "tls.self-signed")
    assert finding.severity == "medium"
    assert "Subject:" in finding.evidence and "Issuer:" in finding.evidence


def test_ca_issued_certificate_is_not_reported_as_self_signed():
    assert "tls.self-signed" not in _keys(_findings(_cert_output()))


def test_long_validity_is_low():
    findings = _findings(
        _cert_output(not_before=NOW - timedelta(days=10), not_after=NOW + timedelta(days=1000))
    )
    finding = _by_key(findings, "tls.long-validity")
    assert finding.severity == "low"
    assert finding.data["validity_days"] == 1010


def test_normal_validity_period_is_not_reported():
    findings = _findings(
        _cert_output(not_before=NOW - timedelta(days=10), not_after=NOW + timedelta(days=355))
    )
    assert "tls.long-validity" not in _keys(findings)


@pytest.mark.parametrize(
    "signature",
    ["sha1WithRSAEncryption", "md5WithRSAEncryption", "ecdsa-with-SHA1"],
)
def test_weak_signature_algorithms_are_medium(signature):
    findings = _findings(_cert_output(signature=signature))
    finding = _by_key(findings, "tls.weak-signature")
    assert finding.severity == "medium"
    assert signature in finding.evidence


@pytest.mark.parametrize(
    "signature",
    ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "ecdsa-with-SHA256"],
)
def test_modern_signature_algorithms_are_not_reported(signature):
    assert "tls.weak-signature" not in _keys(_findings(_cert_output(signature=signature)))


def test_short_rsa_key_is_medium():
    findings = _findings(_cert_output(key_type="rsa", key_bits=1024))
    finding = _by_key(findings, "tls.short-key")
    assert finding.severity == "medium"
    assert finding.data["key_bits"] == 1024


@pytest.mark.parametrize(
    ("key_type", "key_bits"),
    [("rsa", 2048), ("rsa", 4096), ("ec", 256), (None, None)],
)
def test_adequate_or_unknown_keys_are_not_reported(key_type, key_bits):
    findings = _findings(_cert_output(key_type=key_type, key_bits=key_bits))
    assert "tls.short-key" not in _keys(findings)


# -- hostname coverage ---------------------------------------------------


def test_hostname_mismatch_is_low():
    findings = _findings(
        _cert_output(subject="commonName=other.example.net", san="DNS:other.example.net"),
        hostnames=("portal.example.com",),
    )
    finding = _by_key(findings, "tls.hostname-mismatch")
    assert finding.severity == "low"
    assert "other.example.net" in finding.evidence


def test_matching_san_is_not_a_mismatch():
    findings = _findings(_cert_output(), hostnames=("www.example.com",))
    assert "tls.hostname-mismatch" not in _keys(findings)


def test_wildcard_san_covers_one_label():
    findings = _findings(
        _cert_output(subject="commonName=*.example.com", san="DNS:*.example.com"),
        hostnames=("portal.example.com",),
    )
    assert "tls.hostname-mismatch" not in _keys(findings)


def test_wildcard_does_not_cover_a_deeper_label():
    findings = _findings(
        _cert_output(subject="commonName=*.example.com", san="DNS:*.example.com"),
        hostnames=("a.b.example.com",),
    )
    assert "tls.hostname-mismatch" in _keys(findings)


def test_ip_in_san_is_not_a_mismatch():
    findings = _findings(
        _cert_output(subject="commonName=box", san="IP Address:10.10.10.5"),
        hostnames=("portal.example.com",),
    )
    assert "tls.hostname-mismatch" not in _keys(findings)


def test_unknown_hostnames_are_never_guessed_at():
    # No hostnames known: a mismatch cannot be shown, so nothing is claimed.
    findings = _findings(_cert_output(subject="commonName=unrelated.local"), hostnames=())
    assert "tls.hostname-mismatch" not in _keys(findings)


def test_certificate_without_names_is_not_checked_for_mismatch():
    findings = _findings(
        _cert_output(subject="organizationName=Acme", san=None),
        hostnames=("portal.example.com",),
    )
    assert "tls.hostname-mismatch" not in _keys(findings)


# -- ssl-date ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("2012-08-02T18:29:31Z; +4s from scanner time.", 4),
        ("2012-08-02T18:29:31Z; -2h15m from scanner time.", -8100),
        ("2012-08-02T18:29:31Z; +4s from local time.", 4),
        ("2012-08-02T18:29:31Z; +1d2h3m4s from scanner time.", 93784),
    ],
)
def test_clock_skew_parsing(text, seconds):
    parsed = parse_clock_skew(text)
    assert parsed is not None
    assert parsed[0] == seconds


@pytest.mark.parametrize("text", ["", "no skew here", "Unable to obtain data from the target"])
def test_clock_skew_parsing_of_junk_returns_nothing(text):
    assert parse_clock_skew(text) is None


def test_large_clock_skew_is_reported():
    evidence = _evidence(
        scripts={"ssl-date": "2012-08-02T18:29:31Z; +2h17m from scanner time."},
    )
    findings = TlsAnalyzer().analyse(evidence)
    finding = _by_key(findings, "tls.clock-skew")
    assert finding.severity == "low"
    assert finding.data["skew_seconds"] == 8220
    assert "from scanner time" in finding.evidence


def test_small_clock_skew_is_noise_and_is_not_reported():
    evidence = _evidence(scripts={"ssl-date": "2012-08-02T18:29:31Z; +4s from scanner time."})
    assert "tls.clock-skew" not in _keys(TlsAnalyzer().analyse(evidence))


# -- ssl-enum-ciphers (optional bonus path) ------------------------------


WEAK_CIPHER_OUTPUT = """
  SSLv3:
    ciphers:
      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
      TLS_RSA_WITH_RC4_128_MD5 (rsa 2048) - D
    warnings:
      64-bit block cipher 3DES vulnerable to SWEET32 attack
  least strength: D
"""

STRONG_CIPHER_OUTPUT = """
  TLSv1.3:
    ciphers:
      TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
    cipher preference: server
  least strength: A
"""


def test_weak_ciphers_are_reported_when_the_optional_script_ran():
    evidence = _evidence(scripts={"ssl-enum-ciphers": WEAK_CIPHER_OUTPUT})
    finding = _by_key(TlsAnalyzer().analyse(evidence), "tls.weak-cipher")
    assert finding.severity == "medium"
    assert "RC4" in finding.evidence or "3DES" in finding.evidence


def test_strong_cipher_list_is_not_reported():
    evidence = _evidence(scripts={"ssl-enum-ciphers": STRONG_CIPHER_OUTPUT})
    assert "tls.weak-cipher" not in _keys(TlsAnalyzer().analyse(evidence))


def test_absent_cipher_script_yields_nothing():
    assert TlsAnalyzer().analyse(_evidence()) == []


# -- analyse() orchestration ---------------------------------------------


class _RecordingProbe:
    """Stands in for TlsProbe; records calls so tests can prove it was skipped."""

    def __init__(self, payload=None):
        self.payload = payload
        self.calls: list[tuple[str, int]] = []

    def fetch(self, ip: str, port: int):
        self.calls.append((ip, port))
        return self.payload


def test_no_relevant_scripts_yields_no_findings_without_a_probe():
    assert TlsAnalyzer().analyse(_evidence()) == []


def test_ssl_cert_output_is_used_and_the_probe_is_left_alone():
    evidence = _evidence(scripts={"ssl-cert": _cert_output()})
    probe = _RecordingProbe(payload={"certificate": {}})
    findings = TlsAnalyzer().analyse(evidence, probe=probe)
    assert probe.calls == []
    assert _by_key(findings, "tls.certificate").source == "ssl-cert"


def test_probe_is_only_consulted_when_there_is_no_ssl_cert_output():
    probe = _RecordingProbe(
        payload={
            "certificate": {
                "subject": ((("commonName", "portal.example.com"),),),
                "issuer": ((("commonName", "Acme Issuing CA"),),),
                "notBefore": "Jan  1 00:00:00 2025 GMT",
                "notAfter": "Jan  1 00:00:00 2026 GMT",
                "subjectAltName": (("DNS", "portal.example.com"),),
            },
            "protocol": "TLSv1.2",
            "cipher": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
        }
    )
    findings = TlsAnalyzer().analyse(_evidence(), probe=probe)
    assert probe.calls == [("10.10.10.5", 443)]
    info = _by_key(findings, "tls.certificate")
    assert info.source == "netrecon tls probe"
    assert "TLSv1.2" in info.summary


def test_failed_probe_produces_nothing():
    probe = _RecordingProbe(payload=None)
    assert TlsAnalyzer().analyse(_evidence(), probe=probe) == []


def test_probe_payload_without_a_parsed_certificate_reports_only_what_was_read():
    facts = facts_from_probe(
        {
            "certificate": {},
            "protocol": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            "der_bytes": 1203,
            "der_sha256": "ab" * 32,
        }
    )
    assert facts.not_after is None
    assert facts.protocol == "TLSv1.3"
    findings = evaluate_certificate(_evidence(), facts, source="netrecon tls probe", now=NOW)
    # No dates were read, so no date findings may be derived from them.
    assert _keys(findings) == {"tls.certificate"}


# -- probe guardrail (no network: the scope check happens first) ----------


def test_probe_refuses_an_out_of_scope_address(scope):
    probe = TlsProbe(timeout=1, scope=scope)
    with pytest.raises(ScopeViolation):
        probe.fetch("198.51.100.99", 443)


# -- house rules ---------------------------------------------------------


def test_findings_never_claim_a_cve_or_exploitability():
    evidence = _evidence(
        scripts={
            "ssl-cert": _cert_output(
                subject="commonName=box.local",
                issuer="commonName=box.local",
                san="DNS:box.local",
                key_bits=1024,
                signature="sha1WithRSAEncryption",
                not_before=NOW - timedelta(days=1000),
                not_after=NOW - timedelta(days=1),
            ),
            "ssl-date": "2012-08-02T18:29:31Z; +2h17m from scanner time.",
            "ssl-enum-ciphers": WEAK_CIPHER_OUTPUT,
        }
    )
    findings = TlsAnalyzer().analyse(evidence)
    assert findings
    for finding in findings:
        text = " ".join(filter(None, (finding.summary, finding.recommendation, finding.title)))
        assert "CVE-" not in text.upper()
        assert "exploit" not in text.lower()
        assert finding.severity in SEVERITIES
