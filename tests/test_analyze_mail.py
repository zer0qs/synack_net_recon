"""Tests for the mail analyzer, over real smtp-/pop3-/imap-* NSE output shapes.

No sockets and no subprocesses. The findings that must stay quiet unless the
evidence is explicit are mail.open-relay (critical, and the script that proves
it is not run by default) and the two cleartext-transport findings, which need
a capability list before they may say anything.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import ServiceEvidence
from netrecon.analyze.mail import MailAnalyzer

SMTP_NO_STARTTLS = """
smtp.example.com Hello [203.0.113.9], SIZE 52428800, 8BITMIME, PIPELINING, AUTH LOGIN PLAIN, VRFY, ETRN, ENHANCEDSTATUSCODES
This server supports the following commands: HELO EHLO RCPT DATA RSET MAIL QUIT HELP AUTH VRFY ETRN BDAT
""".strip()

SMTP_WITH_STARTTLS = """
mx1.example.com at your service, SIZE 157286400, 8BITMIME, STARTTLS, AUTH LOGIN PLAIN, PIPELINING, SMTPUTF8
This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH
""".strip()

SMTP_WITH_EXPN = (
    "This server supports the following commands: HELO EHLO STARTTLS RCPT DATA "
    "RSET MAIL QUIT HELP AUTH VRFY EXPN"
)

POP3_WITH_STLS = "USER CAPA RESP-CODES UIDL PIPELINING STLS TOP SASL(PLAIN)"

POP3_NO_STLS = "USER CAPA RESP-CODES UIDL PIPELINING TOP SASL(PLAIN) SASL(LOGIN)"

IMAP_WITH_STARTTLS = "LOGINDISABLED IDLE IMAP4 LITERAL+ STARTTLS NAMESPACE IMAP4rev1"

IMAP_NO_STARTTLS = "IDLE IMAP4 LITERAL+ AUTH=PLAIN AUTH=LOGIN NAMESPACE IMAP4rev1"

NTLM_INFO = """
Target_Name: ACTIVESMTP
NetBIOS_Domain_Name: ACTIVESMTP
NetBIOS_Computer_Name: SMTP-TEST2
DNS_Domain_Name: somedomain.com
DNS_Computer_Name: smtp-test2.somedomain.com
Product_Version: 6.1.7601
""".strip()

OPEN_RELAY_POSITIVE = """
Server is an open relay (1/16 tests)
MAIL FROM:<antispam@insecure.org> -> RCPT TO:<relaytest@insecure.org>
""".strip()

OPEN_RELAY_NEGATIVE = "Server doesn't seem to be an open relay, all tests failed"

OPEN_RELAY_AUTH_NEEDED = "Server isn't an open relay, authentication needed"


def _mail(**overrides) -> ServiceEvidence:
    fields = {
        "ip": "10.10.10.5",
        "port": 25,
        "protocol": "tcp",
        "service": "smtp",
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
        (_mail(), True),
        (_mail(port=587, service="submission"), True),
        (_mail(port=993, service="imaps"), True),
        (_mail(port=110, service=None), True),
        (_mail(port=995, service=None), True),
        (_mail(port=2525, service="smtp"), True),
        (_mail(port=2525, service=None, scripts={"smtp-commands": SMTP_NO_STARTTLS}), True),
        (_mail(port=22, service="ssh"), False),
        (_mail(port=8080, service=None), False),
    ],
)
def test_applies_to(evidence, expected):
    assert MailAnalyzer().applies_to(evidence) is expected


# -- cleartext transport -------------------------------------------------


def test_no_starttls_and_cleartext_auth_on_port_25():
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-commands": SMTP_NO_STARTTLS}))
    assert _keys(findings) == {
        "mail.no-starttls",
        "mail.cleartext-auth",
        "mail.vrfy-expn-enabled",
        "mail.capabilities",
    }
    transport = _by_key(findings, "mail.no-starttls")
    assert transport.severity == "medium"
    assert "AUTH LOGIN PLAIN" in transport.evidence
    auth = _by_key(findings, "mail.cleartext-auth")
    assert auth.severity == "medium"
    assert sorted(auth.data["mechanisms"]) == ["LOGIN", "PLAIN"]


def test_starttls_suppresses_both_transport_findings():
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-commands": SMTP_WITH_STARTTLS}))
    assert "mail.no-starttls" not in _keys(findings)
    assert "mail.cleartext-auth" not in _keys(findings)
    assert _by_key(findings, "mail.capabilities").data["starttls"] is True


def test_submission_port_without_starttls_fires():
    findings = MailAnalyzer().analyse(
        _mail(port=587, service="submission", scripts={"smtp-commands": SMTP_NO_STARTTLS})
    )
    assert "mail.no-starttls" in _keys(findings)
    assert "587/tcp" in _by_key(findings, "mail.no-starttls").title


def test_pop3_stls_counts_as_starttls():
    findings = MailAnalyzer().analyse(
        _mail(port=110, service="pop3", scripts={"pop3-capabilities": POP3_WITH_STLS})
    )
    assert "mail.no-starttls" not in _keys(findings)
    assert "mail.cleartext-auth" not in _keys(findings)


def test_pop3_without_stls_reports_cleartext_sasl():
    findings = MailAnalyzer().analyse(
        _mail(port=110, service="pop3", scripts={"pop3-capabilities": POP3_NO_STLS})
    )
    assert "mail.no-starttls" in _keys(findings)
    assert sorted(_by_key(findings, "mail.cleartext-auth").data["mechanisms"]) == ["LOGIN", "PLAIN"]


def test_imap_with_starttls_is_clean():
    findings = MailAnalyzer().analyse(
        _mail(port=143, service="imap", scripts={"imap-capabilities": IMAP_WITH_STARTTLS})
    )
    assert _keys(findings) == {"mail.capabilities"}
    assert findings[0].severity == "info"


def test_imap_without_starttls_fires():
    findings = MailAnalyzer().analyse(
        _mail(port=143, service="imap", scripts={"imap-capabilities": IMAP_NO_STARTTLS})
    )
    assert "mail.no-starttls" in _keys(findings)
    assert "mail.cleartext-auth" in _keys(findings)


@pytest.mark.parametrize(
    "evidence",
    [
        _mail(port=465, service="smtps", scripts={"smtp-commands": SMTP_NO_STARTTLS}),
        _mail(port=993, service="imaps", scripts={"imap-capabilities": IMAP_NO_STARTTLS}),
        _mail(port=995, service="pop3s", scripts={"pop3-capabilities": POP3_NO_STLS}),
        _mail(port=25, service="smtp", tunnel="ssl", scripts={"smtp-commands": SMTP_NO_STARTTLS}),
    ],
)
def test_implicit_tls_ports_are_not_reported_as_cleartext(evidence):
    findings = MailAnalyzer().analyse(evidence)
    assert "mail.no-starttls" not in _keys(findings)
    assert "mail.cleartext-auth" not in _keys(findings)
    assert _by_key(findings, "mail.capabilities").data["implicit_tls"] is True


def test_no_transport_finding_without_a_capability_list():
    """A port that never gave us a capability list cannot be judged."""
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-ntlm-info": NTLM_INFO}))
    assert _keys(findings) == {"mail.ntlm-info"}


def test_bare_open_port_with_no_scripts_yields_nothing():
    assert MailAnalyzer().analyse(_mail()) == []
    assert MailAnalyzer().analyse(_mail(product="Postfix smtpd")) == []


# -- open relay (the critical one) ---------------------------------------


def test_open_relay_fires_on_a_positive_result():
    finding = _by_key(
        MailAnalyzer().analyse(_mail(scripts={"smtp-open-relay": OPEN_RELAY_POSITIVE})),
        "mail.open-relay",
    )
    assert finding.severity == "critical"
    assert "1/16 tests" in finding.evidence
    assert "verify the result by hand" in finding.recommendation


@pytest.mark.parametrize(
    "output",
    [OPEN_RELAY_NEGATIVE, OPEN_RELAY_AUTH_NEEDED, "", "   ", "open relay"],
)
def test_open_relay_stays_quiet_without_a_positive_result(output):
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-open-relay": output}))
    assert "mail.open-relay" not in _keys(findings)


def test_open_relay_absent_by_default_because_the_script_is_not_run():
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-commands": SMTP_WITH_STARTTLS}))
    assert "mail.open-relay" not in _keys(findings)


# -- user enumeration ----------------------------------------------------


def test_vrfy_and_expn_are_both_named():
    finding = _by_key(
        MailAnalyzer().analyse(_mail(scripts={"smtp-commands": SMTP_WITH_EXPN})),
        "mail.vrfy-expn-enabled",
    )
    assert finding.severity == "low"
    assert finding.data["verbs"] == ["VRFY", "EXPN"]
    assert "VRFY/EXPN" in finding.title


def test_no_vrfy_finding_when_the_verbs_are_absent():
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-commands": SMTP_WITH_STARTTLS}))
    assert "mail.vrfy-expn-enabled" not in _keys(findings)


# -- NTLM ----------------------------------------------------------------


def test_ntlm_info_is_recorded_for_pivoting():
    finding = _by_key(
        MailAnalyzer().analyse(_mail(scripts={"smtp-ntlm-info": NTLM_INFO})),
        "mail.ntlm-info",
    )
    assert finding.severity == "info"
    assert finding.data["dns_domain_name"] == "somedomain.com"
    assert finding.data["netbios_computer_name"] == "SMTP-TEST2"
    assert "DNS_Domain_Name: somedomain.com" in finding.evidence


def test_no_ntlm_finding_without_fields():
    findings = MailAnalyzer().analyse(_mail(scripts={"smtp-ntlm-info": "NTLM not supported"}))
    assert "mail.ntlm-info" not in _keys(findings)


# -- capabilities --------------------------------------------------------


def test_capabilities_always_recorded_with_the_raw_list():
    finding = _by_key(
        MailAnalyzer().analyse(_mail(scripts={"smtp-commands": SMTP_WITH_STARTTLS})),
        "mail.capabilities",
    )
    assert finding.severity == "info"
    assert finding.evidence.startswith("mx1.example.com at your service")
    assert "STARTTLS" in finding.data["capabilities"]


# -- robustness ----------------------------------------------------------


_ALL_SCRIPTS = (
    "smtp-commands",
    "smtp-ntlm-info",
    "smtp-open-relay",
    "pop3-capabilities",
    "imap-capabilities",
)


@pytest.mark.parametrize("output", ["", "\n\n", ":", "AUTH", "STARTTLS", "x", "Hello ["])
def test_malformed_output_never_raises(output):
    findings = MailAnalyzer().analyse(_mail(scripts=dict.fromkeys(_ALL_SCRIPTS, output)))
    assert all(finding.key.startswith("mail.") and finding.evidence for finding in findings)
    assert "mail.open-relay" not in _keys(findings)


@pytest.mark.parametrize("output", ["", "   ", "\n\n"])
def test_contentless_output_produces_nothing_at_all(output):
    assert MailAnalyzer().analyse(_mail(scripts=dict.fromkeys(_ALL_SCRIPTS, output))) == []
