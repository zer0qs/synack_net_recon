"""Mail service analysis: where credentials and messages cross in the clear.

Mail is the protocol family where transport security is still optional and
often left off. A submission or POP3/IMAP port that never advertises STARTTLS
takes usernames and passwords - frequently the same directory credentials used
everywhere else - as cleartext on the wire, and the greeting banner tells us so
without us ever authenticating. The capability list an MTA or MSA volunteers
also exposes user-enumeration verbs (VRFY, EXPN) and, through NTLM, the AD
domain and host names worth pivoting to.

Only the capability and NTLM lists nmap already collected are read here. In
particular ``mail.open-relay`` is reported solely when ``smtp-open-relay``
positively said so; that script is intrusive and netrecon does not run it by
default, so the usual case is that the finding simply does not exist.
"""

from __future__ import annotations

import re
from typing import Any

from netrecon.analyze.base import Finding, ServiceEvidence

#: nmap service names for mail transfer and retrieval.
MAIL_SERVICE_NAMES: frozenset[str] = frozenset(
    {"smtp", "smtps", "submission", "pop3", "pop3s", "imap", "imaps"}
)

MAIL_PORTS: frozenset[int] = frozenset({25, 110, 143, 465, 587, 993, 995})

#: Ports that start in cleartext, so STARTTLS is the only protection available.
CLEARTEXT_PORTS: frozenset[int] = frozenset({25, 110, 143, 587})

#: Ports and service names that are TLS from the first byte.
IMPLICIT_TLS_PORTS: frozenset[int] = frozenset({465, 993, 995})
IMPLICIT_TLS_SERVICES: frozenset[str] = frozenset({"smtps", "pop3s", "imaps"})

_SCRIPT_PREFIXES: tuple[str, ...] = ("smtp-", "pop3-", "imap-")

#: STARTTLS in SMTP/IMAP, STLS in POP3 - either means TLS can be negotiated.
_STARTTLS_TOKENS: frozenset[str] = frozenset({"STARTTLS", "STLS"})

#: Cleartext-equivalent SASL mechanisms: the password crosses as-is or base64.
_CLEARTEXT_MECHS: tuple[str, ...] = ("PLAIN", "LOGIN")

_OPEN_RELAY = re.compile(r"\bis\s+an\s+open\s+relay\b", re.IGNORECASE)

_NOT_OPEN_RELAY = re.compile(r"(?:doesn't|does not|isn't|is not)\s+seem|\bisn't\s+an\s+open", re.I)

_KEY_VALUE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\- ]*?)\s*:\s*(.+)$")

#: Capability tokens are separated by commas (smtp-commands) or spaces (CAPA).
_TOKEN_SPLIT = re.compile(r"[,\s]+")

_USER_ENUM_VERBS: tuple[str, ...] = ("VRFY", "EXPN")


class MailAnalyzer:
    """Findings from ``smtp-*``/``pop3-*``/``imap-*`` NSE output."""

    name = "mail"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        service = (evidence.service or "").strip().lower()
        if service in MAIL_SERVICE_NAMES:
            return True
        if _ran_mail_script(evidence):
            return True
        return evidence.port in MAIL_PORTS

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        caps = _capabilities(evidence)
        findings: list[Finding] = []
        findings.extend(_open_relay_findings(evidence))
        findings.extend(_transport_findings(evidence, caps))
        findings.extend(_user_enum_findings(evidence, caps))
        findings.extend(_ntlm_findings(evidence))
        findings.extend(_capability_findings(evidence, caps))
        return findings


class _Capabilities:
    """A capability/command list as one mail service advertised it."""

    def __init__(self, raw: str, tokens: list[str], source: str) -> None:
        self.raw = raw
        self.tokens = tokens
        self.source = source
        self.upper = raw.upper()

    @property
    def starttls(self) -> bool:
        return any(token in _STARTTLS_TOKENS for token in self.tokens)

    @property
    def cleartext_mechs(self) -> list[str]:
        """PLAIN/LOGIN offered, and only when advertised as an AUTH mechanism."""
        if "AUTH" not in self.upper and "SASL" not in self.upper:
            return []
        return [
            mech
            for mech in _CLEARTEXT_MECHS
            if re.search(rf"\b{mech}\b", self.upper)
        ]

    @property
    def user_enum_verbs(self) -> list[str]:
        return [verb for verb in _USER_ENUM_VERBS if verb in self.tokens]


# -- individual findings -------------------------------------------------


def _open_relay_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Critical, and only on a positive result from smtp-open-relay.

    The script is in nmap's intrusive category and netrecon does not run it, so
    the normal path through here returns nothing at all.
    """
    output = evidence.script("smtp-open-relay")
    if not output:
        return []
    if _NOT_OPEN_RELAY.search(output) or not _OPEN_RELAY.search(output):
        return []
    return [
        Finding(
            key="mail.open-relay",
            title="SMTP server relays mail for unauthenticated senders",
            severity="critical",
            summary=(
                "smtp-open-relay completed a MAIL FROM/RCPT TO pair for a sender and a "
                "recipient that are both external to this server, so it accepts mail it "
                "has no reason to carry. Third parties can send mail that appears to come "
                "from this organisation, and the host's reputation and address space will "
                "be used for spam and phishing."
            ),
            evidence=_first_lines(output, 4),
            recommendation=(
                "Reject recipients outside the served domains unless the session is "
                "authenticated, and verify the result by hand before reporting it - "
                "relay tests can be influenced by a mail gateway in front of the server."
            ),
            source="smtp-open-relay",
        )
    ]


def _transport_findings(evidence: ServiceEvidence, caps: _Capabilities | None) -> list[Finding]:
    """Medium: cleartext transport, and cleartext auth offered over it."""
    if caps is None or not _is_cleartext_port(evidence):
        return []
    if caps.starttls:
        return []

    findings = [
        Finding(
            key="mail.no-starttls",
            title=f"Mail service on {evidence.port}/{evidence.protocol} does not offer STARTTLS",
            severity="medium",
            summary=(
                "This port begins in cleartext and the advertised capability list contains "
                "no STARTTLS/STLS, so there is no way for a client to upgrade the session. "
                "Mail bodies and any credentials used on this port cross the network "
                "unprotected and are readable by anything on the path."
            ),
            evidence=caps.raw,
            recommendation=(
                "Enable STARTTLS with a valid certificate on this port, require it for "
                "authentication, and offer implicit-TLS alternatives (465 for submission, "
                "993/995 for retrieval)."
            ),
            source=caps.source,
            data={"capabilities": caps.tokens},
        )
    ]

    mechs = caps.cleartext_mechs
    if mechs:
        findings.append(
            Finding(
                key="mail.cleartext-auth",
                title="Password authentication offered on a cleartext mail port",
                severity="medium",
                summary=(
                    "AUTH " + "/".join(mechs) + " is advertised on a port with no TLS and no "
                    "STARTTLS, so any client that authenticates here sends the username and "
                    "password in the clear (base64 is encoding, not encryption). These are "
                    "very often directory credentials usable elsewhere."
                ),
                evidence=caps.raw,
                recommendation=(
                    "Refuse AUTH until the session is encrypted (require STARTTLS, or move "
                    "clients to an implicit-TLS port) and check mail logs for authentications "
                    "that have already happened on this port."
                ),
                source=caps.source,
                data={"mechanisms": mechs},
            )
        )
    return findings


def _user_enum_findings(evidence: ServiceEvidence, caps: _Capabilities | None) -> list[Finding]:
    """Low: VRFY/EXPN give an unauthenticated way to test usernames."""
    if caps is None:
        return []
    verbs = caps.user_enum_verbs
    if not verbs:
        return []
    return [
        Finding(
            key="mail.vrfy-expn-enabled",
            title=f"SMTP {'/'.join(verbs)} available for user enumeration",
            severity="low",
            summary=(
                f"The server lists {', '.join(verbs)} among its supported commands. Either "
                "verb lets an unauthenticated caller test whether an address exists (and "
                "EXPN expands list membership), which builds a username list for password "
                "spraying and phishing without any authentication attempt."
            ),
            evidence=caps.raw,
            recommendation=(
                "Disable VRFY and EXPN on internet-facing MTAs, and make invalid and valid "
                "recipients indistinguishable in responses where the MTA allows it."
            ),
            source=caps.source,
            data={"verbs": verbs},
        )
    ]


def _ntlm_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Info: NTLM negotiation names the domain and host, useful for pivoting."""
    output = evidence.script("smtp-ntlm-info")
    if not output:
        return []
    fields = _key_values(output)
    if not fields:
        return []
    data: dict[str, Any] = {
        key.strip().lower(): value for key, value in fields.items() if value
    }
    return [
        Finding(
            key="mail.ntlm-info",
            title="Domain and host names disclosed via SMTP NTLM",
            severity="info",
            summary=(
                "The server completed an NTLM challenge without credentials and in doing so "
                "named its AD domain, NetBIOS and DNS host names and OS build. That is "
                "pivot information: it ties this mail service to a Windows domain to target "
                "and gives internal naming that is otherwise not visible from outside."
            ),
            evidence=_quote([f"{key}: {value}" for key, value in fields.items()], 8),
            recommendation=(
                "Accept this as inherent to offering NTLM authentication; prefer modern "
                "authentication where possible and confirm the disclosed domain is one this "
                "host is meant to advertise externally."
            ),
            source="smtp-ntlm-info",
            data=data,
        )
    ]


def _capability_findings(evidence: ServiceEvidence, caps: _Capabilities | None) -> list[Finding]:
    """Info: the raw list, so every judgement above can be re-checked."""
    if caps is None:
        return []
    return [
        Finding(
            key="mail.capabilities",
            title="Mail service capabilities recorded",
            severity="info",
            summary=(
                "The capability/command list the service advertised before authentication. "
                "Recorded so the transport and enumeration findings on this port can be "
                "verified without rescanning."
            ),
            evidence=caps.raw,
            recommendation=(
                "Review the advertised commands against what this service needs to offer."
            ),
            source=caps.source,
            data={
                "capabilities": caps.tokens,
                "starttls": caps.starttls,
                "implicit_tls": _is_implicit_tls(evidence),
            },
        )
    ]


# -- parsing -------------------------------------------------------------


def _ran_mail_script(evidence: ServiceEvidence) -> bool:
    return any(
        key.lower().startswith(_SCRIPT_PREFIXES)
        for key in (*evidence.scripts, *evidence.host_scripts)
    )


def _capabilities(evidence: ServiceEvidence) -> _Capabilities | None:
    """The first capability or command list available for this port."""
    for script_id in ("smtp-commands", "pop3-capabilities", "imap-capabilities"):
        output = evidence.script(script_id)
        if not output or not output.strip():
            continue
        raw = "\n".join(line.strip() for line in output.splitlines() if line.strip())
        tokens = _tokens(raw)
        if not tokens:
            continue
        return _Capabilities(raw=raw, tokens=tokens, source=script_id)
    return None


def _tokens(raw: str) -> list[str]:
    """Upper-case capability tokens, de-duplicated, order preserved."""
    tokens: list[str] = []
    for piece in _TOKEN_SPLIT.split(raw.upper()):
        token = piece.strip().strip(".;")
        if not token or token in tokens:
            continue
        tokens.append(token)
    return tokens


def _is_implicit_tls(evidence: ServiceEvidence) -> bool:
    if (evidence.tunnel or "").strip().lower() in {"ssl", "tls"}:
        return True
    service = (evidence.service or "").strip().lower()
    if service in IMPLICIT_TLS_SERVICES or service.startswith(("ssl/", "tls/")):
        return True
    return evidence.port in IMPLICIT_TLS_PORTS


def _is_cleartext_port(evidence: ServiceEvidence) -> bool:
    """True for a port that starts unencrypted, so STARTTLS is the only option."""
    if _is_implicit_tls(evidence):
        return False
    if evidence.port in CLEARTEXT_PORTS:
        return True
    # A mail service on a non-standard port still starts in cleartext unless
    # the service name or tunnel says otherwise.
    return (evidence.service or "").strip().lower() in {"smtp", "submission", "pop3", "imap"}


def _key_values(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in output.splitlines():
        match = _KEY_VALUE.match(raw.strip())
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        if key and value:
            fields.setdefault(key, value)
    return fields


def _first_lines(text: str, limit: int) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:limit])


def _quote(lines: list[str], limit: int) -> str:
    """Quote at most *limit* lines, saying how many were left out."""
    shown = lines[:limit]
    remaining = len(lines) - len(shown)
    if remaining > 0:
        shown = [*shown, f"... (+{remaining} more)"]
    return "\n".join(shown)
