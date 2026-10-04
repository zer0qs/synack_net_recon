"""TLS certificate hygiene, read from evidence netrecon already collected.

Almost everything worth saying about a TLS listener is already in the
``ssl-cert`` NSE output on disk: the validity dates, the issuer, the key size
and the signature algorithm. Parsing that text is therefore the primary path
here - it costs the target nothing, it can be re-run offline against an old run
directory, and it quotes the scanner's own words back to the reader so a
finding can be checked without rescanning.

:class:`TlsProbe` is the single exception to the "analyzers open no sockets"
rule in this package, and it is used only when ``--scripts`` never ran, so no
``ssl-cert`` output exists. It reads the certificate *without* trusting it:
hosts inside an engagement scope routinely serve self-signed, expired or
mismatched certificates, and verifying the chain would throw away exactly the
evidence reported below. The address is re-checked against the scope file
immediately before the socket is opened.

Severity is an exposure judgement. "high" on an expired certificate means "an
assessor should look at this today", because users are being trained to click
through the warning - never that anything here is exploitable. No finding in
this module names a CVE or claims a working attack.
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from netrecon.analyze.base import Finding, ServiceEvidence
from netrecon.report.categories import TLS_PORTS, TLS_SERVICE_NAMES

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the import cost off runtime
    from netrecon.core.scope import Scope

#: Service names that imply TLS on the wire. The report's web-focused set plus
#: the non-web wrappers nmap labels directly; anything of the form ``ssl/*`` is
#: matched by prefix in :meth:`TlsAnalyzer.applies_to`.
TLS_SERVICES: frozenset[str] = TLS_SERVICE_NAMES | frozenset(
    {
        "ssl",
        "tls",
        "ftps",
        "ftps-data",
        "nntps",
        "telnets",
        "ircs",
        "sip-tls",
        "submissions",
    }
)

#: Ports conventionally wrapped in TLS. Weak evidence on its own (anything can
#: listen anywhere), used only when the service name says nothing.
TLS_CONVENTIONAL_PORTS: frozenset[int] = TLS_PORTS | frozenset(
    {465, 563, 614, 989, 990, 992, 994, 2376, 5061, 6697, 8883}
)

#: A certificate inside this window is a change-control item, not a problem yet.
EXPIRY_WARNING_DAYS = 30

#: CA/Browser Forum ceiling at the time of writing; longer lifetimes mean a
#: compromised key stays usable for years.
MAX_VALIDITY_DAYS = 825

MIN_RSA_BITS = 2048

#: Below this, the two clocks are close enough that the difference is noise.
CLOCK_SKEW_THRESHOLD_SECONDS = 300

#: Digest families that no longer resist collisions. The negative lookahead
#: keeps ``sha256``/``sha384`` out of the ``sha1`` match.
WEAK_SIGNATURE_RE = re.compile(r"(md2|md4|md5|sha1)(?!\d)", re.IGNORECASE)

#: Substrings that mark a cipher suite as broken or deprecated.
WEAK_CIPHER_TOKENS: tuple[str, ...] = (
    "null",
    "export",
    "anon",
    "rc4",
    "rc2",
    "des",
    "idea",
    "md5",
)

#: Split a distinguished name on "/" only where a new ``key=`` begins, so a
#: value containing a slash does not lose half of itself.
_NAME_SPLIT_RE = re.compile(r"/(?=[A-Za-z0-9.]+=)")

_LABELS_TO_FINGERPRINT = {"md5": "md5", "sha-1": "sha1", "sha1": "sha1", "sha-256": "sha256"}

_TIMESTAMP_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S %Y GMT",  # ssl.getpeercert() form
    "%Y%m%d%H%M%SZ",  # raw ASN.1 UTCTime, seen in truncated output
)

_SKEW_RE = re.compile(
    r"([+-]?)\s*((?:\d+\s*[dhms])+)\s*from\s+(?:scanner|local)\s+time", re.IGNORECASE
)

_SKEW_PART_RE = re.compile(r"(\d+)\s*([dhms])")

_SKEW_UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


@dataclass
class CertificateFacts:
    """What could be read about one certificate - and nothing more.

    Every field is optional because real NSE output is truncated, reordered and
    occasionally missing: a field that could not be read stays ``None`` so no
    finding is derived from it.
    """

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    sans: tuple[str, ...] = ()
    key_type: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprints: dict[str, str] = field(default_factory=dict)
    protocol: str | None = None
    cipher: str | None = None
    #: The source lines, cleaned of nmap's "|" gutter, for quoting as evidence.
    lines: tuple[str, ...] = ()

    @property
    def subject_cn(self) -> str | None:
        return self.subject.get("commonName")

    @property
    def issuer_cn(self) -> str | None:
        return self.issuer.get("commonName")

    @property
    def covered_names(self) -> tuple[str, ...]:
        """Names this certificate asserts: the subject CN plus DNS/IP SANs."""
        names: list[str] = []
        if self.subject_cn:
            names.append(self.subject_cn)
        for entry in self.sans:
            kind, _, value = entry.partition(":")
            if kind.strip().upper() in {"DNS", "IP", "IP ADDRESS"} and value.strip():
                names.append(value.strip())
        seen: set[str] = set()
        unique: list[str] = []
        for name in names:
            lowered = name.strip().lower()
            if lowered and lowered not in seen:
                seen.add(lowered)
                unique.append(name.strip())
        return tuple(unique)

    @property
    def is_empty(self) -> bool:
        """True when nothing usable was read, so there is nothing to report."""
        return not any(
            (
                self.subject,
                self.issuer,
                self.sans,
                self.not_before,
                self.not_after,
                self.fingerprints,
                self.protocol,
                self.key_bits,
                self.signature_algorithm,
            )
        )

    def line(self, label: str) -> str | None:
        """The original line for *label*, so a finding quotes the tool verbatim."""
        wanted = label.strip().lower()
        for line in self.lines:
            if line.lower().startswith(wanted):
                return line
        return None

    def quote(self, *labels: str) -> str | None:
        """Several original lines joined, skipping the ones that are absent."""
        quoted = [line for line in (self.line(label) for label in labels) if line]
        return "\n".join(quoted) or None


def _script_output(evidence: ServiceEvidence, name: str) -> str | None:
    """Output of exactly this script id.

    Deliberately not :meth:`ServiceEvidence.script`, whose prefix fallback would
    hand ``ssl-cert-intaddr`` output to the ``ssl-cert`` parser.
    """
    return evidence.scripts.get(name) or evidence.host_scripts.get(name)


def _clean_lines(text: str) -> list[str]:
    """Strip nmap's ``|`` / ``|_`` gutter and blank lines from script output."""
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("|_"):
            line = line[2:]
        elif line.startswith("|"):
            line = line[1:]
        line = line.strip()
        if line:
            lines.append(line)
    return lines


def _parse_name(text: str) -> dict[str, str]:
    """Parse ``commonName=x/organizationName=y`` into a mapping."""
    fields: dict[str, str] = {}
    for part in _NAME_SPLIT_RE.split(text.strip()):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        # First occurrence wins: nmap emits the significant fields first.
        if key and key not in fields:
            fields[key] = value.strip()
    return fields


def _parse_sans(text: str) -> tuple[str, ...]:
    entries: list[str] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if ":" in chunk:
            entries.append(chunk)
    return tuple(entries)


def _parse_timestamp(text: str) -> datetime | None:
    """Parse any of the timestamp shapes seen in ssl-cert and ssl module output."""
    value = text.strip()
    if not value:
        return None
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        for fmt in _TIMESTAMP_FORMATS:
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    # ssl-cert reports UTC without saying so; assume it rather than local time.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_certificate(text: str) -> CertificateFacts:
    """Parse ``ssl-cert`` output defensively.

    Fields may be missing, reordered or cut off mid-line; anything unrecognised
    is ignored rather than guessed at.
    """
    lines = _clean_lines(text)
    facts = CertificateFacts(lines=tuple(lines))
    for line in lines:
        label, sep, value = line.partition(":")
        if not sep:
            continue
        label = label.strip().lower()
        value = value.strip()
        if label == "subject":
            facts.subject = _parse_name(value)
        elif label == "issuer":
            facts.issuer = _parse_name(value)
        elif label == "subject alternative name":
            facts.sans = _parse_sans(value)
        elif label == "public key type":
            facts.key_type = value.lower() or None
        elif label == "public key bits":
            facts.key_bits = int(value) if value.isdigit() else None
        elif label == "signature algorithm":
            facts.signature_algorithm = value or None
        elif label == "not valid before":
            facts.not_before = _parse_timestamp(value)
        elif label == "not valid after":
            facts.not_after = _parse_timestamp(value)
        elif label in _LABELS_TO_FINGERPRINT:
            facts.fingerprints[_LABELS_TO_FINGERPRINT[label]] = " ".join(value.split())
    return facts


def _flatten_rdn(rdns: Any) -> str:
    """Render ``ssl.getpeercert()``'s nested name tuples as an ssl-cert name."""
    parts: list[str] = []
    for rdn in rdns or ():
        for pair in rdn or ():
            if isinstance(pair, tuple) and len(pair) == 2:
                parts.append(f"{pair[0]}={pair[1]}")
    return "/".join(parts)


def facts_from_probe(payload: dict[str, Any]) -> CertificateFacts:
    """Rebuild :class:`CertificateFacts` from one :meth:`TlsProbe.fetch` result.

    The probe result is rendered into ``ssl-cert``'s own line shape first, so
    findings quote evidence in the same form whichever source produced them.
    Key size and signature algorithm are absent on this path: the stdlib hands
    back no such fields and netrecon adds no X.509 parser to invent them.
    """
    cert = payload.get("certificate") or {}
    lines: list[str] = []
    subject = _flatten_rdn(cert.get("subject"))
    if subject:
        lines.append(f"Subject: {subject}")
    sans = cert.get("subjectAltName") or ()
    rendered_sans = [f"{kind}:{value}" for kind, value in sans if value]
    if rendered_sans:
        lines.append("Subject Alternative Name: " + ", ".join(rendered_sans))
    issuer = _flatten_rdn(cert.get("issuer"))
    if issuer:
        lines.append(f"Issuer: {issuer}")
    if cert.get("notBefore"):
        lines.append(f"Not valid before: {cert['notBefore']}")
    if cert.get("notAfter"):
        lines.append(f"Not valid after:  {cert['notAfter']}")
    if payload.get("der_sha256"):
        lines.append(f"SHA-256: {payload['der_sha256']}")
    facts = parse_certificate("\n".join(lines))
    facts.protocol = payload.get("protocol") or None
    cipher = payload.get("cipher")
    if isinstance(cipher, tuple) and cipher:
        facts.cipher = str(cipher[0])
    return facts


def _describe_name(fields: dict[str, str]) -> str:
    """A short human label for a subject or issuer, falling back to the lot."""
    for key in ("commonName", "organizationName", "organizationalUnitName"):
        if fields.get(key):
            return fields[key]
    return "/".join(f"{k}={v}" for k, v in fields.items()) or "unknown"


def _hostname_covered(name: str, covered: Iterable[str]) -> bool:
    """RFC 6125 style match: exact, or a wildcard over exactly one label."""
    target = name.strip().lower().rstrip(".")
    if not target:
        return False
    for entry in covered:
        candidate = entry.strip().lower().rstrip(".")
        if not candidate:
            continue
        if candidate == target:
            return True
        if candidate.startswith("*."):
            head, _, tail = target.partition(".")
            if head and tail and f".{tail}" == candidate[1:]:
                return True
    return False


def evaluate_certificate(
    evidence: ServiceEvidence,
    facts: CertificateFacts,
    *,
    source: str = "ssl-cert",
    now: datetime | None = None,
) -> list[Finding]:
    """Findings derivable from one certificate. No I/O, no network."""
    if facts.is_empty:
        return []
    moment = now or datetime.now(UTC)
    findings: list[Finding] = []

    if facts.not_after is not None:
        remaining = facts.not_after - moment
        if remaining.total_seconds() < 0:
            findings.append(
                Finding(
                    key="tls.expired-certificate",
                    title="TLS certificate has expired",
                    severity="high",
                    summary=(
                        f"The certificate served on {evidence.label} expired "
                        f"{abs(remaining.days)} day(s) ago, on "
                        f"{facts.not_after.date().isoformat()}."
                    ),
                    evidence=facts.quote("Not valid after", "Subject"),
                    recommendation=(
                        "Renew or replace the certificate. Until then clients either fail "
                        "to connect or are trained to click through the warning."
                    ),
                    source=source,
                    data={"not_after": facts.not_after.isoformat(), "days_expired": abs(remaining.days)},
                )
            )
        elif remaining <= timedelta(days=EXPIRY_WARNING_DAYS):
            findings.append(
                Finding(
                    key="tls.expiring-soon",
                    title="TLS certificate expires soon",
                    severity="low",
                    summary=(
                        f"The certificate on {evidence.label} expires in {remaining.days} day(s), "
                        f"on {facts.not_after.date().isoformat()}."
                    ),
                    evidence=facts.quote("Not valid after"),
                    recommendation="Confirm the renewal is scheduled before the expiry date.",
                    source=source,
                    data={"not_after": facts.not_after.isoformat(), "days_remaining": remaining.days},
                )
            )

    if facts.not_before is not None and facts.not_before > moment:
        findings.append(
            Finding(
                key="tls.not-yet-valid",
                title="TLS certificate is not yet valid",
                severity="medium",
                summary=(
                    f"The certificate on {evidence.label} is dated from "
                    f"{facts.not_before.date().isoformat()}, which is in the future. Either the "
                    "certificate was issued early or a clock is wrong."
                ),
                evidence=facts.quote("Not valid before"),
                recommendation=(
                    "Check the host clock and the issuance date; clients will reject the "
                    "certificate until the start date passes."
                ),
                source=source,
                data={"not_before": facts.not_before.isoformat()},
            )
        )

    if facts.not_before is not None and facts.not_after is not None:
        validity = facts.not_after - facts.not_before
        if validity.days > MAX_VALIDITY_DAYS:
            findings.append(
                Finding(
                    key="tls.long-validity",
                    title="TLS certificate lifetime is unusually long",
                    severity="low",
                    summary=(
                        f"The certificate on {evidence.label} is valid for {validity.days} days, "
                        f"more than the {MAX_VALIDITY_DAYS}-day maximum public CAs issue. A "
                        "compromised key stays usable for that whole period."
                    ),
                    evidence=facts.quote("Not valid before", "Not valid after"),
                    recommendation="Shorten the lifetime and automate renewal.",
                    source=source,
                    data={"validity_days": validity.days},
                )
            )

    if facts.subject and facts.issuer and facts.subject == facts.issuer:
        findings.append(
            Finding(
                key="tls.self-signed",
                title="TLS certificate is self-signed",
                severity="medium",
                summary=(
                    f"The certificate on {evidence.label} names itself as its own issuer "
                    f"({_describe_name(facts.subject)}), so no third party vouches for it and "
                    "clients cannot distinguish it from an interception certificate."
                ),
                evidence=facts.quote("Subject", "Issuer"),
                recommendation=(
                    "Issue the certificate from a CA the clients already trust, or document "
                    "why this endpoint is exempt."
                ),
                source=source,
                data={"subject": _describe_name(facts.subject)},
            )
        )

    covered = facts.covered_names
    known_hostnames = [name for name in evidence.hostnames if name and name.strip()]
    # Only checked when names are actually known: without them a mismatch cannot
    # be shown, and netrecon does not guess at what the client would have asked for.
    if covered and known_hostnames:
        matched = [name for name in known_hostnames if _hostname_covered(name, covered)]
        if not matched and not _hostname_covered(evidence.ip, covered):
            findings.append(
                Finding(
                    key="tls.hostname-mismatch",
                    title="TLS certificate does not cover the known hostnames",
                    severity="low",
                    summary=(
                        f"The certificate on {evidence.label} covers {', '.join(covered)}, which "
                        f"does not include the name(s) this host answers to "
                        f"({', '.join(known_hostnames)}) or its address."
                    ),
                    evidence=facts.quote("Subject", "Subject Alternative Name"),
                    recommendation=(
                        "Confirm which name clients use. A certificate for a different name "
                        "produces warnings users learn to dismiss."
                    ),
                    source=source,
                    data={"covered": list(covered), "hostnames": known_hostnames},
                )
            )

    if facts.signature_algorithm and WEAK_SIGNATURE_RE.search(facts.signature_algorithm):
        findings.append(
            Finding(
                key="tls.weak-signature",
                title="TLS certificate signed with a weak digest",
                severity="medium",
                summary=(
                    f"The certificate on {evidence.label} is signed with "
                    f"{facts.signature_algorithm}. MD5 and SHA-1 signatures no longer resist "
                    "collisions and modern clients reject them."
                ),
                evidence=facts.quote("Signature Algorithm"),
                recommendation="Reissue with a SHA-256 or stronger signature.",
                source=source,
                data={"signature_algorithm": facts.signature_algorithm},
            )
        )

    if facts.key_type == "rsa" and facts.key_bits is not None and facts.key_bits < MIN_RSA_BITS:
        findings.append(
            Finding(
                key="tls.short-key",
                title="TLS certificate uses a short RSA key",
                severity="medium",
                summary=(
                    f"The certificate on {evidence.label} carries a {facts.key_bits}-bit RSA key, "
                    f"below the {MIN_RSA_BITS}-bit minimum current guidance sets."
                ),
                evidence=facts.quote("Public Key type", "Public Key bits"),
                recommendation=f"Reissue with at least a {MIN_RSA_BITS}-bit RSA key, or an EC key.",
                source=source,
                data={"key_type": facts.key_type, "key_bits": facts.key_bits},
            )
        )

    findings.append(_certificate_summary(evidence, facts, source))
    return findings


def _certificate_summary(
    evidence: ServiceEvidence, facts: CertificateFacts, source: str
) -> Finding:
    """The always-present record of what was actually served."""
    parts: list[str] = []
    if facts.subject:
        parts.append(f"subject {_describe_name(facts.subject)}")
    if facts.issuer:
        parts.append(f"issuer {_describe_name(facts.issuer)}")
    if facts.not_before and facts.not_after:
        parts.append(
            f"valid {facts.not_before.date().isoformat()} to {facts.not_after.date().isoformat()}"
        )
    elif facts.not_after:
        parts.append(f"valid until {facts.not_after.date().isoformat()}")
    if facts.key_type:
        bits = f" {facts.key_bits}-bit" if facts.key_bits else ""
        parts.append(f"{facts.key_type.upper()}{bits} key")
    if facts.protocol:
        parts.append(f"negotiated {facts.protocol}")
    if facts.cipher:
        parts.append(f"cipher {facts.cipher}")
    summary = f"TLS on {evidence.label}: " + ("; ".join(parts) if parts else "certificate read")
    return Finding(
        key="tls.certificate",
        title="TLS certificate details",
        severity="info",
        summary=summary,
        evidence="\n".join(facts.lines) or None,
        source=source,
        data={
            "subject": facts.subject,
            "issuer": facts.issuer,
            "subject_alternative_names": list(facts.sans),
            "key_type": facts.key_type,
            "key_bits": facts.key_bits,
            "signature_algorithm": facts.signature_algorithm,
            "not_before": facts.not_before.isoformat() if facts.not_before else None,
            "not_after": facts.not_after.isoformat() if facts.not_after else None,
            "fingerprints": facts.fingerprints,
            "protocol": facts.protocol,
            "cipher": facts.cipher,
        },
    )


def parse_clock_skew(text: str) -> tuple[int, str] | None:
    """Seconds of skew and the line it came from, out of ``ssl-date`` output."""
    for line in _clean_lines(text):
        match = _SKEW_RE.search(line)
        if not match:
            continue
        seconds = sum(
            int(amount) * _SKEW_UNIT_SECONDS[unit.lower()]
            for amount, unit in _SKEW_PART_RE.findall(match.group(2))
        )
        return (-seconds if match.group(1) == "-" else seconds, line)
    return None


def clock_skew_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Report a target clock far enough off to matter for logs and tickets."""
    text = _script_output(evidence, "ssl-date")
    if not text:
        return []
    parsed = parse_clock_skew(text)
    if parsed is None:
        return []
    seconds, line = parsed
    if abs(seconds) < CLOCK_SKEW_THRESHOLD_SECONDS:
        return []
    return [
        Finding(
            key="tls.clock-skew",
            title="Target clock differs from the scanner clock",
            severity="low",
            summary=(
                f"The TLS handshake on {evidence.label} reports a clock "
                f"{abs(seconds)} seconds {'behind' if seconds < 0 else 'ahead of'} the scanner. "
                "Skew of this size breaks certificate validity windows, time-based tokens and "
                "log correlation."
            ),
            evidence=line,
            recommendation="Check NTP on the host before relying on its timestamps.",
            source="ssl-date",
            data={"skew_seconds": seconds},
        )
    ]


def weak_cipher_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Optional: ``ssl-enum-ciphers`` is outside netrecon's allowed NSE set.

    It only runs when an operator supplied the output by other means, so this is
    a bonus path - absent output simply yields nothing.
    """
    text = _script_output(evidence, "ssl-enum-ciphers")
    if not text:
        return []
    reasons: list[str] = []
    quoted: list[str] = []
    for line in _clean_lines(text):
        lowered = line.lower()
        if lowered.startswith("least strength"):
            grade = line.split(":")[-1].strip().upper()[:1]
            if grade and "C" <= grade <= "F":
                reasons.append(f"graded {grade} overall")
                quoted.append(line)
            continue
        if lowered.startswith(("sslv2", "sslv3")):
            reasons.append(f"obsolete protocol offered ({line.rstrip(':')})")
            quoted.append(line)
            continue
        # Only lines that look like a cipher suite, so warnings and headers do
        # not get read as cipher names.
        if "_" not in line and "-" not in line:
            continue
        hit = next((token for token in WEAK_CIPHER_TOKENS if token in lowered), None)
        if hit:
            reasons.append(f"weak suite offered ({line.split('(')[0].strip()})")
            quoted.append(line)
    if not reasons:
        return []
    return [
        Finding(
            key="tls.weak-cipher",
            title="Weak TLS ciphers or protocols offered",
            severity="medium",
            summary=(
                f"{evidence.label} offers cipher suites or protocol versions that current "
                "guidance retires: " + "; ".join(dict.fromkeys(reasons)) + "."
            ),
            evidence="\n".join(quoted[:8]),
            recommendation=(
                "Restrict the server to TLS 1.2+ with AEAD suites and remove the listed suites."
            ),
            source="ssl-enum-ciphers",
            data={"reasons": list(dict.fromkeys(reasons))},
        )
    ]


class TlsAnalyzer:
    """Certificate and transport findings for one TLS-speaking port."""

    name = "tls"
    needs_probe = True

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        if (evidence.tunnel or "").strip().lower() in {"ssl", "tls"}:
            return True
        service = (evidence.service or "").strip().lower()
        if service in TLS_SERVICES or service.startswith(("ssl/", "tls/")):
            return True
        if any(name.startswith(("ssl-", "sslv", "tls-")) for name in evidence.scripts):
            return True
        return evidence.port in TLS_CONVENTIONAL_PORTS

    def analyse(self, evidence: ServiceEvidence, probe: Any | None = None) -> list[Finding]:
        findings: list[Finding] = []
        cert_output = _script_output(evidence, "ssl-cert")
        if cert_output:
            findings.extend(
                evaluate_certificate(evidence, parse_certificate(cert_output), source="ssl-cert")
            )
        elif probe is not None:
            # No ssl-cert output to read, so the certificate is only obtainable
            # by asking the host for it once.
            payload = probe.fetch(evidence.ip, evidence.port)
            if payload:
                findings.extend(
                    evaluate_certificate(
                        evidence, facts_from_probe(payload), source="netrecon tls probe"
                    )
                )
        findings.extend(clock_skew_findings(evidence))
        findings.extend(weak_cipher_findings(evidence))
        return findings


@dataclass
class TlsProbe:
    """One TLS connection, used only when there is no ``ssl-cert`` output.

    This is the only socket in :mod:`netrecon.analyze`. Both fields are
    required: a probe without a scope could not be built, let alone used.
    """

    timeout: int
    scope: Scope

    def fetch(self, ip: str, port: int) -> dict[str, Any] | None:
        """Read one peer certificate plus the negotiated protocol and cipher.

        Returns ``None`` for anything that goes wrong on the wire - unreachable
        host, not TLS, handshake refused - because a failed probe is an ordinary
        outcome and must never abort the stage.

        The scope check sits deliberately *outside* that error handling: a
        connection error is expected, but an attempt to touch an address outside
        the scope file is a bug in netrecon and has to stay loud.
        """
        self.scope.enforce_strict([ip])

        context = ssl.create_default_context()
        # Reading a certificate is not trusting it. Hosts in scope routinely
        # serve self-signed or expired certificates, and verifying here would
        # discard the very evidence this analyzer exists to report.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with (
                socket.create_connection((ip, port), timeout=self.timeout) as raw,
                context.wrap_socket(raw) as tls_sock,
            ):
                parsed = tls_sock.getpeercert() or {}
                binary = tls_sock.getpeercert(binary_form=True)
                result: dict[str, Any] = {
                    "ip": ip,
                    "port": port,
                    "certificate": parsed,
                    "protocol": tls_sock.version(),
                    "cipher": tls_sock.cipher(),
                }
                if not parsed and binary:
                    # With CERT_NONE, CPython hands back an empty dict. netrecon
                    # adds no X.509 parser, so the honest fallback is the size
                    # and digest of the DER - enough to fingerprint the host,
                    # and nothing is inferred that was not actually read.
                    result["der_bytes"] = len(binary)
                    result["der_sha256"] = hashlib.sha256(binary).hexdigest()
                return result
        except (OSError, ValueError):
            return None
