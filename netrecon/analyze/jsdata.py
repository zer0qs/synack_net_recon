"""Deep analysis of JavaScript and front-end assets.

Front-end bundles are the most informative thing a web service hands out
unauthenticated: they routinely contain the full API surface, internal
hostnames, feature flags, and - too often - credentials and real customer data
that someone inlined during development.

Everything here is a **pure function over a string**. No requests are made; the
web stage fetches the bodies and calls in. Three rules shape the output:

* **Masked by default.** Secrets and PII are reported with the value masked and
  a file/line reference. The full body is saved in the run directory for an
  operator to verify. A report that is itself a credential dump is a liability.
* **PII is reported as a count and a kind first.** Finding 4,000 customer email
  addresses in a bundle is the finding; printing 4,000 addresses into a report
  just moves the breach. Samples are capped and masked.
* **Discovered hosts are reported, never fetched.** A hostname found in a
  bundle is outside the authorised IP scope until the operator puts it in the
  scope file, so netrecon lists it and stops there.

The patterns are heuristics. They produce false positives by design - a lead to
check, not a finding to report as fact.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from typing import Any

# -- limits --------------------------------------------------------------

#: Caps per analysed file, so one minified megabyte cannot swamp a report.
MAX_ENDPOINTS = 400
MAX_MATCHES_PER_KIND = 50
MAX_HOSTS = 200
#: How much surrounding text to keep with a match, for context.
CONTEXT_CHARS = 60


# -- data types ----------------------------------------------------------


@dataclass(frozen=True)
class ApiEndpoint:
    """One path or URL the front-end talks to."""

    value: str
    kind: str  # "path" | "url" | "template"
    method: str | None = None
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "kind": self.kind,
            "method": self.method,
            "source": self.source,
        }


@dataclass(frozen=True)
class SensitiveMatch:
    """A string that looks like it should not be in a public asset."""

    kind: str  # "aws_access_key_id", "email", "credit_card", ...
    category: str  # "secret" | "pii" | "infrastructure"
    value: str  # masked unless the operator turned redaction off
    line: int
    source: str
    name: str | None = None  # the variable it was assigned to, when known
    context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "category": self.category,
            "name": self.name,
            "value": self.value,
            "line": self.line,
            "source": self.source,
            "context": self.context,
        }


@dataclass
class JsAnalysis:
    """Everything one JavaScript or HTML body yielded."""

    source: str
    bytes: int = 0
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    secrets: list[SensitiveMatch] = field(default_factory=list)
    pii: list[SensitiveMatch] = field(default_factory=list)
    infrastructure: list[SensitiveMatch] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def total_findings(self) -> int:
        return len(self.secrets) + len(self.pii) + len(self.infrastructure)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "bytes": self.bytes,
            "truncated": self.truncated,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "secret_candidates": [s.to_dict() for s in self.secrets],
            "pii_candidates": [p.to_dict() for p in self.pii],
            "infrastructure": [i.to_dict() for i in self.infrastructure],
            "hosts": self.hosts,
            "source_maps": self.source_maps,
            "comments": self.comments,
            "totals": {
                "endpoints": len(self.endpoints),
                "secrets": len(self.secrets),
                "pii": len(self.pii),
                "infrastructure": len(self.infrastructure),
                "hosts": len(self.hosts),
            },
        }


# -- masking -------------------------------------------------------------


#: Separator between the revealed head and tail of a masked secret.
MASK_ELLIPSIS = "…"


def mask_value(value: str) -> str:
    """Mask a value as ``first six + … + last four``, e.g. ``AKIAZZ…N42X``.

    The head and tail are what let an operator find the value again in the body
    saved under the run directory. A short value has no room to give that away,
    so it reveals at most the first two characters and nothing from the tail.
    """
    text = str(value)
    if len(text) <= 12:
        return f"{text[:2]}{'*' * max(len(text) - 2, 0)}"
    return f"{text[:6]}{MASK_ELLIPSIS}{text[-4:]} (len {len(text)})"


def mask_email(value: str) -> str:
    """Mask an address but keep the domain: the domain is the useful part."""
    local, _, domain = value.partition("@")
    if not domain:
        return mask_value(value)
    head = local[:2] if len(local) > 2 else local[:1]
    return f"{head}{'*' * max(len(local) - len(head), 1)}@{domain}"


def mask_digits(value: str) -> str:
    """Keep only the last four digits of a number-like value."""
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "*" * len(digits)
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


# -- API surface ---------------------------------------------------------

#: Ordered so the more specific patterns win; each must expose group 1.
ENDPOINT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "path",
        re.compile(
            r"""['"`](/(?:api|v\d+|rest|graphql|gql|internal|admin|auth|oauth|sso|"""
            r"""account|user|users|session|token|upload|download|export|import|"""
            r"""webhook|callback|rpc)[^'"`\s<>]{0,200})['"`]"""
        ),
    ),
    (
        "path",
        re.compile(
            r"""['"`](/[a-zA-Z0-9_\-./{}:$]{2,150}\."""
            r"""(?:json|xml|php|aspx?|jsp|jspx|do|action|cgi|pl|py|rb))['"`]"""
        ),
    ),
    (
        "url",
        re.compile(r"""['"`](https?://[^'"`\s<>]{4,250})['"`]"""),
    ),
    (
        "template",
        re.compile(r"""['"`](/[a-zA-Z0-9_\-./]*\$\{[^'"`]{1,80}\}[^'"`\s]{0,120})['"`]"""),
    ),
)

#: Call sites that reveal the HTTP method alongside the URL.
METHOD_CALL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"""axios\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['"`](?P<url>[^'"`]{2,250})['"`]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""\$\.(?P<method>get|post|ajax)\s*\(\s*['"`](?P<url>[^'"`]{2,250})['"`]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""\.open\s*\(\s*['"`](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]\s*,\s*['"`](?P<url>[^'"`]{2,250})['"`]""",
    ),
    re.compile(
        r"""fetch\s*\(\s*['"`](?P<url>[^'"`]{2,250})['"`]\s*,\s*\{[^}]{0,200}?method\s*:\s*['"`](?P<method>[A-Z]{3,7})['"`]""",
        re.DOTALL,
    ),
)

#: Paths that are assets, not API surface.
ASSET_SUFFIXES = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".webp", ".map", ".avif",
)


def extract_endpoints(body: str, source: str = "") -> list[ApiEndpoint]:
    """Pull the API surface out of a script or page body."""
    found: dict[str, ApiEndpoint] = {}

    # Method-bearing call sites first, so their method survives deduplication.
    # Every loop checks the cap *before* inserting, so MAX_ENDPOINTS is a hard
    # limit: a bundle built to overflow it cannot grow the report past it.
    for pattern in METHOD_CALL_PATTERNS:
        for match in pattern.finditer(body):
            url = match.group("url").strip()
            if not _is_interesting_endpoint(url):
                continue
            if url not in found and len(found) >= MAX_ENDPOINTS:
                break
            kind = "url" if url.startswith(("http://", "https://")) else "path"
            found.setdefault(
                url, ApiEndpoint(url, kind, match.group("method").upper(), source)
            )

    for kind, pattern in ENDPOINT_PATTERNS:
        if len(found) >= MAX_ENDPOINTS:
            break
        for match in pattern.finditer(body):
            value = match.group(1).strip()
            if not _is_interesting_endpoint(value):
                continue
            if value not in found:
                if len(found) >= MAX_ENDPOINTS:
                    break
                found[value] = ApiEndpoint(value, kind, None, source)

    return sorted(found.values(), key=lambda e: (e.value.lower(), e.kind))


def _is_interesting_endpoint(value: str) -> bool:
    if not 2 <= len(value) <= 250:
        return False
    lowered = value.lower()
    if lowered.endswith(ASSET_SUFFIXES):
        return False
    # Bare schemes, mime types and the like slip through the URL pattern.
    return not lowered.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:"))


# -- secrets -------------------------------------------------------------

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b")),
    (
        "aws_secret_access_key",
        re.compile(
            r"""(?:aws)?_?secret_?(?:access)?_?key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']""",
            re.IGNORECASE,
        ),
    ),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("google_oauth_id", re.compile(r"\b(\d{10,14}-[0-9a-z]{32}\.apps\.googleusercontent\.com)\b")),
    ("slack_token", re.compile(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,70})\b")),
    ("slack_webhook", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/+]{20,})")),
    (
        "github_token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,100})\b"),
    ),
    ("gitlab_token", re.compile(r"\b(glpat-[0-9A-Za-z_\-]{20,})\b")),
    ("stripe_key", re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,64})\b")),
    ("twilio_sid", re.compile(r"\b(AC[0-9a-fA-F]{32})\b")),
    ("sendgrid_key", re.compile(r"\b(SG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,})\b")),
    ("npm_token", re.compile(r"\b(npm_[0-9A-Za-z]{36})\b")),
    ("openai_key", re.compile(r"\b(sk-(?:proj-)?[0-9A-Za-z_\-]{20,})\b")),
    ("mailgun_key", re.compile(r"(?<![\w\-])(key-[0-9a-fA-F]{32})\b")),
    (
        # The marker, not the key body: a service-account blob is thousands of
        # characters and reporting it would be the credential dump this module
        # exists to avoid. Requiring the private key to actually start with a
        # PEM header is what separates a live blob from a templated one.
        "gcp_service_account",
        re.compile(
            r"""(["']type["']\s*:\s*["']service_account["'])"""
            r"""(?=[\s\S]{0,4000}?["']private_key["']\s*:\s*["'](?:\\n)?-----BEGIN)"""
        ),
    ),
    (
        # apiKey next to authDomain/projectId: either alone is too weak, the
        # pair is a Firebase web config. The captured value is the key itself,
        # so a config full of placeholders is filtered like any other.
        "firebase_config",
        re.compile(
            r"""apiKey["']?\s*[:=]\s*["']([^"'\s]{8,160})["']"""
            r"""(?=[^{}]{0,400}?(?:authDomain|projectId|databaseURL)["']?\s*[:=])""",
            re.IGNORECASE,
        ),
    ),
    (
        "firebase_config",
        re.compile(
            r"\b([a-z0-9][a-z0-9\-]{0,62}\.(?:firebaseio\.com|firebaseapp\.com))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bearer_header",
        re.compile(
            r"""authorization["']?\s*[:=,]\s*["']?\s*Bearer\s+([A-Za-z0-9._\-+/=]{8,512})""",
            re.IGNORECASE,
        ),
    ),
    (
        "basic_auth_header",
        re.compile(
            r"""authorization["']?\s*[:=,]\s*["']?\s*Basic\s+([A-Za-z0-9+/=]{12,512})""",
            re.IGNORECASE,
        ),
    ),
    ("azure_storage_key", re.compile(r"AccountKey\s*=\s*([A-Za-z0-9+/=]{40,120})", re.IGNORECASE)),
    (
        # A bare UUID is a request id, a build id or a React key far more often
        # than it is a credential, so the key-ish name is a hard requirement.
        "heroku_api_key",
        re.compile(
            r"""(?:heroku|api|auth|access|client|app|service|session)[_-]?"""
            r"""(?:api[_-]?)?(?:key|token|secret|password)["']?\s*[:=]\s*["']"""
            r"""([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']""",
            re.IGNORECASE,
        ),
    ),
    ("private_key_block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b")),
    (
        "basic_auth_in_url",
        re.compile(r"((?:https?|ftp|mongodb|postgres(?:ql)?|mysql|redis)://[^/\s:@'\"]{1,64}:[^/\s@'\"]{1,64}@[^\s'\"]{1,120})"),
    ),
    (
        "connection_string",
        re.compile(
            r"((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s'\"<>]{8,200})"
        ),
    ),
)

#: ``name = "value"`` assignments where the name says it is a secret.
ASSIGNED_SECRET = re.compile(
    r"""["']?\b((?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|"""
    r"""auth[_-]?token|bearer[_-]?token|private[_-]?key|encryption[_-]?key|signing[_-]?key|"""
    r"""secret|password|passwd|pwd|token|key))["']?\s*[:=]\s*["']([^"'\s]{8,160})["']""",
    re.IGNORECASE,
)

#: Markers that make a value a template or sample rather than a live secret.
PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example", "your_", "yourkey", "your-", "placeholder", "xxxx", "<", "{{", "${",
    "test_key", "dummy", "redacted", "insert", "todo", "fixme", "abc123", "123456",
    "changeme", "sample", "replace", "null", "undefined", "notarealkey", "lorem",
    "process.env", "import.meta", "%s", "%(", "demo_", "_demo",
)


def looks_like_placeholder(value: str) -> bool:
    """Filter obvious templates, so the report stays worth reading."""
    lowered = value.strip().lower()
    if not lowered or len(lowered) < 8:
        return True
    if lowered in {"undefined", "null", "none", "false", "true", "password", "changeme"}:
        return True
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    # Almost no character variety means a filler string, not a key.
    return len(set(lowered)) <= 3


def extract_secrets(body: str, source: str = "", *, redact: bool = True) -> list[SensitiveMatch]:
    """Credential-shaped strings, masked by default.

    Context windows are redacted against *every* value found, not just the one
    the window belongs to. Two secrets within a context width of each other are
    common in a config object, and a window that quoted its neighbour verbatim
    would put an unmasked credential in the report.
    """
    matches: list[SensitiveMatch] = []
    seen: set[tuple[str, str]] = set()
    per_kind: dict[str, int] = {}
    found_values: list[str] = []

    def add(kind: str, value: str, start: int, name: str | None = None) -> None:
        if looks_like_placeholder(value):
            return
        identity = (kind, value)
        if identity in seen:
            return
        if per_kind.get(kind, 0) >= MAX_MATCHES_PER_KIND:
            return
        seen.add(identity)
        per_kind[kind] = per_kind.get(kind, 0) + 1
        found_values.append(value)
        matches.append(
            SensitiveMatch(
                kind=kind,
                category="secret",
                value=mask_value(value) if redact else value,
                line=body.count("\n", 0, start) + 1,
                source=source,
                name=name,
                # Filled in below, once every value in this body is known.
                context=_context(body, start, redact=False),
            )
        )

    credentialled: set[str] = set()
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(body):
            value = match.group(1)
            if kind == "basic_auth_in_url":
                credentialled.add(value)
            elif kind == "connection_string" and value in credentialled:
                # Already reported, more precisely, as an embedded credential.
                continue
            add(kind, value, match.start(1))

    for match in ASSIGNED_SECRET.finditer(body):
        add("assigned_secret", match.group(2), match.start(2), name=match.group(1))

    if redact and found_values:
        matches = [
            replace(entry, context=_redact_all(entry.context, found_values))
            for entry in matches
        ]
    return matches


#: A fragment this long is enough of a secret to matter.
PARTIAL_SECRET_CHARS = 8


def _redact_all(text: str | None, values: list[str]) -> str | None:
    """Blank out every known secret value in a context window.

    Whole values are replaced outright. The window is also a fixed-width slice
    of the body, so it can begin or end part way through a neighbouring secret;
    those partial fragments are trimmed too. Eight characters of a key is
    enough to be worth protecting, and a truncated context is a small price.
    """
    if not text:
        return text
    for value in values:
        if value and value in text:
            text = text.replace(value, "[redacted]")

    for value in values:
        if not value or len(value) < PARTIAL_SECRET_CHARS:
            continue
        # A trailing fragment: the window ends inside this value.
        for length in range(min(len(text), len(value) - 1), PARTIAL_SECRET_CHARS - 1, -1):
            if text.endswith(value[:length]):
                text = text[:-length] + "[redacted]"
                break
        # A leading fragment: the window begins inside this value.
        for length in range(min(len(text), len(value) - 1), PARTIAL_SECRET_CHARS - 1, -1):
            if text.startswith(value[-length:]):
                text = "[redacted]" + text[length:]
                break
    return text


# -- PII -----------------------------------------------------------------

#: The length bounds are not cosmetic. An unbounded ``[A-Za-z0-9._%+\-]+``
#: before the ``@`` backtracks over the whole of a long separator-rich run
#: (``"1-1-1-..."``) at every start position, which is quadratic: 100 KB of
#: minified code took eleven seconds. 64 is the RFC 5321 local-part limit and
#: 253 the maximum hostname length, so nothing valid is lost.
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24})\b")
#: Loose international phone shape; validated further below. The window starts
#: at six so an eight-digit E.164 number is still offered to the validator.
PHONE_RE = re.compile(r"(?<![\w.])(\+?\d[\d\s().\-]{6,18}\d)(?![\w.])")
CARD_RE = re.compile(r"(?<!\d)((?:\d[ \-]?){12,18}\d)(?!\d)")
IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{10,30})\b")
SSN_RE = re.compile(r"\b(\d{3}-\d{2}-\d{4})\b")
#: Vietnamese national ID / citizen number, 9 or 12 digits.
VN_ID_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

#: S3 bucket references. Group 1 is always the bucket name. Each form requires
#: an ``s3`` label, so ``ec2.eu-west-1.amazonaws.com`` and friends stay out.
S3_BUCKET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # <bucket>.s3.amazonaws.com and <bucket>.s3.<region>.amazonaws.com
    re.compile(
        r"\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][a-z0-9\-]{1,20})?\.amazonaws\.com\b",
        re.IGNORECASE,
    ),
    # s3.<region>.amazonaws.com/<bucket> (path style)
    re.compile(
        r"(?<![\w.\-])s3(?:[.\-][a-z0-9\-]{1,20})?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])",
        re.IGNORECASE,
    ),
    re.compile(r"s3://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])", re.IGNORECASE),
)

#: Issuer prefixes, longest first. Used to raise confidence in a Luhn-valid
#: number, never as a gate: a card from an issuer not listed here is still
#: reported, just without an issuer name attached.
CARD_ISSUER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("6011", "discover"),
    ("34", "amex"),
    ("37", "amex"),
    ("35", "jcb"),
    ("51", "mastercard"),
    ("52", "mastercard"),
    ("53", "mastercard"),
    ("54", "mastercard"),
    ("55", "mastercard"),
    ("4", "visa"),
)

#: Domains that only ever appear in examples.
EXAMPLE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "domain.com",
    "email.com", "yourdomain.com", "mysite.com", "sentry.io", "w3.org",
    "schema.org", "localhost",
}


def _luhn_valid(digits: str) -> bool:
    """Luhn check. Without it, any long number reads as a card number."""
    numbers = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(numbers) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(numbers)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _card_issuer(digits: str) -> str | None:
    """Name the issuer when the prefix is one we know, otherwise ``None``."""
    for prefix, issuer in CARD_ISSUER_PREFIXES:
        if digits.startswith(prefix):
            return issuer
    return None


def _plausible_phone(raw: str) -> bool:
    text = raw.strip()
    # Dotted quads and version strings reach this pattern; they are not phones.
    if text.count(".") >= 2:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return False
    digits = re.sub(r"\D", "", text)
    # E.164 is the confident case: a leading + and 8 to 15 digits.
    if text.startswith("+"):
        return 8 <= len(digits) <= 15
    # Without the +, version strings, timestamps and ids all make long digit
    # runs, so keep the old heuristic: a longer run plus a conventional
    # separator. Loosening this is what would regress the false-positive tests.
    if not 9 <= len(digits) <= 15:
        return False
    return bool(re.search(r"[\s().\-]", raw))


def extract_pii(body: str, source: str = "", *, redact: bool = True) -> list[SensitiveMatch]:
    """Personal data left in a front-end asset.

    Reported conservatively: a bundle full of customer records is a serious
    finding, but a report that reprints those records is a second breach, so
    values are masked and the count is what matters.
    """
    matches: list[SensitiveMatch] = []
    per_kind: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    # Character spans already claimed by a more specific pattern. A national
    # identifier and a phone number have the same shape, so whichever pattern
    # is more specific must win rather than both firing on one string.
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    def add(
        kind: str,
        value: str,
        start: int,
        masked: str,
        end: int | None = None,
        name: str | None = None,
    ) -> None:
        identity = (kind, value)
        if identity in seen:
            return
        if per_kind.get(kind, 0) >= MAX_MATCHES_PER_KIND:
            per_kind[kind] = per_kind.get(kind, 0) + 1
            return
        seen.add(identity)
        per_kind[kind] = per_kind.get(kind, 0) + 1
        claimed.append((start, end if end is not None else start + len(value)))
        matches.append(
            SensitiveMatch(
                kind=kind,
                category="pii",
                value=masked if redact else value,
                line=body.count("\n", 0, start) + 1,
                source=source,
                name=name,
            )
        )

    for match in EMAIL_RE.finditer(body):
        address = match.group(1)
        domain = address.split("@")[-1].lower()
        if domain in EXAMPLE_EMAIL_DOMAINS or domain.endswith(".example"):
            continue
        if address.lower().startswith(("noreply@", "no-reply@", "donotreply@")):
            continue
        add("email", address, match.start(1), mask_email(address))

    # Buckets before the numeric patterns: a bucket name can contain a long
    # digit run, and the claimed span keeps it from being read as a number.
    for pattern in S3_BUCKET_PATTERNS:
        for match in pattern.finditer(body):
            bucket = match.group(1).lower()
            # Not masked: a bucket name is not personal data, and masking it
            # would leave the operator with a finding they cannot act on.
            add("s3_bucket", bucket, match.start(1), bucket, match.end(1))

    for match in CARD_RE.finditer(body):
        raw = match.group(1)
        digits = re.sub(r"\D", "", raw)
        if overlaps(match.start(1), match.end(1)):
            continue
        if _luhn_valid(digits):
            add(
                "credit_card",
                digits,
                match.start(1),
                mask_digits(digits),
                match.end(1),
                name=_card_issuer(digits),
            )

    for match in IBAN_RE.finditer(body):
        add("iban", match.group(1), match.start(1), mask_value(match.group(1)), match.end(1))

    for match in SSN_RE.finditer(body):
        add("ssn", match.group(1), match.start(1), mask_digits(match.group(1)), match.end(1))

    for match in VN_ID_RE.finditer(body):
        if not overlaps(match.start(1), match.end(1)):
            add(
                "national_id",
                match.group(1),
                match.start(1),
                mask_digits(match.group(1)),
                match.end(1),
            )

    # Phone last: its pattern is the loosest, so anything a more specific
    # identifier already claimed is not re-reported as a phone number.
    for match in PHONE_RE.finditer(body):
        raw = match.group(1)
        if overlaps(match.start(1), match.end(1)):
            continue
        if _plausible_phone(raw):
            add("phone", re.sub(r"\D", "", raw), match.start(1), mask_digits(raw), match.end(1))

    return matches


def pii_summary(matches: list[SensitiveMatch]) -> dict[str, int]:
    """Counts by kind - the number is the finding, not the values."""
    counts: dict[str, int] = {}
    for match in matches:
        counts[match.kind] = counts.get(match.kind, 0) + 1
    return dict(sorted(counts.items()))


# -- infrastructure leakage ---------------------------------------------

#: The label repetition is bounded for the same reason as :data:`EMAIL_RE`: an
#: unbounded ``+`` over labels re-walks the whole dotted run at every start
#: position, so ``"a." * 20000`` took nineteen seconds. A hostname cannot
#: exceed 253 characters (checked below), and 40 labels is far past anything a
#: bundle references.
HOSTNAME_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,40}"
    r"(?:[a-zA-Z]{2,24}|local|internal|corp|lan|intranet))\b"
)

#: A dotted identifier is only a hostname if its last label is a real suffix.
#: Without this, ``axios.post``, ``app.js.map`` and the local part of an email
#: address all read as hostnames and swamp the finding that matters.
KNOWN_SUFFIXES: frozenset[str] = frozenset(
    """
    com net org edu gov mil int info biz name pro app dev io co ai cloud tech
    online site xyz top shop store blog wiki news media live life world zone
    systems solutions services network host hosting software digital agency
    group team work design studio email link click page web site1
    local internal corp lan intranet localdomain test example invalid onion
    ac ad ae af ag ai al am ao ar at au az ba bd be bg bh bn bo br bs bt bw by bz
    ca cd cf ch ci cl cm cn cr cu cv cy cz de dk do dz ec ee eg es et eu fi fj fr
    ga ge gh gr gt hk hn hr ht hu id ie il im in iq ir is it je jo jp ke kg kh kr
    kw kz la lb lk lt lu lv ly ma mc md me mg mk ml mm mn mo mt mu mv mw mx my mz
    na ng ni nl no np nz om pa pe pg ph pk pl pr ps pt py qa ro rs ru rw sa se sg
    si sk sn so sv sy th tj tm tn tr tt tw tz ua ug uk us uy uz ve vn za zm zw
    """.split()
)


def _is_hostname(host: str) -> bool:
    """True when the final label is a plausible public or internal suffix."""
    suffix = host.rsplit(".", 1)[-1]
    return suffix in KNOWN_SUFFIXES
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")

#: Hostname fragments that mark a non-production or internal environment.
INTERNAL_MARKERS = (
    ".local", ".internal", ".corp", ".lan", ".intranet", ".test", ".localdomain",
    "staging.", "stage.", "dev.", "test.", "qa.", "uat.", "preprod.", "internal.",
    "admin.", "jenkins.", "gitlab.", "jira.", "vpn.", "ldap.", "backup.",
)

#: Cloud instance metadata endpoints. Their presence in a bundle is worth a look.
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.200.200"}

COMMON_CDN_SUFFIXES = (
    "googleapis.com", "gstatic.com", "jsdelivr.net", "unpkg.com", "cloudflare.com",
    "cdnjs.com", "bootstrapcdn.com", "jquery.com", "fontawesome.com", "w3.org",
    "schema.org", "github.io", "githubusercontent.com",
)


def extract_infrastructure(
    body: str, source: str = "", *, redact: bool = True
) -> tuple[list[SensitiveMatch], list[str]]:
    """Internal hostnames and private addresses referenced by the front-end.

    Returns ``(findings, all_hosts)``. Hosts are reported so the operator can
    decide whether they belong in the scope file; netrecon never resolves or
    contacts them.
    """
    matches: list[SensitiveMatch] = []
    hosts: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, start: int) -> None:
        identity = (kind, value)
        if identity in seen or len(matches) >= MAX_MATCHES_PER_KIND * 3:
            return
        seen.add(identity)
        matches.append(
            SensitiveMatch(
                kind=kind,
                category="infrastructure",
                value=value,  # hostnames are not secret; masking them hides the finding
                line=body.count("\n", 0, start) + 1,
                source=source,
                context=_context(body, start, redact=redact),
            )
        )

    for match in HOSTNAME_RE.finditer(body):
        host = match.group(1).lower().rstrip(".")
        # "ops.team@acme.vn" would otherwise yield "ops.team" as a host: the
        # local part of an address can contain dots and a word that happens to
        # be a valid suffix.
        if body[match.end(1) : match.end(1) + 1] == "@":
            continue
        if not _is_hostname(host) or host.endswith(COMMON_CDN_SUFFIXES) or len(host) > 253:
            continue
        if len(hosts) < MAX_HOSTS:
            hosts.add(host)
        if any(marker in f".{host}" for marker in INTERNAL_MARKERS):
            add("internal_hostname", host, match.start(1))
        if host in METADATA_HOSTS:
            add("cloud_metadata_endpoint", host, match.start(1))

    for match in IPV4_RE.finditer(body):
        text = match.group(1)
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if text in METADATA_HOSTS:
            add("cloud_metadata_endpoint", text, match.start(1))
        elif address.is_private and not address.is_loopback:
            add("private_address", text, match.start(1))
        if len(hosts) < MAX_HOSTS and not address.is_loopback:
            hosts.add(text)

    return matches, sorted(hosts)


# -- comments and source maps -------------------------------------------

SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*'\"]{1,250})")
#: Developer comments worth surfacing. Minified bundles strip most comments,
#: so what survives is usually a licence header or something someone meant.
INTERESTING_COMMENT_RE = re.compile(
    r"/\*{1,2}([^*]{0,400}?(?:TODO|FIXME|HACK|XXX|password|passwd|secret|api[_\- ]?key|"
    r"credential|token|staging|internal|do not (?:commit|ship|deploy)|temporary|workaround)"
    r"[^*]{0,400}?)\*/|//\s*((?:TODO|FIXME|HACK|XXX)[^\n]{0,200})",
    re.IGNORECASE,
)


def extract_source_maps(body: str) -> list[str]:
    return sorted(set(SOURCE_MAP_RE.findall(body)))


def extract_comments(body: str, limit: int = 30) -> list[str]:
    comments: list[str] = []
    for match in INTERESTING_COMMENT_RE.finditer(body):
        text = " ".join((match.group(1) or match.group(2) or "").split())
        if text and text not in comments:
            comments.append(text[:300])
        if len(comments) >= limit:
            break
    return comments


# -- entry point ---------------------------------------------------------


def analyse_javascript(
    body: str, source: str = "", *, redact: bool = True, truncated: bool = False
) -> JsAnalysis:
    """Run every extractor over one body."""
    infrastructure, hosts = extract_infrastructure(body, source, redact=redact)
    return JsAnalysis(
        source=source,
        bytes=len(body),
        truncated=truncated,
        endpoints=extract_endpoints(body, source),
        secrets=extract_secrets(body, source, redact=redact),
        pii=extract_pii(body, source, redact=redact),
        infrastructure=infrastructure,
        hosts=hosts,
        source_maps=extract_source_maps(body),
        comments=extract_comments(body),
    )


def merge_analyses(analyses: list[JsAnalysis]) -> dict[str, Any]:
    """Roll several files up into one per-endpoint view."""
    endpoints: dict[str, ApiEndpoint] = {}
    secrets: list[SensitiveMatch] = []
    pii: list[SensitiveMatch] = []
    infrastructure: list[SensitiveMatch] = []
    hosts: set[str] = set()
    source_maps: set[str] = set()

    for analysis in analyses:
        for endpoint in analysis.endpoints:
            existing = endpoints.get(endpoint.value)
            # Prefer the record that knows the HTTP method.
            if existing is None or (existing.method is None and endpoint.method):
                endpoints[endpoint.value] = endpoint
        secrets.extend(analysis.secrets)
        pii.extend(analysis.pii)
        infrastructure.extend(analysis.infrastructure)
        hosts.update(analysis.hosts)
        source_maps.update(analysis.source_maps)

    return {
        "endpoints": [e.to_dict() for e in sorted(endpoints.values(), key=lambda e: e.value)],
        "secret_candidates": [s.to_dict() for s in secrets],
        "pii_candidates": [p.to_dict() for p in pii],
        "pii_summary": pii_summary(pii),
        "infrastructure": [i.to_dict() for i in infrastructure],
        "hosts_referenced": sorted(hosts),
        "source_maps": sorted(source_maps),
        "totals": {
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "pii": len(pii),
            "infrastructure": len(infrastructure),
            "hosts_referenced": len(hosts),
        },
    }


def _context(body: str, position: int, *, redact: bool, secret: str | None = None) -> str:
    """A short window around a match, with the secret itself blanked out."""
    start = max(position - CONTEXT_CHARS, 0)
    end = min(position + CONTEXT_CHARS, len(body))
    snippet = " ".join(body[start:end].split())
    if redact and secret:
        snippet = snippet.replace(secret, "[redacted]")
    return snippet[: CONTEXT_CHARS * 2]
