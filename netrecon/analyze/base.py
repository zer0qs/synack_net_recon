"""Shared types for the per-service analyzers.

An analyzer turns evidence netrecon already collected - nmap ``-sV`` service
records and NSE script output - into structured, triageable findings. Analyzers
are **pure functions over data already on disk**: they open no sockets and send
no packets, so running them costs the target nothing and they can be re-run
offline against an old run directory.

The one exception is marked explicitly: :attr:`Analyzer.needs_probe` analyzers
may ask the stage for a single additional connection (TLS certificate reads,
where the information simply is not in the NSE output unless ``--scripts`` ran).
Those are opt-in and rate-limited like every other netrecon request.

Severity is an *exposure* judgement, not a vulnerability rating. "high" means
"an assessor should look at this today", never "exploitable".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

#: Ordered most urgent first; used for sorting and for report styling.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

SEVERITY_ORDER: dict[str, int] = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """One observation about one service.

    ``evidence`` must quote what the tool actually returned, so a reader can
    check the conclusion without re-running the scan. ``recommendation`` is
    advice for the operator, not an action netrecon takes.
    """

    #: Stable identifier, e.g. "tls.expired-certificate".
    key: str
    title: str
    severity: str
    summary: str
    evidence: str | None = None
    recommendation: str | None = None
    #: Where this came from, e.g. "ssl-cert" or "nmap -sV".
    source: str | None = None
    #: Extra structured data for summary.json consumers.
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(
                f"{self.key}: severity {self.severity!r} is not one of "
                + ", ".join(SEVERITIES)
            )

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "source": self.source,
            "data": self.data,
        }


@dataclass
class ServiceEvidence:
    """Everything already known about one open port, handed to analyzers."""

    ip: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    cpes: tuple[str, ...] = ()
    #: NSE script id -> output, for scripts that ran against this port.
    scripts: dict[str, str] = field(default_factory=dict)
    #: Host-level NSE output (smb2-time, smb-os-discovery and friends).
    host_scripts: dict[str, str] = field(default_factory=dict)
    hostnames: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def banner(self) -> str:
        """``product version (extrainfo)``, as a single searchable string."""
        parts = [p for p in (self.product, self.version) if p]
        text = " ".join(parts)
        if self.extrainfo:
            text = f"{text} ({self.extrainfo})" if text else self.extrainfo
        return text or (self.service or "")

    def script(self, *names: str) -> str | None:
        """First matching script output, by exact id then by prefix."""
        for name in names:
            if name in self.scripts:
                return self.scripts[name]
            if name in self.host_scripts:
                return self.host_scripts[name]
        for name in names:
            for source in (self.scripts, self.host_scripts):
                for key, value in source.items():
                    if key.startswith(name):
                        return value
        return None

    def has_script(self, *names: str) -> bool:
        return self.script(*names) is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "tunnel": self.tunnel,
            "cpes": list(self.cpes),
            "scripts": sorted(self.scripts),
        }


class Analyzer(Protocol):
    """Interface every per-service analyzer implements."""

    #: Stable short name, used in config, logs and the report.
    name: str

    #: True when the analyzer may open its own connection (TLS only today).
    needs_probe: bool

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        """Whether this analyzer has anything to say about this port."""
        ...

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        """Produce findings from evidence already collected. No I/O."""
        ...


@dataclass
class AnalyzerResult:
    """Findings for one service, plus which analyzer produced them."""

    analyzer: str
    evidence: ServiceEvidence
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "ip": self.evidence.ip,
            "port": self.evidence.port,
            "protocol": self.evidence.protocol,
            "service": self.evidence.service,
            "banner": self.evidence.banner,
            "findings": [f.to_dict() for f in sort_findings(self.findings)],
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then alphabetically for a stable report."""
    return sorted(findings, key=lambda f: (f.rank, f.key, f.title))


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop repeats of the same key+evidence, keeping the first."""
    seen: set[tuple[str, str | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        identity = (finding.key, finding.evidence)
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(finding)
    return unique


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return {name: count for name, count in counts.items() if count}


def parse_version(text: str | None) -> tuple[int, ...]:
    """Parse a dotted version into comparable integers.

    Returns an empty tuple when nothing numeric is present, so callers can tell
    "no version known" from "version 0".
    """
    if not text:
        return ()
    import re

    match = re.search(r"(\d+(?:\.\d+)*)", str(text))
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def version_below(found: str | None, threshold: str) -> bool:
    """True when *found* parses to a version lower than *threshold*.

    Unknown versions return False: netrecon does not report a finding it cannot
    substantiate from the evidence.
    """
    parsed = parse_version(found)
    if not parsed:
        return False
    target = parse_version(threshold)
    length = max(len(parsed), len(target))
    padded = parsed + (0,) * (length - len(parsed))
    target_padded = target + (0,) * (length - len(target))
    return padded < target_padded
