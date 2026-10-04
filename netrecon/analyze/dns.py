"""DNS analysis: what a nameserver hands out before anyone authenticates.

Two things on a DNS listener matter during an engagement. First, whether the
server recurses for an arbitrary querier: an open resolver leaks what the
organisation looks up *and* lets unrelated third parties use the host as a
reflection and amplification source, so it is a finding about other people's
networks as much as this one. Second, how much the server volunteers about
itself - ``version.bind``, NSID and SRV/service-discovery answers are free
software inventory and internal topology.

Everything below is read out of NSE output nmap already produced: no queries
are sent from here. Where the script output does not support a conclusion, no
finding is produced - a silent analyzer is more useful than a guessed one.
"""

from __future__ import annotations

import re
from typing import Any

from netrecon.analyze.base import Finding, ServiceEvidence

#: nmap service names for a DNS listener.
DNS_SERVICE_NAMES: frozenset[str] = frozenset({"domain", "dns"})

DNS_PORTS: frozenset[int] = frozenset({53})

#: Cap on records copied into ``data``; the full output stays in scripts.json.
MAX_RECORDS = 50

# dns-recursion emits this one sentence, and only when a recursive query sent
# from the scanning host was actually answered.
_RECURSION_ENABLED = re.compile(r"recursion\s+appears\s+to\s+be\s+enabled", re.IGNORECASE)

# "10 of 100 tested domains are cached." - the leading count is what decides
# whether snooping actually returned anything.
_CACHE_SNOOP_COUNT = re.compile(
    r"(\d+)\s+of\s+(\d+)\s+tested\s+domains\s+are\s+cached", re.IGNORECASE
)

# "548/tcp afpovertcp" (service discovery) and "3268/tcp 0 100 host" (SRV).
_RECORD_LINE = re.compile(r"^\d{1,5}/(?:tcp|udp)\b")

# dns-nsid uses "bind.version: 9.7.3-P3" but "NSID host (hexhex)".
_NSID_FIELD = re.compile(
    r"^(id\.server|bind\.version|version\.bind|NSID)\s*(?::|\s)\s*(.+)$", re.IGNORECASE
)


class DnsAnalyzer:
    """Findings from ``dns-*`` NSE output and the ``-sV`` banner."""

    name = "dns"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        service = (evidence.service or "").strip().lower()
        if service in DNS_SERVICE_NAMES:
            return True
        if _ran_dns_script(evidence):
            return True
        return evidence.port in DNS_PORTS and evidence.protocol.strip().lower() in {"tcp", "udp"}

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        nsid = _parse_nsid(evidence.script("dns-nsid"))
        findings: list[Finding] = []
        findings.extend(_recursion_findings(evidence))
        findings.extend(_version_findings(nsid))
        findings.extend(_cache_snoop_findings(evidence))
        findings.extend(_service_record_findings(evidence))
        findings.extend(_server_findings(evidence, nsid))
        return findings


# -- individual findings -------------------------------------------------


def _recursion_findings(evidence: ServiceEvidence) -> list[Finding]:
    output = evidence.script("dns-recursion")
    if not output or not _RECURSION_ENABLED.search(output):
        return []
    return [
        Finding(
            key="dns.open-recursion",
            title="DNS recursion enabled for an arbitrary querier",
            severity="high",
            summary=(
                "The server answered a recursive query from the scanning host, so it "
                "resolves names for clients it has no relationship with. Two consequences "
                "an assessor should look at today: the cache is readable by anyone, which "
                "leaks the names this organisation looks up, and the host can be used by "
                "third parties as a DNS reflection and amplification source against "
                "targets of their choosing."
            ),
            evidence=_first_lines(output, 3),
            recommendation=(
                "Restrict recursion to known client networks (BIND allow-recursion and "
                "views, unbound access-control, 'disable recursion' on Windows DNS) and "
                "keep internet-facing authoritative service separate from the resolver. "
                "Where a resolver must stay reachable, add response rate limiting."
            ),
            source="dns-recursion",
        )
    ]


def _version_findings(nsid: dict[str, str]) -> list[Finding]:
    """Low: the server names its own software and version to any querier."""
    version = nsid.get("bind.version")
    if not version:
        return []
    quoted = [f"bind.version: {version}"]
    if nsid.get("id.server"):
        quoted.append(f"id.server: {nsid['id.server']}")
    if nsid.get("nsid"):
        quoted.append(f"NSID {nsid['nsid']}")
    return [
        Finding(
            key="dns.version-disclosed",
            title="DNS server discloses its software version",
            severity="low",
            summary=(
                "The server answered a version.bind/NSID query with its software and "
                "version string. That is not itself a weakness, but it tells an attacker "
                "which advisories to read before touching the host."
            ),
            evidence="\n".join(quoted),
            recommendation=(
                "Suppress the version response where the software allows it (BIND "
                "'version none;', unbound hide-version) and review the disclosed version "
                "against vendor advisories for this product."
            ),
            source="dns-nsid",
            data={key: value for key, value in nsid.items() if value},
        )
    ]


def _cache_snoop_findings(evidence: ServiceEvidence) -> list[Finding]:
    output = evidence.script("dns-cache-snoop")
    if not output:
        return []
    match = _CACHE_SNOOP_COUNT.search(output)
    if not match:
        # An error line ("not a known mode") or anything we cannot read as a
        # result count proves nothing, so say nothing.
        return []
    cached = int(match.group(1))
    if cached <= 0:
        return []
    domains = _snooped_domains(output)
    return [
        Finding(
            key="dns.cache-snooping",
            title="DNS cache contents readable (cache snooping)",
            severity="medium",
            summary=(
                f"The server confirmed {cached} of {match.group(2)} tested names as present "
                "in its cache, so an unauthenticated querier can read which external "
                "services the hosts behind this resolver have been talking to - cloud "
                "tenants, vendors, security products and remote-access endpoints included."
            ),
            evidence=_quote(
                [match.group(0).strip(), *domains],
                8,
            ),
            recommendation=(
                "Limit who may query the resolver at all (allow-query / access-control, "
                "or a firewall in front of it); cache snooping follows from the resolver "
                "being reachable by untrusted sources."
            ),
            source="dns-cache-snoop",
            data={
                "cached_count": cached,
                "tested_count": int(match.group(2)),
                "cached_domains": domains[:MAX_RECORDS],
            },
        )
    ]


def _service_record_findings(evidence: ServiceEvidence) -> list[Finding]:
    """Info: SRV and DNS-SD answers, which map internal services for free."""
    records: list[str] = []
    sources: list[str] = []
    for script_id in ("dns-srv-enum", "dns-service-discovery"):
        output = evidence.script(script_id)
        if not output:
            continue
        found = _record_lines(output)
        if found:
            sources.append(script_id)
            records.extend(found)
    if not records:
        return []
    capped = records[:MAX_RECORDS]
    return [
        Finding(
            key="dns.service-records",
            title="Service records enumerable over DNS",
            severity="info",
            summary=(
                f"{len(records)} service record(s) were returned, naming hosts, ports and "
                "roles (domain controllers, Kerberos, LDAP, SIP and similar). Useful as a "
                "target list for the rest of the engagement; expected on an internal "
                "network, worth questioning on an internet-facing server."
            ),
            evidence=_quote(capped, 8),
            recommendation=(
                "Confirm these records are meant to be visible to the querying network, "
                "and that nothing internal is published in an external zone."
            ),
            source=", ".join(sources),
            data={
                "records": capped,
                "record_count": len(records),
                "truncated": len(records) > len(capped),
            },
        )
    ]


def _server_findings(evidence: ServiceEvidence, nsid: dict[str, str]) -> list[Finding]:
    """Info: the identified software, for inventory and advisory review."""
    product = (evidence.product or "").strip()
    version = (evidence.version or "").strip()
    bind_version = nsid.get("bind.version", "")
    if not (product or version or bind_version):
        return []
    identity = " ".join(part for part in (product, version) if part) or bind_version
    from_banner = bool(product or version)
    data: dict[str, Any] = {
        "software": product or None,
        "version": version or bind_version or None,
        "id_server": nsid.get("id.server") or None,
        "nsid": nsid.get("nsid") or None,
        "hostnames": list(evidence.hostnames) or None,
    }
    return [
        Finding(
            key="dns.server",
            title=f"DNS server identified: {identity}",
            severity="info",
            summary=(
                "Recorded for inventory. Treat the version as a pointer, not a "
                "vulnerability: review it against vendor advisories for this product "
                "rather than assuming anything is exploitable."
            ),
            evidence=identity if from_banner else f"bind.version: {bind_version}",
            recommendation=(
                "Check the running version against the vendor's supported releases and "
                "advisories for this product."
            ),
            source="nmap -sV" if from_banner else "dns-nsid",
            data={key: value for key, value in data.items() if value},
        )
    ]


# -- parsing -------------------------------------------------------------


def _ran_dns_script(evidence: ServiceEvidence) -> bool:
    return any(
        key.lower().startswith("dns-")
        for key in (*evidence.scripts, *evidence.host_scripts)
    )


def _parse_nsid(output: str | None) -> dict[str, str]:
    """Pull the three fields dns-nsid reports, under stable key names."""
    fields: dict[str, str] = {}
    if not output:
        return fields
    for raw in output.splitlines():
        match = _NSID_FIELD.match(raw.strip())
        if not match:
            continue
        name = match.group(1).lower()
        value = match.group(2).strip()
        if not value:
            continue
        if name == "nsid":
            # "dns.example.com (646E73...)" - the readable half is enough.
            fields.setdefault("nsid", value.split(" (")[0].strip())
        elif name == "version.bind":
            fields.setdefault("bind.version", value)
        else:
            fields.setdefault(name, value)
    return fields


def _snooped_domains(output: str) -> list[str]:
    """The cached names dns-cache-snoop listed under its count line."""
    domains: list[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or _CACHE_SNOOP_COUNT.search(line):
            continue
        # One bare hostname per line; anything with whitespace is prose.
        if " " in line or "." not in line:
            continue
        domains.append(line)
    return domains


def _record_lines(output: str) -> list[str]:
    """Record lines, each prefixed with the group heading it appeared under."""
    records: list[str] = []
    heading: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _RECORD_LINE.match(line):
            records.append(f"{heading}: {line}" if heading else line)
            continue
        lowered = line.lower()
        if lowered.startswith("service") and "host" in lowered:
            # dns-srv-enum column header, not a group name.
            continue
        if "=" in line or ":" in line:
            # A per-record attribute (DNS-SD TXT data), not a group name.
            continue
        heading = line
    return records


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
