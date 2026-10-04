"""SSH host key and algorithm hygiene, from NSE output already collected.

``ssh-hostkey`` and ``ssh2-enum-algos`` answer the two questions worth asking
about an SSH listener without touching it again: what key identifies the host,
and which key exchange, cipher and MAC algorithms it is still willing to use.
Both are already on disk after the scripts stage, so this analyzer is pure text
analysis - it opens nothing and sends nothing.

The algorithm findings are deliberately about *what the server offers*, not
about what a client would negotiate. A modern client will pick something strong;
the finding is that a legacy or coerced client does not have to, which is an
exposure an assessor should see, not a demonstrated attack. Nothing here claims
exploitability and nothing here names a CVE: the version-age finding points at
the vendor's advisories instead, because a banner is not a patch level.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netrecon.analyze.base import Finding, ServiceEvidence, version_below

#: Conventional SSH port, used only when the service name says nothing.
SSH_PORT = 22

MIN_RSA_BITS = 2048

#: Exact key exchange names retired by current guidance: both end in SHA-1 over
#: a group a modern client would not accept.
WEAK_KEX: frozenset[str] = frozenset(
    {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"}
)

#: Ciphers named outright; everything in CBC mode is caught by the suffix rule.
WEAK_CIPHER_NAMES: tuple[str, ...] = ("arcfour", "3des-cbc", "des-cbc", "blowfish", "cast128")

#: MACs named outright; every truncated MAC is caught by the "-96" suffix rule.
WEAK_MAC_NAMES: tuple[str, ...] = ("hmac-md5", "hmac-sha1-96", "hmac-md5-96", "umac-64")

#: Host key algorithms that imply a DSA key, which is capped at 1024 bits.
DSA_KEY_NAMES: frozenset[str] = frozenset({"ssh-dss", "dsa", "dss"})

#: The release netrecon compares against for the version-age note. It is a
#: "this is old, go and check" threshold, not a vulnerability boundary.
OPENSSH_REVIEW_VERSION = "8.0"

#: ``2048 f0:58:...:11 (RSA)`` - the fingerprint form varies (hex MD5 or
#: base64 SHA256), so it is captured verbatim rather than validated.
_HOST_KEY_RE = re.compile(r"^(\d+)\s+(\S+)\s+\(([A-Za-z0-9_-]+)\)")

#: ``kex_algorithms (4)`` and its client_to_server/server_to_client variants.
_SECTION_RE = re.compile(r"^([A-Za-z0-9_]+)\s*\((\d+)\)\s*$")


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


@dataclass
class HostKey:
    """One host key as ``ssh-hostkey`` reported it."""

    bits: int | None
    fingerprint: str | None
    key_type: str
    #: The source line, so findings can quote the tool verbatim.
    line: str

    @property
    def normalised_type(self) -> str:
        return self.key_type.strip().lower()

    @property
    def is_dsa(self) -> bool:
        return self.normalised_type in {"dsa", "dss", "ssh-dss"}

    @property
    def is_rsa(self) -> bool:
        return self.normalised_type in {"rsa", "ssh-rsa"}

    @property
    def is_protocol_v1(self) -> bool:
        return self.normalised_type in {"rsa1", "ssh-rsa1"}

    def describe(self) -> str:
        bits = f"{self.bits}-bit " if self.bits else ""
        return f"{bits}{self.key_type.upper()}"


@dataclass
class AlgorithmLists:
    """The algorithm name-lists ``ssh2-enum-algos`` reported, by section."""

    sections: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: Section name -> the header line as printed, for quoting as evidence.
    headers: dict[str, str] = field(default_factory=dict)

    def of_kind(self, kind: str) -> list[tuple[str, str]]:
        """``(section, algorithm)`` pairs for every section matching *kind*.

        Matched by substring because nmap splits a section into
        ``*_client_to_server`` and ``*_server_to_client`` when the two differ.
        """
        found: list[tuple[str, str]] = []
        for section, algorithms in self.sections.items():
            if kind in section:
                found.extend((section, algorithm) for algorithm in algorithms)
        return found

    def quote(self, offenders: list[tuple[str, str]]) -> str:
        """Re-render the offending entries under their own section headers."""
        lines: list[str] = []
        for section in dict.fromkeys(section for section, _ in offenders):
            lines.append(self.headers.get(section, section))
            lines.extend(
                f"    {algorithm}" for sect, algorithm in offenders if sect == section
            )
        return "\n".join(lines)


def parse_host_keys(text: str) -> list[HostKey]:
    """Parse ``ssh-hostkey`` output.

    Full-key and known-hosts comparison lines are skipped rather than guessed
    at: only lines that actually carry ``bits fingerprint (TYPE)`` are used.
    """
    keys: list[HostKey] = []
    for line in _clean_lines(text):
        match = _HOST_KEY_RE.match(line)
        if not match:
            continue
        keys.append(
            HostKey(
                bits=int(match.group(1)),
                fingerprint=match.group(2),
                key_type=match.group(3),
                line=line,
            )
        )
    return keys


def parse_algorithms(text: str) -> AlgorithmLists:
    """Parse ``ssh2-enum-algos`` output into per-section name-lists."""
    sections: dict[str, list[str]] = {}
    headers: dict[str, str] = {}
    current: str | None = None
    for line in _clean_lines(text):
        header = _SECTION_RE.match(line)
        if header:
            current = header.group(1)
            sections.setdefault(current, [])
            headers[current] = line
            continue
        if current is None:
            continue
        # One per line at verbosity >= 1; comma-separated if anything reformats it.
        for chunk in line.split(","):
            algorithm = chunk.strip()
            if algorithm and algorithm not in sections[current]:
                sections[current].append(algorithm)
    return AlgorithmLists(
        sections={name: tuple(values) for name, values in sections.items()},
        headers=headers,
    )


def _is_weak_cipher(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered.endswith("-cbc") or any(bad in lowered for bad in WEAK_CIPHER_NAMES)


def _is_weak_mac(name: str) -> bool:
    lowered = name.strip().lower()
    # A truncated MAC leaves fewer bits to forge against, whatever the digest.
    return lowered.endswith("-96") or any(bad in lowered for bad in WEAK_MAC_NAMES)


def _host_key_findings(evidence: ServiceEvidence, keys: list[HostKey]) -> list[Finding]:
    findings: list[Finding] = []
    for key in keys:
        if key.is_dsa:
            findings.append(
                Finding(
                    key="ssh.weak-host-key",
                    title="SSH host key uses DSA",
                    severity="medium",
                    summary=(
                        f"{evidence.label} presents a {key.describe()} host key. DSA host keys are "
                        "capped at 1024 bits and OpenSSH has removed support for them, so clients "
                        "that still accept this key are running legacy configuration."
                    ),
                    evidence=key.line,
                    recommendation=(
                        "Remove the DSA host key and serve Ed25519 or RSA (>= 2048-bit) only."
                    ),
                    source="ssh-hostkey",
                    data={"key_type": key.key_type, "bits": key.bits},
                )
            )
        elif key.is_rsa and key.bits is not None and key.bits < MIN_RSA_BITS:
            findings.append(
                Finding(
                    key="ssh.weak-host-key",
                    title="SSH host key is a short RSA key",
                    severity="medium",
                    summary=(
                        f"{evidence.label} presents a {key.describe()} host key, below the "
                        f"{MIN_RSA_BITS}-bit minimum current guidance sets for RSA."
                    ),
                    evidence=key.line,
                    recommendation=(
                        f"Regenerate the host key with at least {MIN_RSA_BITS} bits, or use "
                        "Ed25519. Note that clients will see a host key change."
                    ),
                    source="ssh-hostkey",
                    data={"key_type": key.key_type, "bits": key.bits},
                )
            )
    return findings


def _algorithm_findings(evidence: ServiceEvidence, algorithms: AlgorithmLists) -> list[Finding]:
    findings: list[Finding] = []

    weak_kex = [
        (section, algorithm)
        for section, algorithm in algorithms.of_kind("kex_algorithms")
        if algorithm.strip().lower() in WEAK_KEX
    ]
    if weak_kex:
        names = sorted({algorithm for _, algorithm in weak_kex})
        findings.append(
            Finding(
                key="ssh.weak-kex",
                title="SSH offers retired key exchange algorithms",
                severity="medium",
                summary=(
                    f"{evidence.label} still offers {', '.join(names)}. These exchanges rely on "
                    "SHA-1 and small fixed groups, and a client that asks for them will get them."
                ),
                evidence=algorithms.quote(weak_kex),
                recommendation=(
                    "Restrict KexAlgorithms to curve25519-sha256 and the SHA-2 "
                    "group-exchange variants."
                ),
                source="ssh2-enum-algos",
                data={"algorithms": names},
            )
        )

    weak_ciphers = [
        (section, algorithm)
        for section, algorithm in algorithms.of_kind("encryption_algorithms")
        if _is_weak_cipher(algorithm)
    ]
    if weak_ciphers:
        names = sorted({algorithm for _, algorithm in weak_ciphers})
        findings.append(
            Finding(
                key="ssh.weak-cipher",
                title="SSH offers weak or legacy ciphers",
                severity="medium",
                summary=(
                    f"{evidence.label} offers {', '.join(names)}. RC4 and 64-bit block ciphers are "
                    "retired outright, and SSH's CBC modes have a long history of implementation "
                    "problems that the CTR and AEAD modes avoid."
                ),
                evidence=algorithms.quote(weak_ciphers),
                recommendation=(
                    "Restrict Ciphers to the AEAD and CTR suites "
                    "(chacha20-poly1305, aes*-gcm, aes*-ctr)."
                ),
                source="ssh2-enum-algos",
                data={"algorithms": names},
            )
        )

    weak_macs = [
        (section, algorithm)
        for section, algorithm in algorithms.of_kind("mac_algorithms")
        if _is_weak_mac(algorithm)
    ]
    if weak_macs:
        names = sorted({algorithm for _, algorithm in weak_macs})
        findings.append(
            Finding(
                key="ssh.weak-mac",
                title="SSH offers weak or truncated MACs",
                severity="medium",
                summary=(
                    f"{evidence.label} offers {', '.join(names)}. MD5 and truncated MACs leave "
                    "fewer bits of integrity protection than the SHA-2 and encrypt-then-MAC "
                    "alternatives already available."
                ),
                evidence=algorithms.quote(weak_macs),
                recommendation=(
                    "Restrict MACs to the hmac-sha2-*-etm@openssh.com variants."
                ),
                source="ssh2-enum-algos",
                data={"algorithms": names},
            )
        )

    dsa_offered = [
        (section, algorithm)
        for section, algorithm in algorithms.of_kind("server_host_key_algorithms")
        if algorithm.strip().lower() in DSA_KEY_NAMES
    ]
    if dsa_offered:
        findings.append(
            Finding(
                key="ssh.weak-host-key",
                title="SSH offers a DSA host key algorithm",
                severity="medium",
                summary=(
                    f"{evidence.label} advertises {dsa_offered[0][1]} as a host key algorithm. DSA "
                    "host keys are capped at 1024 bits and are no longer supported by current "
                    "OpenSSH clients."
                ),
                evidence=algorithms.quote(dsa_offered),
                recommendation="Remove the DSA host key and serve Ed25519 or RSA (>= 2048-bit).",
                source="ssh2-enum-algos",
                data={"algorithms": sorted({a for _, a in dsa_offered})},
            )
        )

    return findings


def _protocol_v1_findings(evidence: ServiceEvidence, keys: list[HostKey]) -> list[Finding]:
    """SSHv1 support, from whichever of the three sources actually said so."""
    quoted: list[str] = []
    sources: list[str] = []

    sshv1 = evidence.script("sshv1")
    if sshv1 and "sshv1" in sshv1.lower():
        quoted.append(sshv1.strip())
        sources.append("sshv1")

    v1_keys = [key for key in keys if key.is_protocol_v1]
    if v1_keys:
        quoted.extend(key.line for key in v1_keys)
        sources.append("ssh-hostkey")

    # nmap reports "protocol 1.99" for a server that answers both versions.
    extrainfo = (evidence.extrainfo or "").lower()
    if "protocol 1.99" in extrainfo or "protocol 1.5" in extrainfo:
        quoted.append(f"nmap -sV: {evidence.banner}")
        sources.append("nmap -sV")

    if not quoted:
        return []
    return [
        Finding(
            key="ssh.protocol-v1",
            title="SSH protocol version 1 is supported",
            severity="high",
            summary=(
                f"{evidence.label} still answers SSH protocol 1, which has unfixable integrity "
                "weaknesses and was removed from OpenSSH years ago. Its presence usually means "
                "the daemon as a whole is very old."
            ),
            evidence="\n".join(quoted),
            recommendation=(
                "Disable protocol 1 (Protocol 2 only) and plan an upgrade of the daemon."
            ),
            source=", ".join(dict.fromkeys(sources)),
            data={"sources": list(dict.fromkeys(sources))},
        )
    ]


def _version_findings(evidence: ServiceEvidence) -> list[Finding]:
    product = (evidence.product or "").lower()
    if "openssh" not in product:
        return []
    if not version_below(evidence.version, OPENSSH_REVIEW_VERSION):
        return []
    return [
        Finding(
            key="ssh.outdated-openssh",
            title="OpenSSH banner reports an old release",
            severity="low",
            summary=(
                f"{evidence.label} reports {evidence.banner}, which is older than OpenSSH "
                f"{OPENSSH_REVIEW_VERSION}. Review it against the vendor's advisories: the banner "
                "shows the upstream version, not which distribution patches are applied."
            ),
            evidence=f"nmap -sV: {evidence.banner}",
            recommendation=(
                "Confirm the installed package against the vendor's advisories for this release, "
                "and upgrade if it is unpatched."
            ),
            source="nmap -sV",
            data={"product": evidence.product, "version": evidence.version},
        )
    ]


def _host_key_summary(evidence: ServiceEvidence, keys: list[HostKey], raw: str) -> Finding:
    """The always-present record of which keys identify this host."""
    if keys:
        described = ", ".join(key.describe() for key in keys)
        summary = f"{evidence.label} presents {len(keys)} host key(s): {described}."
        quoted = "\n".join(key.line for key in keys)
    else:
        # Output was present but no line parsed; quote it rather than claim anything.
        summary = f"{evidence.label} returned host key output that did not parse into key lines."
        quoted = "\n".join(_clean_lines(raw)[:6])
    return Finding(
        key="ssh.host-key",
        title="SSH host keys",
        severity="info",
        summary=summary,
        evidence=quoted or None,
        source="ssh-hostkey",
        data={
            "keys": [
                {"type": key.key_type, "bits": key.bits, "fingerprint": key.fingerprint}
                for key in keys
            ]
        },
    )


class SshAnalyzer:
    """Host key and algorithm findings for one SSH port."""

    name = "ssh"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        service = (evidence.service or "").strip().lower()
        if service == "ssh" or service.endswith("/ssh"):
            return True
        if any(name.startswith(("ssh-", "ssh2-", "sshv1")) for name in evidence.scripts):
            return True
        return evidence.port == SSH_PORT

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        findings: list[Finding] = []

        host_key_output = evidence.script("ssh-hostkey")
        keys = parse_host_keys(host_key_output) if host_key_output else []
        findings.extend(_host_key_findings(evidence, keys))

        algos_output = evidence.script("ssh2-enum-algos")
        if algos_output:
            findings.extend(_algorithm_findings(evidence, parse_algorithms(algos_output)))

        findings.extend(_protocol_v1_findings(evidence, keys))
        findings.extend(_version_findings(evidence))

        if host_key_output:
            findings.append(_host_key_summary(evidence, keys, host_key_output))
        return findings
