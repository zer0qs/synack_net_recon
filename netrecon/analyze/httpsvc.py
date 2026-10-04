"""HTTP analyzer for evidence netrecon already collected.

This analyzer reads ``nmap -sV`` fields and NSE script output for web ports and
turns them into findings. It deliberately does **not** crawl: the live GET-only
requesting lives in the web recon stage, which is opt-in behind ``--web``. So
this module runs on every scan, costs the target nothing, and still works when
replaying an old run directory offline.

Division of labour with the web stage: that stage owns anything that needs a
response in hand (missing security headers, JavaScript analysis, robots
contents). Here the same NSE text is parsed for *exposures* - writable methods,
an exposed repository, a leaked backup, an open proxy - plus the technology
stack, which is shared with the web stage through
:mod:`netrecon.analyze.techstack` so both report it in one shape.

Severity is an exposure judgement. "high" means an assessor should look today,
never "exploitable".
"""

from __future__ import annotations

import re

from netrecon.analyze import techstack
from netrecon.analyze.base import Finding, ServiceEvidence, parse_version
from netrecon.report.categories import is_web_service

#: Methods whose presence is worth a finding. GET/HEAD/POST/OPTIONS are normal.
DANGEROUS_METHODS: tuple[str, ...] = ("PUT", "DELETE", "TRACE", "CONNECT")

#: What each dangerous method would mean if it really is enabled.
_METHOD_RISK: dict[str, str] = {
    "PUT": "may allow writing files to the server",
    "DELETE": "may allow removing server-side resources",
    "TRACE": "reflects the request back, which assists request-smuggling and XST work",
    "CONNECT": "may let the server be used to tunnel to other hosts",
}

#: NSE output that means http-git actually found a repository, rather than just
#: running. The script prints nothing at all when it finds nothing.
_GIT_FOUND = re.compile(
    r"repositor(?:y|ies)\s+found|git\s+repository|\.git/(?:HEAD|config|index)\b",
    re.IGNORECASE,
)

#: Lines in NSE output that report a failure, not a finding.
_NEGATIVE_LINE = re.compile(
    r"ERROR|couldn't|could not|no .*found|nothing found|not vulnerable|timeout",
    re.IGNORECASE,
)

_PATH_LIKE = re.compile(r"(/[\w.~/@%+-]{1,160})")


def _lines(text: str | None) -> list[str]:
    """NSE output as clean lines, with nmap's leading pipes stripped."""
    if not text:
        return []
    out: list[str] = []
    for raw in str(text).splitlines():
        line = raw.strip()
        line = re.sub(r"^[|_\s]+", "", line).strip()
        if line:
            out.append(line)
    return out


def parse_methods(text: str | None) -> set[str]:
    """HTTP methods named in ``http-methods`` output.

    Only the method-listing lines are read, so a URL or a header name elsewhere
    in the output cannot be mistaken for a supported method.
    """
    methods: set[str] = set()
    for line in _lines(text):
        if "method" not in line.lower():
            continue
        _, _, listed = line.partition(":")
        for token in re.split(r"[\s,]+", listed.strip()):
            if re.fullmatch(r"[A-Z][A-Z_-]{2,19}", token or ""):
                methods.add(token)
    return methods


def dangerous_methods(text: str | None) -> list[str]:
    found = parse_methods(text)
    return [method for method in DANGEROUS_METHODS if method in found]


def git_repository_found(text: str | None) -> bool:
    """True only when ``http-git`` positively reports a repository."""
    if not text:
        return False
    return bool(_GIT_FOUND.search(text))


def config_backups(text: str | None) -> list[str]:
    """Paths ``http-config-backup`` reported as retrievable."""
    found: list[str] = []
    for line in _lines(text):
        if _NEGATIVE_LINE.search(line):
            continue
        for path in _PATH_LIKE.findall(line):
            if path not in found:
                found.append(path)
    return found


def open_proxy(text: str | None) -> bool:
    """True only when ``http-open-proxy`` says the proxy is open.

    The script also prints when a proxy merely redirects, which is not the same
    thing, so the negative phrasings are checked first.
    """
    if not text:
        return False
    lowered = " ".join(str(text).lower().split())
    if "not an open proxy" in lowered or "proxy might be redirecting" in lowered:
        return False
    return "open proxy" in lowered


def security_headers_reported(text: str | None) -> list[str]:
    """Header names ``http-security-headers`` mentioned, for context."""
    names: list[str] = []
    for line in _lines(text):
        # The script heads each section with the header name, writing it either
        # with hyphens or (older output) with underscores.
        match = re.match(r"([A-Za-z][A-Za-z0-9_-]{3,48}):", line)
        if match and re.search(r"[-_]", match.group(1)):
            name = match.group(1).lower().replace("_", "-")
            if name not in names:
                names.append(name)
    return names


def robots_paths(text: str | None) -> list[str]:
    """Disallowed paths from ``http-robots.txt`` output."""
    paths: list[str] = []
    for line in _lines(text):
        for path in _PATH_LIKE.findall(line):
            if path not in paths:
                paths.append(path)
    return paths


def page_title(text: str | None) -> str | None:
    """The page title from ``http-title`` output, when it found one."""
    for line in _lines(text):
        if re.search(r"did ?n[o']t|site doesn't have a title", line, re.IGNORECASE):
            return None
        if line.lower().startswith("requested resource was"):
            continue
        return line[:200]
    return None


def server_header(evidence: ServiceEvidence) -> tuple[str | None, str]:
    """The Server header value and where it came from.

    ``http-server-header`` is the direct quote. Failing that, nmap's ``-sV``
    product/version for an HTTP service is itself derived from that header, so it
    is used as a second-hand but honest substitute - and labelled as such.
    """
    value = evidence.script("http-server-header")
    if value:
        cleaned = " ".join(_lines(value))
        if cleaned:
            return (cleaned[:200], "http-server-header")
    if evidence.product:
        banner = evidence.banner
        return (banner or None, "nmap -sV")
    return (None, "")


class HttpServiceAnalyzer:
    """Findings for HTTP(S) ports from -sV and NSE evidence. Opens nothing."""

    name = "http"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        return is_web_service(evidence.service, evidence.port, evidence.tunnel)

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(self._method_findings(evidence))
        findings.extend(self._exposure_findings(evidence))
        findings.extend(self._technology_findings(evidence))
        findings.extend(self._disclosure_findings(evidence))
        return findings

    # -- methods ---------------------------------------------------------

    def _method_findings(self, evidence: ServiceEvidence) -> list[Finding]:
        output = evidence.script("http-methods")
        risky = dangerous_methods(output)
        if not risky:
            return []
        detail = "; ".join(f"{method} {_METHOD_RISK[method]}" for method in risky)
        return [
            Finding(
                key="http.dangerous-methods",
                title="Server advertises write or diagnostic HTTP methods",
                severity="medium",
                summary=(
                    f"{evidence.label} lists {', '.join(risky)} among its supported methods. "
                    f"{detail}. nmap read this from an OPTIONS response: netrecon did not "
                    f"send any of these methods, so whether they are actually permitted on a "
                    f"given path is unconfirmed."
                ),
                evidence=(output or "").strip()[:600] or None,
                recommendation=(
                    "Confirm by hand which paths honour these methods, then disable the ones "
                    "the application does not need (TRACE and CONNECT in particular, and WebDAV "
                    "verbs on anything not serving WebDAV)."
                ),
                source="http-methods",
                data={"methods": risky, "all_methods": sorted(parse_methods(output))},
            )
        ]

    # -- exposed artefacts -----------------------------------------------

    def _exposure_findings(self, evidence: ServiceEvidence) -> list[Finding]:
        findings: list[Finding] = []

        git_output = evidence.script("http-git")
        if git_repository_found(git_output):
            findings.append(
                Finding(
                    key="http.git-exposed",
                    title="Git repository exposed over HTTP",
                    severity="high",
                    summary=(
                        f"A .git directory is reachable on {evidence.label}. An exposed "
                        f"repository usually yields full source, configuration and commit "
                        f"history, including secrets removed in later commits."
                    ),
                    evidence=(git_output or "").strip()[:600] or None,
                    recommendation=(
                        "Block or remove the .git directory from the web root and rotate any "
                        "credential that was ever committed. Review the repository contents "
                        "manually to establish what was disclosed."
                    ),
                    source="http-git",
                )
            )

        backup_output = evidence.script("http-config-backup")
        backups = config_backups(backup_output)
        if backups:
            findings.append(
                Finding(
                    key="http.config-backup-exposed",
                    title="Configuration or editor backup files retrievable",
                    severity="high",
                    summary=(
                        f"{len(backups)} backup or editor temporary file(s) are retrievable on "
                        f"{evidence.label}. These commonly contain database credentials and "
                        f"application secrets in clear text, and are served as plain text "
                        f"rather than executed."
                    ),
                    evidence=(backup_output or "").strip()[:600] or None,
                    recommendation=(
                        "Remove the files from the document root, deny the extensions at the "
                        "web server, and rotate any credential they contain. Retrieve and "
                        "review each file to record what was exposed."
                    ),
                    source="http-config-backup",
                    data={"paths": backups[:50]},
                )
            )

        proxy_output = evidence.script("http-open-proxy")
        if open_proxy(proxy_output):
            findings.append(
                Finding(
                    key="http.open-proxy",
                    title="HTTP service appears to be an open proxy",
                    severity="high",
                    summary=(
                        f"{evidence.label} relayed a proxied request during nmap's check. An "
                        f"open proxy lets a third party reach internal addresses through this "
                        f"host and attribute outbound traffic to it."
                    ),
                    evidence=(proxy_output or "").strip()[:600] or None,
                    recommendation=(
                        "Restrict the proxy to the networks that need it, or disable forward "
                        "proxying. Re-test from outside the perimeter to confirm the exposure "
                        "and check logs for existing abuse."
                    ),
                    source="http-open-proxy",
                )
            )

        return findings

    # -- technology stack ------------------------------------------------

    def _technology_findings(self, evidence: ServiceEvidence) -> list[Finding]:
        detected = list(techstack.detect_from_service(evidence))

        # The NSE scripts quote the same headers the web stage would read, so the
        # header detectors are reused rather than reimplemented here.
        pseudo_headers: dict[str, str] = {}
        value, _origin = server_header(evidence)
        if value and evidence.script("http-server-header"):
            pseudo_headers["server"] = value
        generator = evidence.script("http-generator")
        if generator:
            joined = " ".join(_lines(generator))
            if joined:
                pseudo_headers["x-generator"] = joined[:200]
        if pseudo_headers:
            detected.extend(techstack.detect_from_headers(pseudo_headers))

        merged = techstack.merge(detected)
        if not merged:
            return []

        title = page_title(evidence.script("http-title"))
        labels = [tech.label for tech in merged]
        return [
            Finding(
                key="http.technology",
                title="Technology stack identified: " + ", ".join(labels[:6]),
                severity="info",
                summary=(
                    f"{evidence.label} discloses {len(merged)} component(s): "
                    f"{', '.join(labels)}. Fingerprints come from banners the service "
                    f"published itself, so each carries a confidence; they are not a "
                    f"statement about what is installed, and a version here is a lead for "
                    f"correlation, not a vulnerability."
                ),
                evidence="; ".join(
                    f"{tech.name}: {tech.source}={tech.evidence}" for tech in merged[:10]
                )
                or None,
                recommendation=(
                    "Confirm versions from the host itself before relying on them, and reduce "
                    "what the service volunteers about its build."
                ),
                source="nmap -sV / NSE",
                data={
                    "technologies": [tech.to_dict() for tech in merged],
                    "count": len(merged),
                    "with_version": sum(1 for tech in merged if tech.version),
                    "page_title": title,
                    "security_headers_reported": security_headers_reported(
                        evidence.script("http-security-headers")
                    ),
                    "robots_paths": robots_paths(evidence.script("http-robots.txt"))[:25],
                },
            )
        ]

    # -- version disclosure ----------------------------------------------

    def _disclosure_findings(self, evidence: ServiceEvidence) -> list[Finding]:
        value, origin = server_header(evidence)
        if not value or not parse_version(value):
            return []
        return [
            Finding(
                key="http.server-version-disclosed",
                title="Server header discloses software version",
                severity="low",
                summary=(
                    f"{evidence.label} returns a Server banner naming its software and "
                    f"version ({value}). That hands an attacker the version-matching step "
                    f"for free; it is not itself a vulnerability."
                ),
                evidence=f"{origin}: {value}",
                recommendation=(
                    "Suppress the version token in the Server header (for example "
                    "nginx 'server_tokens off', Apache 'ServerTokens Prod'). Patch level "
                    "still has to be managed; hiding the banner only removes the shortcut."
                ),
                source=origin,
                data={"server": value},
            )
        ]
