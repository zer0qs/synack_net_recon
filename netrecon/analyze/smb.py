"""SMB analysis: what an SMB stack volunteers before anyone authenticates.

SMB answers a surprising number of questions from an anonymous session: OS
build, machine name, AD domain and forest, the dialects it is willing to speak
and whether it insists those dialects be signed. That makes it the most
productive single source of pivot information on a Windows estate, which is why
``smb.host-information`` is emitted as plain ``info`` rather than suppressed -
operators use it to build the host inventory, not to score a risk.

It is also where two configuration facts an assessor wants on day one live:
SMBv1 still being offered, and message signing being *supported but not
required*. Both are settings, not vulnerabilities, so they are reported as what
the server said and nothing more - no CVEs, no exploitability claims.

Everything here is parsed from NSE output netrecon already collected; this
module opens no sockets. Most ``smb*`` scripts are host-level rather than
port-level in nmap's model, so every lookup goes through
:meth:`ServiceEvidence.script`, which searches host scripts as well.
"""

from __future__ import annotations

import re

from netrecon.analyze.base import Finding, ServiceEvidence

#: nmap service names that mean "this is SMB".
SMB_SERVICE_NAMES: frozenset[str] = frozenset({"microsoft-ds", "netbios-ssn", "smb"})

#: Ports to fall back on when ``-sV`` produced no service name.
SMB_PORTS: frozenset[int] = frozenset({139, 445})

#: ``smb-security-mode`` message_signing values that leave signing unenforced.
#: "supported" is nmap's word for "enabled but not required".
_SIGNING_UNENFORCED: frozenset[str] = frozenset({"disabled", "supported"})

#: Windows releases past end of support, as they appear in an SMB OS string.
#: The qualifier alternation keeps the match anchored to the release token, so
#: "Windows Server 2016 Standard 14393" cannot match on a stray digit.
_EOL_WINDOWS_RE = re.compile(
    r"windows"
    r"(?:\s+(?:server|embedded|storage|small\s+business|web|home|professional|"
    r"enterprise|r2|\(r\)|\(tm\)))*"
    r"\s+(2000|2003|2008|2012|xp|vista|8\.1|7|8)\b",
    re.IGNORECASE,
)

_EOL_WINDOWS_LABELS: dict[str, str] = {
    "2000": "Windows 2000",
    "xp": "Windows XP",
    "2003": "Windows Server 2003",
    "vista": "Windows Vista",
    "2008": "Windows Server 2008 / 2008 R2",
    "7": "Windows 7",
    "8": "Windows 8",
    "8.1": "Windows 8.1",
    "2012": "Windows Server 2012 / 2012 R2",
}

#: smb-os-discovery field name -> key in the finding's ``data``.
_OS_FIELDS: dict[str, str] = {
    "os": "os",
    "os cpe": "os_cpe",
    "computer name": "computer_name",
    "netbios computer name": "netbios_computer_name",
    "domain name": "domain",
    "netbios domain name": "netbios_domain",
    "forest name": "forest",
    "fqdn": "fqdn",
    "workgroup": "workgroup",
    "system time": "system_time",
}

#: Anonymous access values that mean "nothing was readable".
_NO_ACCESS: frozenset[str] = frozenset({"<none>", "none", ""})

#: Field names inside an smb-enum-shares share block, so a field with an empty
#: value (``Path:`` on IPC$) is not mistaken for the next share's header.
_SHARE_FIELD_KEYS: frozenset[str] = frozenset(
    {
        "type",
        "comment",
        "users",
        "max users",
        "path",
        "anonymous access",
        "current user access",
        "warning",
        "note",
        "account_used",
    }
)

#: IPC$ is the named-pipe endpoint, not a file share, and anonymous READ on it
#: is the Windows default. Listing it as an anonymously readable share would
#: bury the shares that actually matter, so it is recorded but does not fire.
_UNINTERESTING_SHARES: frozenset[str] = frozenset({"ipc$"})


def _lines(text: str | None) -> list[str]:
    """NSE output as non-empty lines, with nmap's ``|`` gutter removed.

    Script text normally reaches netrecon from the XML ``output`` attribute,
    which has no gutter, but operators also paste plain nmap stdout into a run
    directory; both shapes are accepted. Indentation is preserved because some
    scripts use it structurally.
    """
    if not text:
        return []
    cleaned: list[str] = []
    for raw in str(text).splitlines():
        line = raw.rstrip()
        gutter = line.lstrip()
        if gutter.startswith("|_"):
            line = gutter[2:]
        elif gutter.startswith("|"):
            line = gutter[1:]
        if line.strip():
            cleaned.append(line)
    return cleaned


_FIELD_RE = re.compile(r"^\s*([^:]+?)\s*:\s*(.*)$")


def _fields(lines: list[str]) -> dict[str, str]:
    """``Key: value`` lines as a lower-cased mapping, first occurrence winning."""
    found: dict[str, str] = {}
    for line in lines:
        match = _FIELD_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        if key and key not in found:
            found[key] = match.group(2).strip()
    return found


def _account_user(account: str | None) -> str | None:
    """The username part of an ``account_used`` value (``DOMAIN\\user``)."""
    if not account:
        return None
    return account.replace("/", "\\").split("\\")[-1].strip().lower() or None


class SmbAnalyzer:
    """Turns smb* NSE output into host facts and signing/dialect findings."""

    name = "smb"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        service = (evidence.service or "").strip().lower()
        if service in SMB_SERVICE_NAMES:
            return True
        # Prefix match, so smb-os-discovery, smb2-time and friends all count;
        # script() searches host scripts too, which is where most of them land.
        if evidence.has_script("smb"):
            return True
        return evidence.port in SMB_PORTS

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._host_information(evidence))
        findings.extend(self._signing(evidence))
        findings.extend(self._dialects(evidence))
        findings.extend(self._shares(evidence))
        findings.extend(self._guest(evidence))
        return findings

    # -- host identity ---------------------------------------------------

    def _host_information(self, evidence: ServiceEvidence) -> list[Finding]:
        """Inventory and pivot data, plus the end-of-support judgement."""
        text = evidence.script("smb-os-discovery")
        if not text:
            return []
        fields = _fields(_lines(text))
        data = {
            key: fields[name] for name, key in _OS_FIELDS.items() if fields.get(name)
        }
        if not data:
            # The script ran but said nothing usable (an error line, say).
            return []

        dialects = _dialects_offered(evidence)
        if dialects:
            data["dialects"] = dialects

        findings = [
            Finding(
                key="smb.host-information",
                title="SMB host information disclosed",
                severity="info",
                summary=_host_summary(data),
                evidence=str(text).strip(),
                recommendation=(
                    "Expected from an SMB server, but confirm that the domain, forest and "
                    "FQDN shown here are in scope before using them as pivot targets."
                ),
                source="smb-os-discovery",
                data=data,
            )
        ]

        outdated = self._outdated_windows(data.get("os"))
        if outdated:
            findings.append(outdated)
        return findings

    def _outdated_windows(self, os_string: str | None) -> Finding | None:
        if not os_string:
            return None
        match = _EOL_WINDOWS_RE.search(os_string)
        if not match:
            return None
        release = _EOL_WINDOWS_LABELS[match.group(1).lower()]
        return Finding(
            key="smb.outdated-windows",
            title=f"SMB host reports {release}",
            severity="low",
            summary=(
                f"The OS string reported over SMB indicates {release}, which is no longer "
                "receiving security updates; confirm against the vendor's lifecycle policy."
            ),
            evidence=f"OS: {os_string}",
            recommendation=(
                "Confirm the build and support status with the asset owner. If it is out of "
                "support, treat it as an upgrade or isolation decision rather than a patch."
            ),
            source="smb-os-discovery",
            data={"os": os_string, "release": release},
        )

    # -- signing ---------------------------------------------------------

    def _signing(self, evidence: ServiceEvidence) -> list[Finding]:
        """One finding covering both the SMBv1 and SMBv2 security-mode shapes.

        Reported together rather than once per script: it is a single server
        setting, and an operator reading the report wants one answer.
        """
        unenforced: list[str] = []
        enforced: list[str] = []
        sources: list[str] = []
        dialects: list[str] = []

        v1_text = evidence.script("smb-security-mode")
        if v1_text:
            signing = _fields(_lines(v1_text)).get("message_signing")
            if signing:
                sources.append("smb-security-mode")
                # Values carry an inline warning, e.g. "disabled (dangerous...)".
                state = signing.split()[0].strip().lower()
                line = f"message_signing: {signing}"
                if state in _SIGNING_UNENFORCED:
                    unenforced.append(line)
                elif state == "required":
                    enforced.append(line)

        v2_text = evidence.script("smb2-security-mode")
        if v2_text:
            current: str | None = None
            for line in _lines(v2_text):
                stripped = line.strip()
                dialect = re.fullmatch(r"(\d+(?:\.\d+)+)\s*:?", stripped)
                if dialect:
                    current = dialect.group(1)
                    continue
                lowered = stripped.lower()
                if "message signing" not in lowered:
                    continue
                if "smb2-security-mode" not in sources:
                    sources.append("smb2-security-mode")
                quoted = f"{current}: {stripped}" if current else stripped
                if "not required" in lowered or "disabled" in lowered:
                    unenforced.append(quoted)
                    if current:
                        dialects.append(current)
                elif "required" in lowered:
                    enforced.append(quoted)

        if not unenforced:
            return []

        data: dict[str, object] = {"observations": unenforced, "sources": sources}
        if dialects:
            data["dialects"] = dialects
        if enforced:
            # Worth keeping: a server can enforce on one dialect and not another.
            data["signing_enforced_on"] = enforced
        return [
            Finding(
                key="smb.signing-not-required",
                title="SMB message signing not required",
                severity="medium",
                summary=(
                    "The server reports that SMB message signing is not required, so a client "
                    "may negotiate an unsigned session. Unsigned sessions are what make "
                    "relaying a captured authentication attempt possible, so an assessor "
                    "should check this against the estate's signing policy today."
                ),
                evidence="\n".join(unenforced),
                recommendation=(
                    "Require SMB signing on servers and clients via policy "
                    "(RequireSecuritySignature), after confirming no legacy client depends "
                    "on unsigned sessions."
                ),
                source=", ".join(sources) or None,
                data=data,
            )
        ]

    # -- dialects --------------------------------------------------------

    def _dialects(self, evidence: ServiceEvidence) -> list[Finding]:
        offered = _dialects_offered(evidence)
        smbv1 = [d for d in offered if _is_smbv1(d)]
        if not smbv1:
            return []
        source = "smb-protocols" if evidence.has_script("smb-protocols") else "smb2-capabilities"
        return [
            Finding(
                key="smb.smbv1-enabled",
                title="SMBv1 dialect offered",
                severity="medium",
                summary=(
                    "The server accepted the SMBv1 dialect (NT LM 0.12). SMBv1 is deprecated "
                    "and cannot be signed or encrypted to the standard the later dialects "
                    "manage, so its presence is worth raising even where nothing uses it."
                ),
                evidence="\n".join(smbv1),
                recommendation=(
                    "Confirm whether any client still needs SMBv1; if not, disable the SMBv1 "
                    "server and client components and re-test."
                ),
                source=source,
                data={"smbv1_dialects": smbv1, "dialects": offered},
            )
        ]

    # -- shares ----------------------------------------------------------

    def _shares(self, evidence: ServiceEvidence) -> list[Finding]:
        """Anonymous share access, when the operator supplied smb-enum-shares.

        smb-enum-shares is in nmap's ``intrusive`` category, which netrecon does
        not run by default, so the usual case here is "no output" - hence the
        quiet return rather than a note about a missing script.
        """
        text = evidence.script("smb-enum-shares")
        if not text:
            return []

        shares = _parse_shares(_lines(text))
        anonymous = {
            name: access
            for name, access in shares.items()
            if access and access.strip().lower() not in _NO_ACCESS
        }
        reportable = {
            name: access
            for name, access in anonymous.items()
            if _share_leaf(name) not in _UNINTERESTING_SHARES
        }
        if not reportable:
            return []

        quoted = "\n".join(
            f"{name}: Anonymous access: {access}" for name, access in reportable.items()
        )
        writable = sorted(
            name for name, access in reportable.items() if "write" in access.lower()
        )
        return [
            Finding(
                key="smb.anonymous-shares",
                title="SMB shares reachable without credentials",
                severity="high",
                summary=(
                    f"{len(reportable)} share(s) reported anonymous access: "
                    + ", ".join(f"{name} ({access})" for name, access in reportable.items())
                    + ". Anything a null session can read should be treated as public."
                ),
                evidence=quoted,
                recommendation=(
                    "Review each share's ACL and remove anonymous/Everyone access. Check what "
                    "is actually stored in them before deciding the impact."
                ),
                source="smb-enum-shares",
                data={
                    "anonymous_shares": reportable,
                    "anonymous_writable": writable,
                    # Every share seen, including the ones that did not fire.
                    "all_shares": shares,
                },
            )
        ]

    # -- guest -----------------------------------------------------------

    def _guest(self, evidence: ServiceEvidence) -> list[Finding]:
        """Guest logons accepted, per whichever script logged in as guest."""
        for script in ("smb-security-mode", "smb-enum-shares", "smb-os-discovery"):
            text = evidence.script(script)
            if not text:
                continue
            account = _fields(_lines(text)).get("account_used")
            if _account_user(account) != "guest":
                continue
            return [
                Finding(
                    key="smb.guest-account",
                    title="SMB guest account accepted",
                    severity="medium",
                    summary=(
                        "The SMB session was established using the guest account, so the "
                        "server accepts guest logons. Guest sessions bypass per-user "
                        "accountability and reach anything granted to Everyone."
                    ),
                    evidence=f"account_used: {account}",
                    recommendation=(
                        "Disable the guest account and deny it network logon, then confirm no "
                        "share relies on guest access."
                    ),
                    source=script,
                    data={"account_used": account},
                )
            ]
        return []


def _dialects_offered(evidence: ServiceEvidence) -> list[str]:
    """Dialects the server accepted, from smb-protocols or smb2-capabilities."""
    offered: list[str] = []

    protocols = evidence.script("smb-protocols")
    if protocols:
        collecting = False
        for line in _lines(protocols):
            stripped = line.strip()
            if stripped.lower().startswith("dialects"):
                collecting = True
                continue
            if not collecting:
                # Some builds emit the list with no "dialects:" header.
                if _is_smbv1(stripped) or re.match(r"^\d+(\.\d+)+", stripped):
                    offered.append(stripped)
                continue
            offered.append(stripped)

    capabilities = evidence.script("smb2-capabilities")
    if capabilities:
        for line in _lines(capabilities):
            match = re.fullmatch(r"(\d+(?:\.\d+)+)\s*:?", line.strip())
            if match and match.group(1) not in offered:
                offered.append(match.group(1))

    # Preserve order but drop duplicates, so the report reads as nmap printed it.
    seen: set[str] = set()
    unique: list[str] = []
    for dialect in offered:
        if dialect not in seen:
            seen.add(dialect)
            unique.append(dialect)
    return unique


def _is_smbv1(dialect: str) -> bool:
    lowered = dialect.lower()
    return "nt lm 0.12" in lowered or "smbv1" in lowered


def _share_leaf(name: str) -> str:
    """``\\\\host\\ADMIN$`` and ``ADMIN$`` both reduce to ``admin$``."""
    return name.replace("/", "\\").split("\\")[-1].strip().lower()


def _parse_shares(lines: list[str]) -> dict[str, str]:
    """Map share name -> reported anonymous access.

    Share blocks are recognised by their header line rather than by indentation,
    because the gutter and indent differ between nmap's XML output attribute and
    its stdout. A header is any line that is not a ``key: value`` pair.
    """
    shares: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        stripped = line.strip()
        match = _FIELD_RE.match(line)
        if match and match.group(2).strip():
            key = match.group(1).strip().lower()
            if key == "anonymous access" and current:
                shares[current] = match.group(2).strip()
            continue
        if match and not match.group(2).strip():
            # "SHARE:" / "\\host\SHARE:" headers, and empty fields like "Path:".
            candidate = match.group(1).strip()
            if candidate.lower() in _SHARE_FIELD_KEYS:
                continue
            current = candidate
            shares.setdefault(current, "")
            continue
        if stripped and ":" not in stripped:
            current = stripped
            shares.setdefault(current, "")
    return shares


def _host_summary(data: dict[str, str]) -> str:
    parts: list[str] = []
    if data.get("os"):
        parts.append(f"OS {data['os']}")
    for label, key in (("computer", "computer_name"), ("domain", "domain"), ("FQDN", "fqdn")):
        if data.get(key):
            parts.append(f"{label} {data[key]}")
    if not parts:
        return "SMB returned host details to an unauthenticated session."
    return "SMB returned host details to an unauthenticated session: " + ", ".join(parts) + "."
