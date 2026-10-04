"""Database analysis: who can reach the data store, and what it tells them.

A database engine listening where the scanner can see it is the finding that
matters most often on an internal engagement, and it is almost always a
segmentation mistake rather than a software flaw. So this module reports two
different things and keeps them apart:

* **Reachability.** ``database.exposed`` fires for every database netrecon
  identified. It claims nothing beyond "this answered from where we scanned",
  which is exactly the fact a reviewer needs to decide whether the network path
  should exist at all.
* **Authentication.** ``database.no-authentication`` is reserved for the case
  where the engine actually handed over its own contents to an
  unauthenticated query - a database listing, a server-status dump, a CouchDB
  "admin party" admission. An open port proves nothing about authentication, so
  a port with no supporting output never produces this finding. That restraint
  is the point: a false "critical" costs an operator more than a missed one.

Version findings are deliberately dull. netrecon compares against conservative
thresholds and says "older than X; review against vendor advisories". It never
cites a CVE and never claims exploitability - version strings are routinely
backported, wrapped by distributions, or simply wrong.

Everything is parsed from ``nmap -sV`` records and NSE output netrecon already
collected. No sockets, no subprocesses, no file access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from netrecon.analyze.base import Finding, ServiceEvidence, version_below

#: How many database names to carry in a finding's ``data``; the full list stays
#: in the quoted evidence, so nothing is lost, and the report stays readable.
MAX_NAMES = 50


@dataclass(frozen=True)
class _Engine:
    """One database engine netrecon recognises."""

    key: str
    label: str
    #: nmap service names.
    services: frozenset[str]
    #: Fallback ports, used only when the name and product say nothing.
    ports: frozenset[int]
    #: Lower-cased substrings of the ``-sV`` product string.
    aliases: frozenset[str] = frozenset()
    #: Conservative "older than this deserves a look" version. Not a CVE claim.
    threshold: str | None = None


#: Engines in report order. Thresholds are deliberately behind the current
#: release: the question they raise is "is this still supported?", not "is this
#: vulnerable?".
ENGINES: tuple[_Engine, ...] = (
    _Engine(
        "mysql",
        "MySQL",
        frozenset({"mysql"}),
        frozenset({3306, 3307}),
        frozenset({"mysql", "percona"}),
        "5.7",
    ),
    _Engine(
        "mssql",
        "Microsoft SQL Server",
        frozenset({"ms-sql-s", "ms-sql", "ms-sql-m"}),
        frozenset({1433}),
        frozenset({"microsoft sql server"}),
        "13.0",
    ),
    _Engine(
        "postgresql",
        "PostgreSQL",
        frozenset({"postgresql", "postgres"}),
        frozenset({5432}),
        frozenset({"postgresql"}),
        "11",
    ),
    _Engine(
        "oracle",
        "Oracle Database",
        frozenset({"oracle-tns", "oracle"}),
        frozenset({1521}),
        frozenset({"oracle database", "oracle tns"}),
        "19",
    ),
    _Engine(
        "mongodb",
        "MongoDB",
        frozenset({"mongodb", "mongod"}),
        frozenset({27017, 27018}),
        frozenset({"mongodb"}),
        "4.4",
    ),
    _Engine(
        "redis",
        "Redis",
        frozenset({"redis"}),
        frozenset({6379}),
        frozenset({"redis"}),
        "6.0",
    ),
    _Engine(
        "elasticsearch",
        "Elasticsearch",
        frozenset({"elasticsearch"}),
        frozenset({9200, 9300}),
        # Specific, so Kibana on an adjacent port is not called a database.
        frozenset({"elasticsearch rest api", "elasticsearch binary api"}),
        "7.0",
    ),
    _Engine(
        "cassandra",
        "Apache Cassandra",
        frozenset({"cassandra"}),
        # 9042 is the native protocol; 9160 is the Thrift port cassandra-info uses.
        frozenset({9042, 9160}),
        frozenset({"cassandra"}),
        "3.11",
    ),
    _Engine(
        "couchdb",
        "Apache CouchDB",
        frozenset({"couchdb"}),
        frozenset({5984}),
        frozenset({"couchdb"}),
        "3.0",
    ),
    _Engine(
        "memcached",
        "memcached",
        frozenset({"memcached", "memcache"}),
        frozenset({11211}),
        frozenset({"memcached"}),
        None,
    ),
    _Engine(
        "db2",
        "IBM Db2",
        frozenset({"db2", "ibm-db2", "drda"}),
        # 50000 is the default instance port; 523 is the DAS that db2-das-info reads.
        frozenset({50000, 523}),
        frozenset({"db2"}),
        None,
    ),
)

#: MariaDB ships its own version line under the ``mysql`` service name, and its
#: numbering is unrelated to MySQL's, so it gets its own threshold and label.
_MARIADB_THRESHOLD = "10.4"

#: Service names that veto the port fallback. Ports like 50000 and 9200 are used
#: by plenty of non-database software, and a wrong label in a report is worse
#: than no label - the product string still rescues the real engines.
_NON_DATABASE_SERVICES: frozenset[str] = frozenset(
    {
        "http",
        "https",
        "http-alt",
        "http-proxy",
        "https-alt",
        "ssh",
        "smtp",
        "telnet",
        "ftp",
        "domain",
        "ldap",
        "snmp",
        "vnc",
        "ms-wbt-server",
        "microsoft-ds",
        "netbios-ssn",
        "sip",
        "rtsp",
    }
)

#: Tokens that mean the engine refused the query. Their presence is why a script
#: "running" is never on its own treated as evidence of missing authentication.
_DENIED_RE = re.compile(
    r"not\s+authori[sz]ed|unauthori[sz]ed|authentication\s+required|requires?\s+authentication"
    r"|auth(?:entication)?\s+failed|operation\s+not\s+permitted|\bNOAUTH\b|access\s+denied"
    r"|permission\s+denied|login\s+failed|command\s+not\s+allowed|errmsg",
    re.IGNORECASE,
)

#: stdnse.format_output(false, ...) renders script failures with this prefix.
_SCRIPT_ERROR_RE = re.compile(r"^\s*ERROR\s*:", re.IGNORECASE | re.MULTILINE)

_FIELD_RE = re.compile(r"^\s*([^:=]+?)\s*:\s*(.*)$")
_ASSIGN_RE = re.compile(r"^\s*([^:=]+?)\s*=\s*(.*)$")
#: redis-info aligns its values with runs of spaces instead of a separator.
_COLUMN_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 ()/_-]*?)\s{2,}(\S.*)$")


def _lines(text: str | None) -> list[str]:
    """NSE output as non-empty lines, with nmap's ``|`` gutter removed.

    Output normally arrives from the XML ``output`` attribute, which carries no
    gutter, but operators also drop plain nmap stdout into a run directory.
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


def _pairs(lines: list[str], pattern: re.Pattern[str]) -> dict[str, str]:
    """``key: value`` or ``key = value`` lines, lower-cased, first one winning."""
    found: dict[str, str] = {}
    for line in lines:
        match = pattern.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key and key not in found:
            found[key] = value
    return found


def _excerpt(text: str, limit: int = 12) -> str:
    """The first *limit* lines of script output, for quoting as evidence."""
    lines = _lines(text)
    body = "\n".join(line.strip() for line in lines[:limit])
    if len(lines) > limit:
        body += f"\n... ({len(lines) - limit} further line(s))"
    return body


def _denied(text: str) -> bool:
    return bool(_DENIED_RE.search(text) or _SCRIPT_ERROR_RE.search(text))


def _banner_line(evidence: ServiceEvidence) -> str:
    service = evidence.service or "unknown"
    return (
        f"nmap -sV: {evidence.port}/{evidence.protocol} open {service} "
        f"{evidence.banner}".rstrip()
    )


def _is_tls(evidence: ServiceEvidence) -> bool:
    if (evidence.tunnel or "").strip().lower() in {"ssl", "tls"}:
        return True
    service = (evidence.service or "").strip().lower()
    return service.startswith("ssl/") or service in {"https", "https-alt"}


@dataclass
class _Observations:
    """What the parsers extracted, before any of it becomes a finding."""

    version: str | None = None
    version_evidence: str | None = None
    version_source: str | None = None
    product: str | None = None
    names: list[str] = field(default_factory=list)
    names_source: str | None = None
    names_evidence: str | None = None
    #: ``(source, quoted evidence)`` showing the engine served data unauthenticated.
    no_auth: list[tuple[str, str]] = field(default_factory=list)
    #: ``(source, quoted evidence)`` showing it demanded credentials.
    auth_required: list[tuple[str, str]] = field(default_factory=list)
    #: ``(source, quoted evidence)`` showing a successful cleartext exchange.
    cleartext: list[tuple[str, str]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def set_version(self, version: str | None, quoted: str, source: str) -> None:
        """First parser to find a version wins; script output is tried first."""
        if version and not self.version:
            self.version = version
            self.version_evidence = quoted
            self.version_source = source

    def set_names(self, names: list[str], quoted: str, source: str) -> None:
        if names and not self.names:
            self.names = names
            self.names_evidence = quoted
            self.names_source = source


def _parse_mysql_info(text: str, obs: _Observations) -> None:
    fields = _pairs(_lines(text), _FIELD_RE)
    version = fields.get("version")
    if version:
        obs.set_version(version, f"Version: {version}", "mysql-info")
    capabilities = fields.get("some capabilities")
    if capabilities:
        # The handshake advertises SwitchToSSLAfterHandshake when TLS is offered;
        # its absence from the server's own capability list is the evidence.
        if "ssl" not in capabilities.lower():
            obs.cleartext.append(
                (
                    "mysql-info",
                    f"Some Capabilities: {capabilities}"
                    " (no SSL capability advertised in the server handshake)",
                )
            )
    if fields.get("protocol"):
        obs.extra["mysql_protocol"] = fields["protocol"]


def _parse_ms_sql_info(text: str, obs: _Observations) -> None:
    fields = _pairs(_lines(text), _FIELD_RE)
    number = fields.get("number")
    if number:
        obs.set_version(number, f"Version number: {number}", "ms-sql-info")
    # "name" under the Version block is the human release name, e.g.
    # "Microsoft SQL Server 2000 SP3".
    release = fields.get("name")
    if release:
        obs.product = release
        obs.extra["release"] = release
    for key, target in (
        ("windows server name", "windows_server_name"),
        ("instance name", "instance_name"),
        ("service pack level", "service_pack"),
    ):
        if fields.get(key):
            obs.extra[target] = fields[key]


def _parse_ms_sql_ntlm_info(text: str, obs: _Observations) -> None:
    """NTLM handshake leakage: host and AD names, readable before any login."""
    fields = _pairs(_lines(text), _FIELD_RE)
    for key, target in (
        ("target_name", "ntlm_target"),
        ("netbios_computer_name", "netbios_computer_name"),
        ("netbios_domain_name", "netbios_domain_name"),
        ("dns_computer_name", "dns_computer_name"),
        ("dns_domain_name", "dns_domain_name"),
        ("product_version", "windows_version"),
    ):
        if fields.get(key):
            obs.extra[target] = fields[key]


def _parse_mongodb_info(text: str, obs: _Observations) -> None:
    lines = _lines(text)
    values = _pairs(lines, _ASSIGN_RE)
    if values.get("version"):
        obs.set_version(values["version"], f"version = {values['version']}", "mongodb-info")
    if _denied(text):
        obs.auth_required.append(("mongodb-info", _excerpt(text, 6)))
        return
    # "Server status" is the serverStatus command: operational counters, which a
    # server with authentication enabled does not hand to an anonymous client.
    has_status = any(line.strip().lower().startswith("server status") for line in lines)
    if has_status and values.get("ok") == "1":
        obs.no_auth.append(("mongodb-info", _excerpt(text)))
        obs.cleartext.append(
            ("mongodb-info", "the MongoDB wire-protocol query completed without TLS")
        )


def _parse_mongodb_databases(text: str, obs: _Observations) -> None:
    if _denied(text):
        obs.auth_required.append(("mongodb-databases", _excerpt(text, 6)))
        return
    names = [
        match.group(1).strip()
        for match in (re.match(r"^\s*name\s*=\s*(.+)$", line) for line in _lines(text))
        if match and match.group(1).strip()
    ]
    if not names:
        return
    obs.set_names(names, _excerpt(text, 30), "mongodb-databases")
    obs.no_auth.append(("mongodb-databases", _excerpt(text, 20)))
    obs.cleartext.append(
        ("mongodb-databases", "the MongoDB wire-protocol query completed without TLS")
    )


def _parse_redis_info(text: str, obs: _Observations) -> None:
    if _denied(text):
        obs.auth_required.append(("redis-info", _excerpt(text, 6)))
        return
    lines = _lines(text)
    values = _pairs(lines, _COLUMN_RE)
    version = values.get("version")
    if version:
        quoted = next(
            (line.strip() for line in lines if _COLUMN_RE.match(line) and line.strip().lower().startswith("version")),
            f"Version {version}",
        )
        obs.set_version(version, quoted, "redis-info")
    if values.get("role"):
        obs.extra["redis_role"] = values["role"]
    # Redis refuses INFO when requirepass is set, so a populated INFO reply is
    # direct evidence that no password is in force.
    if version or len(values) >= 3:
        obs.no_auth.append(("redis-info", _excerpt(text)))
        obs.cleartext.append(("redis-info", "the Redis INFO command was answered in cleartext"))


def _parse_couchdb_stats(text: str, obs: _Observations) -> None:
    fields = _pairs(_lines(text), _FIELD_RE)
    state = (fields.get("authentication") or "").strip().lower()
    if state.startswith("not enabled"):
        obs.no_auth.append(
            ("couchdb-stats", f"Authentication : {fields['authentication']}")
        )
    elif state.startswith("enabled"):
        obs.auth_required.append(
            ("couchdb-stats", f"Authentication : {fields['authentication']}")
        )


def _parse_couchdb_databases(text: str, obs: _Observations) -> None:
    if _denied(text):
        obs.auth_required.append(("couchdb-databases", _excerpt(text, 6)))
        return
    names = [
        match.group(1).strip()
        for match in (re.match(r"^\s*\d+\s*=\s*(.+)$", line) for line in _lines(text))
        if match and match.group(1).strip()
    ]
    if not names:
        return
    obs.set_names(names, _excerpt(text, 30), "couchdb-databases")
    obs.no_auth.append(("couchdb-databases", _excerpt(text, 20)))


def _parse_cassandra_info(text: str, obs: _Observations) -> None:
    fields = _pairs(_lines(text), _FIELD_RE)
    if fields.get("cluster name"):
        obs.extra["cluster_name"] = fields["cluster name"]
    # cassandra-info reports the Thrift API version, not the Cassandra release,
    # so it is recorded but never compared against a release threshold.
    if fields.get("version"):
        obs.extra["thrift_version"] = fields["version"]


def _parse_db2_das_info(text: str, obs: _Observations) -> None:
    lines = _lines(text)
    for line in lines:
        match = re.match(r"^\s*Application\s*=\s*\S+?\s+([\d.]+)\s*$", line)
        if match:
            obs.set_version(match.group(1), line.strip(), "db2-das-info")
            break
    names: list[str] = []
    for line in lines:
        match = re.match(r"^\s*DBName\s*=\s*(\S+)\s*$", line, re.IGNORECASE)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    if names:
        obs.set_names(names, _excerpt(text, 40), "db2-das-info")
    for line in lines:
        match = re.match(r"^\s*DB2System\s*=\s*(\S+)\s*$", line, re.IGNORECASE)
        if match:
            obs.extra["db2_system"] = match.group(1)
            break


#: NSE script id -> parser. Only scripts actually present are parsed.
_PARSERS: tuple[tuple[str, Any], ...] = (
    ("mysql-info", _parse_mysql_info),
    ("ms-sql-info", _parse_ms_sql_info),
    ("ms-sql-ntlm-info", _parse_ms_sql_ntlm_info),
    ("mongodb-info", _parse_mongodb_info),
    ("mongodb-databases", _parse_mongodb_databases),
    ("redis-info", _parse_redis_info),
    ("couchdb-stats", _parse_couchdb_stats),
    ("couchdb-databases", _parse_couchdb_databases),
    ("cassandra-info", _parse_cassandra_info),
    ("db2-das-info", _parse_db2_das_info),
)


def match_engine(evidence: ServiceEvidence) -> tuple[_Engine, str] | None:
    """The engine this port looks like, and how it was identified.

    Name and product beat the port number, as elsewhere in netrecon: anything
    can listen anywhere, and a port number alone is weak evidence.
    """
    service = (evidence.service or "").strip().lower()
    # nmap prefixes tunnelled services, e.g. "ssl/mysql".
    candidates = {service, service.split("/")[-1]} if service else set()
    for engine in ENGINES:
        if candidates & engine.services:
            return engine, "service name"

    product = (evidence.product or "").strip().lower()
    if product:
        for engine in ENGINES:
            if any(alias in product for alias in engine.aliases):
                return engine, "product banner"

    if service in _NON_DATABASE_SERVICES:
        return None
    for engine in ENGINES:
        if evidence.port in engine.ports:
            return engine, "port number"
    return None


class DatabaseAnalyzer:
    """Reachability, pre-auth disclosure and missing authentication on data stores."""

    name = "database"
    needs_probe = False

    def applies_to(self, evidence: ServiceEvidence) -> bool:
        return match_engine(evidence) is not None

    def analyse(self, evidence: ServiceEvidence) -> list[Finding]:
        matched = match_engine(evidence)
        if matched is None:
            return []
        engine, identified_by = matched

        obs = _Observations()
        sources: list[str] = []
        for script, parser in _PARSERS:
            text = evidence.script(script)
            if not text or not str(text).strip():
                continue
            sources.append(script)
            parser(str(text), obs)
        if engine.key == "elasticsearch":
            self._elasticsearch_banner(evidence, obs)

        # The -sV banner is the fallback for both: a script that reported a
        # version is closer to the engine than nmap's fingerprint is.
        obs.set_version(evidence.version, _banner_line(evidence), "nmap -sV")
        obs.product = obs.product or evidence.product

        findings = [self._exposed(evidence, engine, identified_by, obs, sources)]
        findings.extend(self._no_authentication(evidence, engine, obs))
        findings.extend(self._databases_listed(evidence, engine, obs))
        findings.extend(self._version_findings(engine, obs))
        findings.extend(self._unencrypted(evidence, engine, obs))
        return findings

    # -- banner-only engines ---------------------------------------------

    def _elasticsearch_banner(self, evidence: ServiceEvidence, obs: _Observations) -> None:
        """Elasticsearch answers ``GET /`` with its cluster details, or a 401.

        nmap's fingerprint records which happened: a version plus a node or
        cluster name means the root document was served to an anonymous request,
        while a realm means something asked for credentials.
        """
        extrainfo = evidence.extrainfo or ""
        banner = _banner_line(evidence)
        if re.search(r"realm", extrainfo, re.IGNORECASE):
            obs.auth_required.append(("nmap -sV", banner))
            return
        if evidence.version and re.search(r"\b(name|cluster)\s*:", extrainfo, re.IGNORECASE):
            obs.no_auth.append(("nmap -sV", banner))
            if not _is_tls(evidence):
                obs.cleartext.append(
                    ("nmap -sV", f"the cluster document was served over cleartext: {banner}")
                )

    # -- findings --------------------------------------------------------

    def _exposed(
        self,
        evidence: ServiceEvidence,
        engine: _Engine,
        identified_by: str,
        obs: _Observations,
        sources: list[str],
    ) -> Finding:
        has_banner = bool(evidence.product or evidence.version or evidence.extrainfo)
        if has_banner:
            quoted = _banner_line(evidence)
            source = "nmap -sV"
        elif obs.version_evidence and obs.version_source != "nmap -sV":
            quoted = obs.version_evidence
            source = obs.version_source
        else:
            quoted = (
                f"{evidence.port}/{evidence.protocol} open, no service banner returned; "
                f"identified by {identified_by}"
            )
            source = "nmap port state"

        data: dict[str, Any] = {
            "engine": engine.key,
            "engine_label": engine.label,
            "identified_by": identified_by,
            "service": evidence.service,
            "product": obs.product or evidence.product,
            "version": obs.version,
            "port": evidence.port,
            "protocol": evidence.protocol,
        }
        if sources:
            data["scripts"] = sources
        data.update(obs.extra)

        hedge = (
            ""
            if identified_by != "port number"
            else " (identified by port number alone, so confirm the engine before reporting)"
        )
        return Finding(
            key="database.exposed",
            title=f"{engine.label} reachable from the scanning position",
            severity="medium",
            summary=(
                f"{engine.label} answered on {evidence.port}/{evidence.protocol} from where "
                f"netrecon scanned{hedge}. Database engines are rarely meant to be reachable "
                "beyond their application tier; confirm this network path is intended."
            ),
            evidence=quoted,
            recommendation=(
                "Restrict the listener to the hosts that need it (bind address, host firewall "
                "or security group) rather than relying on database authentication alone."
            ),
            source=source,
            data={key: value for key, value in data.items() if value not in (None, "", [])},
        )

    def _no_authentication(
        self, evidence: ServiceEvidence, engine: _Engine, obs: _Observations
    ) -> list[Finding]:
        if not obs.no_auth:
            return []
        quoted = "\n\n".join(text for _, text in obs.no_auth)
        sources = sorted({source for source, _ in obs.no_auth})
        data: dict[str, Any] = {"engine": engine.key, "sources": sources}
        if obs.auth_required:
            # Both seen: say so rather than silently picking a side.
            data["also_reported_auth_required"] = sorted({s for s, _ in obs.auth_required})
        return [
            Finding(
                key="database.no-authentication",
                title=f"{engine.label} served data without credentials",
                severity="critical",
                summary=(
                    f"{engine.label} answered an unauthenticated query with its own data "
                    f"(via {', '.join(sources)}), so authentication is not enforced for the "
                    "scanning position. Treat everything the instance holds as readable."
                ),
                evidence=quoted,
                recommendation=(
                    "Enable and require authentication, then re-test. Until then assume the "
                    "contents are disclosed and check the data classification with the owner."
                ),
                source=", ".join(sources),
                data=data,
            )
        ]

    def _databases_listed(
        self, evidence: ServiceEvidence, engine: _Engine, obs: _Observations
    ) -> list[Finding]:
        if not obs.names:
            return []
        shown = obs.names[:MAX_NAMES]
        data: dict[str, Any] = {
            "engine": engine.key,
            "databases": shown,
            "database_count": len(obs.names),
        }
        if len(obs.names) > MAX_NAMES:
            data["truncated"] = True
        return [
            Finding(
                key="database.databases-listed",
                title=f"{engine.label} database names readable",
                severity="high",
                summary=(
                    f"{len(obs.names)} database/keyspace name(s) were readable from "
                    f"{obs.names_source}: "
                    + ", ".join(shown[:10])
                    + (", ..." if len(shown) > 10 else "")
                    + ". Names alone often reveal applications, tenants and environments."
                ),
                evidence=obs.names_evidence,
                recommendation=(
                    "Require authentication for catalogue queries and confirm which of these "
                    "stores hold sensitive data before deciding the impact."
                ),
                source=obs.names_source,
                data=data,
            )
        ]

    def _version_findings(self, engine: _Engine, obs: _Observations) -> list[Finding]:
        if not obs.version:
            return []
        findings = [
            Finding(
                key="database.version-disclosed",
                title=f"{engine.label} version disclosed before authentication",
                severity="low",
                summary=(
                    f"The version string {obs.version!r} is readable without credentials, "
                    "which lets anyone who can reach the port match the build against public "
                    "advisories."
                ),
                evidence=obs.version_evidence,
                recommendation=(
                    "Usually inherent to the protocol. Where the engine supports suppressing "
                    "or editing the banner, weigh it against the monitoring it breaks."
                ),
                source=obs.version_source,
                data={"engine": engine.key, "version": obs.version},
            )
        ]

        threshold, label = _threshold_for(engine, obs)
        if threshold and version_below(obs.version, threshold):
            findings.append(
                Finding(
                    key="database.outdated",
                    title=f"{label} version older than {threshold}",
                    severity="low",
                    summary=(
                        f"{label} reports version {obs.version}, which is older than "
                        f"{threshold}; review against vendor advisories and the product's "
                        "support lifecycle."
                    ),
                    evidence=obs.version_evidence,
                    recommendation=(
                        "Confirm the build with the owner - distributions backport fixes, so "
                        "the number alone does not settle it - then plan an upgrade if the "
                        "release is out of support."
                    ),
                    source=obs.version_source,
                    data={
                        "engine": engine.key,
                        "version": obs.version,
                        "threshold": threshold,
                    },
                )
            )
        return findings

    def _unencrypted(
        self, evidence: ServiceEvidence, engine: _Engine, obs: _Observations
    ) -> list[Finding]:
        if not obs.cleartext or _is_tls(evidence):
            return []
        quoted = "\n".join(text for _, text in obs.cleartext)
        sources = sorted({source for source, _ in obs.cleartext})
        return [
            Finding(
                key="database.unencrypted",
                title=f"{engine.label} reachable without transport encryption",
                severity="low",
                summary=(
                    f"The exchange with {engine.label} completed in cleartext and nmap reported "
                    "no TLS tunnel on this port, so credentials and query results cross the "
                    "network unprotected unless a client opts in to TLS."
                ),
                evidence=quoted,
                recommendation=(
                    "Enable TLS on the listener and require it from clients, or keep the "
                    "traffic inside a trusted segment or tunnel."
                ),
                source=", ".join(sources),
                data={"engine": engine.key, "sources": sources},
            )
        ]


def _threshold_for(engine: _Engine, obs: _Observations) -> tuple[str | None, str]:
    """Threshold and product label, allowing for MariaDB under ``mysql``."""
    haystack = f"{obs.product or ''} {obs.version or ''}".lower()
    if engine.key == "mysql" and "mariadb" in haystack:
        return _MARIADB_THRESHOLD, "MariaDB"
    return engine.threshold, engine.label
