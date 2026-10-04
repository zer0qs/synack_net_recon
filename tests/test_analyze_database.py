"""Tests for the database analyzer.

The important property under test is restraint: ``database.no-authentication``
is critical, so it must fire only when the engine actually handed over data, and
never because a port happens to be open. Fixtures are the real NSE output shapes
(from the @output blocks in the scripts) built straight into
:class:`ServiceEvidence`; nothing here opens a socket or runs a process.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import SEVERITIES, ServiceEvidence
from netrecon.analyze.database import MAX_NAMES, DatabaseAnalyzer

# -- fixtures: real NSE output shapes ------------------------------------

MYSQL_INFO = r"""Protocol: 10
  Version: 5.5.40-0+wheezy1
  Thread ID: 7
  Capabilities flags: 63487
  Some Capabilities: ConnectWithDatabase, SupportsTransactions, Support41Auth
  Status: Autocommit
  Salt: bYyt\NQ/4V6IN+*3`imj
  Auth Plugin Name: mysql_native_password"""

MYSQL_INFO_WITH_TLS = r"""Protocol: 10
  Version: 8.0.33
  Thread ID: 12
  Capabilities flags: 65535
  Some Capabilities: ConnectWithDatabase, SwitchToSSLAfterHandshake, Support41Auth
  Status: Autocommit
  Salt: 7Hy*Q2mvdd\NQ/4V6IN"""

MYSQL_INFO_MARIADB = """Protocol: 10
  Version: 5.5.68-MariaDB
  Thread ID: 4
  Capabilities flags: 63487
  Some Capabilities: ConnectWithDatabase, Support41Auth
  Status: Autocommit"""

MS_SQL_INFO = r"""Windows server name: WINXP
  192.168.100.128\PROD:
    Instance name: PROD
    Version:
      name: Microsoft SQL Server 2000 SP3
      number: 8.00.760
      Product: Microsoft SQL Server 2000
      Service pack level: SP3
      Post-SP patches applied: No
    TCP port: 1278
    Named pipe: \\192.168.100.128\pipe\MSSQL$PROD\sql\query
    Clustered: No"""

MS_SQL_NTLM_INFO = """Target_Name: ACTIVESQL
  NetBIOS_Domain_Name: ACTIVESQL
  NetBIOS_Computer_Name: DB-TEST2
  DNS_Domain_Name: somedomain.com
  DNS_Computer_Name: db-test2.somedomain.com
  DNS_Tree_Name: somedomain.com
  Product_Version: 6.1.7601"""

MONGODB_INFO = """MongoDB Build info
    ok = 1
    bits = 64
    version = 3.6.3
    gitVersion = d1f0ffe23bcd667f4ed18a27b5fd31a0beab5535
    sysInfo = Linux 4.15.0 x86_64 BOOST_LIB_VERSION=1_41
  Server status
    opcounters
      insert = 3
      query = 10
    connections
      available = 19999
      current = 1
    uptime = 747
    ok = 1"""

MONGODB_INFO_DENIED = """MongoDB Build info
    errmsg = command buildInfo requires authentication
    ok = 0"""

MONGODB_DATABASES = """ok = 1
  databases
    1
      empty = false
      sizeOnDisk = 83886080
      name = test
    0
      empty = false
      sizeOnDisk = 83886080
      name = httpstorage
    3
      empty = true
      sizeOnDisk = 1
      name = local
    2
      empty = true
      sizeOnDisk = 1
      name = admin
  totalSize = 167772160"""

MONGODB_DATABASES_DENIED = """errmsg = not authorized on admin to execute command { listDatabases: 1 }
  ok = 0
  code = 13"""

REDIS_INFO = """Version            2.2.11
  Architecture       64 bits
  Process ID         17821
  Used CPU (sys)     2.37
  Used CPU (user)    1.02
  Connected clients  1
  Connected slaves   0
  Used memory        780.16K
  Role               master
  Bind addresses:
    192.168.121.101
  Client connections:
    192.168.171.101"""

REDIS_INFO_DENIED = "ERROR: Authentication required"
REDIS_INFO_NOAUTH_ERROR = "ERROR: -NOAUTH Authentication required."

COUCHDB_STATS_OPEN = """httpd_request_methods
    GET (number of HTTP GET requests)
      current = 5
      count = 1617
  httpd_status_codes
    200 (number of HTTP 200 OK responses)
      current = 5
      count = 1617
  Authentication : NOT enabled ('admin party')"""

COUCHDB_STATS_SECURED = """httpd_request_methods
    GET (number of HTTP GET requests)
      current = 5
      count = 1617
  Authentication : enabled"""

COUCHDB_STATS_UNKNOWN = """httpd
    requests (number of HTTP requests)
      current = 5
  Authentication : unknown"""

COUCHDB_DATABASES = """1 = test_suite_db
  2 = test_suite_db_a
  3 = test_suite_db/with_slashes
  4 = moneyz
  5 = creditcards
  6 = test_suite_users
  7 = test_suite_db_b"""

CASSANDRA_INFO = """Cluster name: Test Cluster
  Version: 19.10.0"""

DB2_DAS_INFO = """DB2 Administration Server Settings
  ;DB2 Server Database Access Profile
  ;Use BINARY file transfer

  [File_Description]
  Application=DB2/LINUX 9.7.0
  Platform=18
  File_Content=DB2 Server Definitions
  DB2System=MYBIGDATABASESERVER
  ServerType=DB2LINUX

  [inst>db2inst1]
  NodeType=1
  DB2Comm=TCPIP
  Authentication=SERVER
  HostName=MYBIGDATABASESERVER
  PortNumber=50000

  [db>db2inst1:TOOLSDB]
  DBAlias=TOOLSDB
  DBName=TOOLSDB
  Drive=/home/db2inst1
  Dir_entry_type=INDIRECT

  [db>db2inst1:PAYROLL]
  DBAlias=PAYROLL
  DBName=PAYROLL
  Dir_entry_type=INDIRECT"""

#: Output shapes that must never raise: empty, failed, truncated, mangled.
BROKEN_OUTPUTS = (
    "",
    "   ",
    "ERROR: Script execution failed (use -d to debug)",
    "Version:",
    "ok = ",
    "MongoDB Build info\n    ok = 1\n    version =",   # truncated mid-record
    "::::\n|_\n|\n",
    "1 = ",
    "Authentication : ",
    "\x00\x01 binary noise \xff",
)

ALL_SCRIPTS = (
    "mysql-info",
    "ms-sql-info",
    "ms-sql-ntlm-info",
    "mongodb-info",
    "mongodb-databases",
    "redis-info",
    "couchdb-stats",
    "couchdb-databases",
    "cassandra-info",
    "db2-das-info",
)


def analyser() -> DatabaseAnalyzer:
    return DatabaseAnalyzer()


def evidence(**kwargs) -> ServiceEvidence:
    base: dict = {"ip": "10.10.10.20", "port": 3306, "service": "mysql"}
    base.update(kwargs)
    return ServiceEvidence(**base)


def keys(findings) -> set[str]:
    return {finding.key for finding in findings}


def find(findings, key: str):
    matches = [finding for finding in findings if finding.key == key]
    assert len(matches) == 1, f"expected exactly one {key}, got {len(matches)}"
    return matches[0]


# -- applies_to ----------------------------------------------------------


@pytest.mark.parametrize(
    ("service", "port", "engine"),
    [
        ("mysql", 3306, "mysql"),
        ("ms-sql-s", 1433, "mssql"),
        ("postgresql", 5432, "postgresql"),
        ("oracle-tns", 1521, "oracle"),
        ("mongodb", 27017, "mongodb"),
        ("mongodb", 27018, "mongodb"),
        ("redis", 6379, "redis"),
        ("elasticsearch", 9200, "elasticsearch"),
        ("elasticsearch", 9300, "elasticsearch"),
        ("cassandra", 9042, "cassandra"),
        ("couchdb", 5984, "couchdb"),
        ("memcached", 11211, "memcached"),
        ("db2", 50000, "db2"),
    ],
)
def test_applies_to_known_engines_by_service_name(service, port, engine):
    analyzer = analyser()
    record = evidence(service=service, port=port)
    assert analyzer.applies_to(record)
    assert find(analyzer.analyse(record), "database.exposed").data["engine"] == engine


@pytest.mark.parametrize(
    ("port", "engine"),
    [
        (3306, "mysql"),
        (1433, "mssql"),
        (5432, "postgresql"),
        (1521, "oracle"),
        (27017, "mongodb"),
        (6379, "redis"),
        (9200, "elasticsearch"),
        (9042, "cassandra"),
        (5984, "couchdb"),
        (11211, "memcached"),
        (50000, "db2"),
    ],
)
def test_applies_to_known_engines_by_port_when_sv_said_nothing(port, engine):
    record = evidence(service=None, port=port)
    assert analyser().applies_to(record)
    finding = find(analyser().analyse(record), "database.exposed")
    assert finding.data["engine"] == engine
    assert finding.data["identified_by"] == "port number"


def test_service_name_beats_the_port_number():
    # A MySQL instance parked on 5432 is still MySQL.
    finding = find(
        analyser().analyse(evidence(service="mysql", port=5432)), "database.exposed"
    )
    assert finding.data["engine"] == "mysql"


def test_tunnelled_service_names_are_recognised():
    record = evidence(service="ssl/mysql", port=3307, tunnel="ssl")
    assert analyser().applies_to(record)


def test_product_banner_identifies_a_database_behind_a_generic_service_name():
    record = evidence(
        service="http", port=9200, product="Elasticsearch REST API", version="7.10.2"
    )
    assert analyser().applies_to(record)
    finding = find(analyser().analyse(record), "database.exposed")
    assert finding.data["engine"] == "elasticsearch"
    assert finding.data["identified_by"] == "product banner"


@pytest.mark.parametrize(
    ("service", "port"),
    [
        ("http", 80),
        ("ssh", 22),
        ("microsoft-ds", 445),
        ("domain", 53),
        # 50000 and 9200 carry plenty of non-database software; a generic web
        # service name must veto the port guess.
        ("http", 50000),
        ("http", 9200),
        ("https", 5984),
    ],
)
def test_does_not_apply_to_non_database_services(service, port):
    record = evidence(service=service, port=port)
    assert not analyser().applies_to(record)
    assert analyser().analyse(record) == []


# -- database.exposed ----------------------------------------------------


def test_exposed_always_fires_for_an_identified_database():
    finding = find(
        analyser().analyse(
            evidence(product="MySQL", version="8.0.33", scripts={"mysql-info": MYSQL_INFO_WITH_TLS})
        ),
        "database.exposed",
    )
    assert finding.severity == "medium"
    assert finding.data["product"] == "MySQL"
    assert finding.data["version"] == "8.0.33"
    assert finding.data["port"] == 3306
    assert "3306/tcp" in finding.evidence


def test_exposed_is_honest_when_only_the_port_identified_the_service():
    finding = find(
        analyser().analyse(evidence(service=None, port=27017)), "database.exposed"
    )
    assert "no service banner returned" in finding.evidence
    assert "identified by port number alone" in finding.summary


def test_exposed_folds_in_ms_sql_ntlm_host_details():
    finding = find(
        analyser().analyse(
            evidence(
                service="ms-sql-s",
                port=1433,
                scripts={"ms-sql-info": MS_SQL_INFO, "ms-sql-ntlm-info": MS_SQL_NTLM_INFO},
            )
        ),
        "database.exposed",
    )
    assert finding.data["dns_computer_name"] == "db-test2.somedomain.com"
    assert finding.data["netbios_domain_name"] == "ACTIVESQL"
    assert finding.data["windows_version"] == "6.1.7601"
    assert finding.data["instance_name"] == "PROD"
    assert finding.data["release"] == "Microsoft SQL Server 2000 SP3"


def test_exposed_records_which_scripts_contributed():
    finding = find(
        analyser().analyse(evidence(scripts={"mysql-info": MYSQL_INFO})), "database.exposed"
    )
    assert finding.data["scripts"] == ["mysql-info"]


def test_exposed_is_the_only_finding_for_a_bare_open_port():
    findings = analyser().analyse(evidence(service="postgresql", port=5432))
    assert keys(findings) == {"database.exposed"}


# -- database.no-authentication (the finding that must stay quiet) --------


def test_no_authentication_does_not_fire_on_an_open_port_with_no_output():
    """An open port says nothing about authentication. This is the core rule."""
    for service, port in (
        ("mysql", 3306),
        ("mongodb", 27017),
        ("redis", 6379),
        ("couchdb", 5984),
        ("elasticsearch", 9200),
        ("ms-sql-s", 1433),
        ("postgresql", 5432),
    ):
        findings = analyser().analyse(evidence(service=service, port=port))
        assert "database.no-authentication" not in keys(findings), service


def test_no_authentication_does_not_fire_from_a_version_banner_alone():
    findings = analyser().analyse(
        evidence(service="mongodb", port=27017, product="MongoDB", version="4.4.6")
    )
    assert "database.no-authentication" not in keys(findings)


def test_no_authentication_does_not_fire_from_mysql_info():
    # The MySQL handshake is pre-auth by design; reading it proves nothing.
    findings = analyser().analyse(evidence(scripts={"mysql-info": MYSQL_INFO}))
    assert "database.no-authentication" not in keys(findings)


@pytest.mark.parametrize(
    ("script", "output"),
    [
        ("redis-info", REDIS_INFO_DENIED),
        ("redis-info", REDIS_INFO_NOAUTH_ERROR),
        ("mongodb-databases", MONGODB_DATABASES_DENIED),
        ("mongodb-info", MONGODB_INFO_DENIED),
    ],
)
def test_no_authentication_does_not_fire_when_the_engine_refused(script, output):
    service = "redis" if script.startswith("redis") else "mongodb"
    port = 6379 if service == "redis" else 27017
    findings = analyser().analyse(
        evidence(service=service, port=port, scripts={script: output})
    )
    assert "database.no-authentication" not in keys(findings)
    assert "database.databases-listed" not in keys(findings)


def test_no_authentication_does_not_fire_when_couchdb_reports_auth_enabled():
    findings = analyser().analyse(
        evidence(service="couchdb", port=5984, scripts={"couchdb-stats": COUCHDB_STATS_SECURED})
    )
    assert "database.no-authentication" not in keys(findings)


def test_no_authentication_does_not_fire_when_couchdb_auth_state_is_unknown():
    findings = analyser().analyse(
        evidence(service="couchdb", port=5984, scripts={"couchdb-stats": COUCHDB_STATS_UNKNOWN})
    )
    assert "database.no-authentication" not in keys(findings)


def test_no_authentication_does_not_fire_for_an_elasticsearch_401():
    findings = analyser().analyse(
        evidence(
            service="http",
            port=9200,
            product="Elasticsearch REST API",
            extrainfo="Shield plugin; realm: security",
        )
    )
    assert "database.no-authentication" not in keys(findings)


def test_no_authentication_fires_for_an_anonymous_mongodb_database_listing():
    finding = find(
        analyser().analyse(
            evidence(service="mongodb", port=27017, scripts={"mongodb-databases": MONGODB_DATABASES})
        ),
        "database.no-authentication",
    )
    assert finding.severity == "critical"
    assert finding.data["sources"] == ["mongodb-databases"]
    assert "name = test" in finding.evidence


def test_no_authentication_fires_for_an_anonymous_mongodb_server_status():
    finding = find(
        analyser().analyse(
            evidence(service="mongodb", port=27017, scripts={"mongodb-info": MONGODB_INFO})
        ),
        "database.no-authentication",
    )
    assert "Server status" in finding.evidence


def test_no_authentication_fires_for_an_answered_redis_info():
    finding = find(
        analyser().analyse(evidence(service="redis", port=6379, scripts={"redis-info": REDIS_INFO})),
        "database.no-authentication",
    )
    assert finding.source == "redis-info"
    assert "Used memory" in finding.evidence


def test_no_authentication_fires_for_couchdb_admin_party():
    finding = find(
        analyser().analyse(
            evidence(service="couchdb", port=5984, scripts={"couchdb-stats": COUCHDB_STATS_OPEN})
        ),
        "database.no-authentication",
    )
    assert finding.evidence == "Authentication : NOT enabled ('admin party')"


def test_no_authentication_fires_for_an_anonymous_couchdb_database_listing():
    findings = analyser().analyse(
        evidence(service="couchdb", port=5984, scripts={"couchdb-databases": COUCHDB_DATABASES})
    )
    assert "database.no-authentication" in keys(findings)


def test_no_authentication_fires_for_an_elasticsearch_cluster_banner():
    finding = find(
        analyser().analyse(
            evidence(
                service="http",
                port=9200,
                product="Elasticsearch REST API",
                version="7.10.2",
                extrainfo="name: node-1; cluster: docker-cluster; Lucene 8.7.0",
            )
        ),
        "database.no-authentication",
    )
    assert finding.source == "nmap -sV"
    assert "Elasticsearch REST API" in finding.evidence


def test_no_authentication_is_reported_once_across_several_proofs():
    finding = find(
        analyser().analyse(
            evidence(
                service="couchdb",
                port=5984,
                scripts={
                    "couchdb-stats": COUCHDB_STATS_OPEN,
                    "couchdb-databases": COUCHDB_DATABASES,
                },
            )
        ),
        "database.no-authentication",
    )
    assert finding.data["sources"] == ["couchdb-databases", "couchdb-stats"]


def test_no_authentication_notes_a_conflicting_auth_report():
    # Stats say auth is on, yet the database list came back anyway: say both.
    finding = find(
        analyser().analyse(
            evidence(
                service="couchdb",
                port=5984,
                scripts={
                    "couchdb-stats": COUCHDB_STATS_SECURED,
                    "couchdb-databases": COUCHDB_DATABASES,
                },
            )
        ),
        "database.no-authentication",
    )
    assert finding.data["also_reported_auth_required"] == ["couchdb-stats"]


def test_no_authentication_never_claims_exploitability_or_a_cve():
    finding = find(
        analyser().analyse(evidence(service="redis", port=6379, scripts={"redis-info": REDIS_INFO})),
        "database.no-authentication",
    )
    blob = " ".join(str(part) for part in (finding.summary, finding.recommendation, finding.title))
    assert "CVE" not in blob.upper()
    assert "exploit" not in blob.lower()


# -- database.databases-listed -------------------------------------------


def test_databases_listed_for_mongodb():
    finding = find(
        analyser().analyse(
            evidence(service="mongodb", port=27017, scripts={"mongodb-databases": MONGODB_DATABASES})
        ),
        "database.databases-listed",
    )
    assert finding.severity == "high"
    assert finding.data["databases"] == ["test", "httpstorage", "local", "admin"]
    assert finding.data["database_count"] == 4


def test_databases_listed_for_couchdb():
    finding = find(
        analyser().analyse(
            evidence(service="couchdb", port=5984, scripts={"couchdb-databases": COUCHDB_DATABASES})
        ),
        "database.databases-listed",
    )
    assert "creditcards" in finding.data["databases"]
    assert finding.data["database_count"] == 7


def test_databases_listed_for_db2_das_profile():
    finding = find(
        analyser().analyse(
            evidence(service="db2", port=50000, scripts={"db2-das-info": DB2_DAS_INFO})
        ),
        "database.databases-listed",
    )
    assert finding.data["databases"] == ["TOOLSDB", "PAYROLL"]


def test_databases_listed_is_capped_but_counted():
    output = "\n".join(f"  {index} = db_{index}" for index in range(1, 81))
    finding = find(
        analyser().analyse(
            evidence(service="couchdb", port=5984, scripts={"couchdb-databases": output})
        ),
        "database.databases-listed",
    )
    assert len(finding.data["databases"]) == MAX_NAMES
    assert finding.data["database_count"] == 80
    assert finding.data["truncated"] is True


def test_databases_listed_does_not_fire_without_a_listing():
    findings = analyser().analyse(
        evidence(service="mongodb", port=27017, scripts={"mongodb-info": MONGODB_INFO})
    )
    assert "database.databases-listed" not in keys(findings)


# -- database.version-disclosed and database.outdated --------------------


def test_version_disclosed_prefers_the_script_over_the_sv_banner():
    finding = find(
        analyser().analyse(
            evidence(product="MySQL", version="5.5.40", scripts={"mysql-info": MYSQL_INFO})
        ),
        "database.version-disclosed",
    )
    assert finding.source == "mysql-info"
    assert finding.evidence == "Version: 5.5.40-0+wheezy1"


def test_version_disclosed_falls_back_to_the_sv_banner():
    finding = find(
        analyser().analyse(evidence(service="postgresql", port=5432, product="PostgreSQL DB", version="9.6.1")),
        "database.version-disclosed",
    )
    assert finding.source == "nmap -sV"
    assert "9.6.1" in finding.evidence


def test_version_disclosed_reads_the_ms_sql_version_number():
    finding = find(
        analyser().analyse(
            evidence(service="ms-sql-s", port=1433, scripts={"ms-sql-info": MS_SQL_INFO})
        ),
        "database.version-disclosed",
    )
    assert finding.data["version"] == "8.00.760"


def test_version_disclosed_does_not_fire_when_no_version_is_known():
    findings = analyser().analyse(evidence(service="redis", port=6379))
    assert "database.version-disclosed" not in keys(findings)
    assert "database.outdated" not in keys(findings)


@pytest.mark.parametrize(
    ("service", "port", "version", "threshold"),
    [
        ("mysql", 3306, "5.5.40-0+wheezy1", "5.7"),
        ("postgresql", 5432, "9.6.1", "11"),
        ("mongodb", 27017, "3.6.3", "4.4"),
        ("redis", 6379, "5.0.7", "6.0"),
        ("elasticsearch", 9200, "6.8.1", "7.0"),
        ("couchdb", 5984, "1.6.1", "3.0"),
    ],
)
def test_outdated_fires_below_the_conservative_threshold(service, port, version, threshold):
    finding = find(
        analyser().analyse(evidence(service=service, port=port, version=version)),
        "database.outdated",
    )
    assert finding.severity == "low"
    assert finding.data["threshold"] == threshold
    assert "review against vendor advisories" in finding.summary


@pytest.mark.parametrize(
    ("service", "port", "version"),
    [
        ("mysql", 3306, "8.0.33"),
        ("mysql", 3306, "5.7.44"),
        ("postgresql", 5432, "14.2"),
        ("mongodb", 27017, "6.0.4"),
        ("redis", 6379, "7.0.11"),
        ("elasticsearch", 9200, "8.11.1"),
    ],
)
def test_outdated_does_not_fire_for_current_versions(service, port, version):
    findings = analyser().analyse(evidence(service=service, port=port, version=version))
    assert "database.outdated" not in keys(findings)


def test_outdated_uses_the_mariadb_threshold_and_label():
    finding = find(
        analyser().analyse(
            evidence(product="MariaDB", scripts={"mysql-info": MYSQL_INFO_MARIADB})
        ),
        "database.outdated",
    )
    assert finding.data["threshold"] == "10.4"
    assert "MariaDB" in finding.title


def test_outdated_does_not_mistake_mariadb_10x_for_an_old_mysql():
    findings = analyser().analyse(
        evidence(product="MariaDB", version="10.11.2-MariaDB")
    )
    assert "database.outdated" not in keys(findings)


def test_outdated_ignores_the_cassandra_thrift_protocol_version():
    # cassandra-info reports the Thrift API version (19.10.0), not the release.
    findings = analyser().analyse(
        evidence(service="cassandra", port=9042, scripts={"cassandra-info": CASSANDRA_INFO})
    )
    exposed = find(findings, "database.exposed")
    assert exposed.data["thrift_version"] == "19.10.0"
    assert exposed.data["cluster_name"] == "Test Cluster"
    assert "database.outdated" not in keys(findings)


def test_outdated_never_claims_a_cve():
    finding = find(
        analyser().analyse(evidence(service="mysql", port=3306, version="5.5.40")),
        "database.outdated",
    )
    blob = " ".join(str(part) for part in (finding.summary, finding.recommendation, finding.title))
    assert "CVE" not in blob.upper()
    assert "exploit" not in blob.lower()


# -- database.unencrypted ------------------------------------------------


def test_unencrypted_fires_when_mysql_advertises_no_ssl_capability():
    finding = find(
        analyser().analyse(evidence(scripts={"mysql-info": MYSQL_INFO})), "database.unencrypted"
    )
    assert finding.severity == "low"
    assert "Some Capabilities" in finding.evidence


def test_unencrypted_does_not_fire_when_mysql_offers_ssl():
    findings = analyser().analyse(evidence(scripts={"mysql-info": MYSQL_INFO_WITH_TLS}))
    assert "database.unencrypted" not in keys(findings)


def test_unencrypted_does_not_fire_when_the_port_is_already_tls():
    findings = analyser().analyse(
        evidence(service="ssl/mysql", tunnel="ssl", scripts={"mysql-info": MYSQL_INFO})
    )
    assert "database.unencrypted" not in keys(findings)


def test_unencrypted_fires_for_a_cleartext_redis_exchange():
    finding = find(
        analyser().analyse(evidence(service="redis", port=6379, scripts={"redis-info": REDIS_INFO})),
        "database.unencrypted",
    )
    assert "cleartext" in finding.evidence


def test_unencrypted_does_not_fire_from_an_open_port_alone():
    findings = analyser().analyse(evidence(service="mysql", port=3306, version="5.7.44"))
    assert "database.unencrypted" not in keys(findings)


# -- robustness ----------------------------------------------------------


@pytest.mark.parametrize("broken", BROKEN_OUTPUTS)
def test_broken_output_in_every_script_does_not_raise(broken):
    findings = analyser().analyse(
        evidence(service="mysql", port=3306, scripts=dict.fromkeys(ALL_SCRIPTS, broken))
    )
    for finding in findings:
        assert finding.severity in SEVERITIES
        assert finding.summary


@pytest.mark.parametrize("broken", BROKEN_OUTPUTS)
def test_broken_output_never_invents_a_weakness(broken):
    findings = analyser().analyse(
        evidence(service="mysql", port=3306, scripts=dict.fromkeys(ALL_SCRIPTS, broken))
    )
    assert not keys(findings) & {
        "database.no-authentication",
        "database.databases-listed",
        "database.outdated",
    }


def test_nmap_stdout_with_the_pipe_gutter_is_parsed_too():
    gutter = "\n".join(["| redis-info: ", "|   Version            2.2.11", "|_  Role               master"])
    findings = analyser().analyse(
        evidence(service="redis", port=6379, scripts={"redis-info": gutter})
    )
    assert "database.no-authentication" in keys(findings)


def test_host_level_scripts_are_searched_as_well():
    # ms-sql-ntlm-info can land as a host script when it ran against 445.
    finding = find(
        analyser().analyse(
            evidence(service="ms-sql-s", port=1433, host_scripts={"ms-sql-ntlm-info": MS_SQL_NTLM_INFO})
        ),
        "database.exposed",
    )
    assert finding.data["dns_domain_name"] == "somedomain.com"


def test_every_finding_quotes_evidence_and_names_its_source():
    findings = analyser().analyse(
        evidence(
            service="mongodb",
            port=27017,
            product="MongoDB",
            version="3.6.3",
            scripts={"mongodb-info": MONGODB_INFO, "mongodb-databases": MONGODB_DATABASES},
        )
    )
    assert keys(findings) == {
        "database.exposed",
        "database.no-authentication",
        "database.databases-listed",
        "database.version-disclosed",
        "database.outdated",
        "database.unencrypted",
    }
    for finding in findings:
        assert finding.evidence and finding.evidence.strip()
        assert finding.source
        assert finding.recommendation
        assert finding.severity in SEVERITIES


def test_the_analyzer_declares_itself_correctly():
    analyzer = analyser()
    assert analyzer.name == "database"
    assert analyzer.needs_probe is False
