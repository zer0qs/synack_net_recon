"""Tests for the HTTP service analyzer.

The analyzer is a pure function over evidence already on disk, so every test
here just hands it a ServiceEvidence with NSE text in it. The cases worth having
are the negative ones: NSE scripts that ran and found nothing must not become
findings, and an "open proxy" check that came back negative must not be reported
as an open proxy.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import ServiceEvidence
from netrecon.analyze.httpsvc import (
    HttpServiceAnalyzer,
    config_backups,
    dangerous_methods,
    git_repository_found,
    open_proxy,
    page_title,
    parse_methods,
    robots_paths,
    security_headers_reported,
    server_header,
)

ANALYZER = HttpServiceAnalyzer()


def service(**kwargs) -> ServiceEvidence:
    base = {"ip": "10.10.10.5", "port": 80, "service": "http"}
    base.update(kwargs)
    return ServiceEvidence(**base)


def keys(evidence: ServiceEvidence) -> list[str]:
    return [finding.key for finding in ANALYZER.analyse(evidence)]


def finding(evidence: ServiceEvidence, key: str):
    for item in ANALYZER.analyse(evidence):
        if item.key == key:
            return item
    return None


# -- selection -----------------------------------------------------------


def test_analyzer_identity():
    assert ANALYZER.name == "http"
    assert ANALYZER.needs_probe is False


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"service": "http", "port": 80}, True),
        ({"service": "https", "port": 443, "tunnel": "ssl"}, True),
        ({"service": None, "port": 8080}, True),
        ({"service": "http-proxy", "port": 3128}, True),
        ({"service": "ssh", "port": 22}, False),
        ({"service": "mysql", "port": 3306}, False),
    ],
)
def test_applies_to_web_ports_only(kwargs, expected):
    assert ANALYZER.applies_to(service(**kwargs)) is expected


def test_nothing_known_means_nothing_reported():
    assert ANALYZER.analyse(service(service=None, port=8080)) == []


# -- http-methods --------------------------------------------------------

METHODS_RISKY = (
    "  Supported Methods: GET HEAD POST OPTIONS TRACE PUT DELETE\n"
    "  Potentially risky methods: TRACE PUT DELETE"
)


def test_parse_methods_reads_only_method_lines():
    text = "  Supported Methods: GET HEAD POST\n  Path tested: /INDEX.HTML\n"
    assert parse_methods(text) == {"GET", "HEAD", "POST"}


def test_dangerous_methods_are_reported_medium():
    item = finding(service(scripts={"http-methods": METHODS_RISKY}), "http.dangerous-methods")
    assert item is not None
    assert item.severity == "medium"
    assert item.data["methods"] == ["PUT", "DELETE", "TRACE"]
    assert "OPTIONS" in item.data["all_methods"]
    assert "netrecon did not send any of these methods" in item.summary
    assert item.source == "http-methods"


def test_ordinary_methods_are_not_a_finding():
    assert dangerous_methods("  Supported Methods: GET HEAD POST OPTIONS") == []
    assert "http.dangerous-methods" not in keys(
        service(scripts={"http-methods": "  Supported Methods: GET HEAD POST OPTIONS"})
    )


def test_connect_is_treated_as_dangerous():
    assert dangerous_methods("  Supported Methods: GET CONNECT") == ["CONNECT"]


# -- http-git ------------------------------------------------------------


def test_exposed_git_repository_is_high():
    output = "  10.10.10.5:80/.git/\n    Git repository found!"
    item = finding(service(scripts={"http-git": output}), "http.git-exposed")
    assert item is not None
    assert item.severity == "high"
    assert "rotate any credential" in item.recommendation
    assert item.evidence and "Git repository found" in item.evidence


def test_http_git_that_found_nothing_is_not_a_finding():
    assert git_repository_found("") is False
    assert git_repository_found("  ERROR: Couldn't connect") is False
    assert "http.git-exposed" not in keys(service(scripts={"http-git": "\n"}))


# -- http-config-backup --------------------------------------------------


def test_retrievable_config_backups_are_high():
    output = "  /config.php.bak\n  /.env~\n  /web.config.old"
    item = finding(service(scripts={"http-config-backup": output}), "http.config-backup-exposed")
    assert item is not None
    assert item.severity == "high"
    assert item.data["paths"] == ["/config.php.bak", "/.env~", "/web.config.old"]


def test_config_backup_error_output_is_not_a_finding():
    assert config_backups("  ERROR: /config.php.bak could not be retrieved") == []
    assert "http.config-backup-exposed" not in keys(
        service(scripts={"http-config-backup": "  Couldn't find any backups"})
    )


# -- http-open-proxy -----------------------------------------------------


def test_open_proxy_is_reported_only_when_the_script_says_so():
    output = "  Potentially OPEN proxy.\n  Methods supported: GET HEAD CONNECT"
    item = finding(service(scripts={"http-open-proxy": output}), "http.open-proxy")
    assert item is not None
    assert item.severity == "high"


@pytest.mark.parametrize(
    "output",
    [
        "",
        "  Proxy might be redirecting requests",
        "  This is not an open proxy",
    ],
)
def test_negative_proxy_output_is_never_an_open_proxy(output):
    assert open_proxy(output) is False
    assert "http.open-proxy" not in keys(service(scripts={"http-open-proxy": output}))


# -- technology ----------------------------------------------------------


def test_technology_finding_carries_structured_versions():
    evidence = service(
        product="nginx",
        version="1.18.0",
        scripts={
            "http-server-header": "nginx/1.18.0 (Ubuntu)",
            "http-generator": "WordPress 6.4.2",
            "http-title": "Example site",
            "http-robots.txt": "2 disallowed entries\n/admin/ /private/",
            "http-security-headers": "Strict_Transport_Security:\n  HSTS not configured",
        },
    )
    item = finding(evidence, "http.technology")
    assert item is not None
    assert item.severity == "info"

    technologies = {entry["name"]: entry for entry in item.data["technologies"]}
    assert technologies["nginx"]["version"] == "1.18.0"
    assert technologies["nginx"]["cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert technologies["WordPress"]["version"] == "6.4.2"
    assert item.data["count"] == 2
    assert item.data["with_version"] == 2
    assert item.data["page_title"] == "Example site"
    assert item.data["robots_paths"] == ["/admin/", "/private/"]
    assert item.data["security_headers_reported"] == ["strict-transport-security"]
    # An info finding still has to be honest about what a banner proves.
    assert "not a statement about what is installed" in item.summary


def test_technology_comes_from_nmap_cpes_too():
    evidence = service(cpes=("cpe:/a:apache:http_server:2.4.41",))
    item = finding(evidence, "http.technology")
    assert item is not None
    names = [entry["name"] for entry in item.data["technologies"]]
    assert names == ["Apache httpd"]
    assert item.data["technologies"][0]["version"] == "2.4.41"


def test_no_technology_no_technology_finding():
    assert "http.technology" not in keys(service(scripts={"http-methods": "  Supported: GET"}))


# -- version disclosure --------------------------------------------------


def test_server_header_version_is_a_low_finding():
    evidence = service(scripts={"http-server-header": "Apache/2.4.41 (Ubuntu)"})
    item = finding(evidence, "http.server-version-disclosed")
    assert item is not None
    assert item.severity == "low"
    assert item.data["server"] == "Apache/2.4.41 (Ubuntu)"
    assert item.source == "http-server-header"
    assert "server_tokens off" in item.recommendation


def test_server_header_without_a_version_is_not_reported():
    assert "http.server-version-disclosed" not in keys(
        service(scripts={"http-server-header": "cloudflare"})
    )


def test_sv_banner_stands_in_for_a_missing_server_header_script():
    value, origin = server_header(service(product="nginx", version="1.18.0"))
    assert value == "nginx 1.18.0"
    assert origin == "nmap -sV"
    item = finding(service(product="nginx", version="1.18.0"), "http.server-version-disclosed")
    assert item is not None
    assert item.evidence == "nmap -sV: nginx 1.18.0"


# -- small parsers -------------------------------------------------------


def test_page_title_handles_the_no_title_case():
    assert page_title("  Did not follow redirect to https://example.test/") is None
    assert page_title("  Welcome to nginx!") == "Welcome to nginx!"
    assert page_title(None) is None


def test_robots_and_security_header_parsers():
    assert robots_paths("  2 disallowed entries\n  /admin/\n  /cgi-bin/") == [
        "/admin/",
        "/cgi-bin/",
    ]
    assert security_headers_reported("  X-Frame-Options:\n    Header: DENY") == [
        "x-frame-options"
    ]


def test_everything_together_produces_one_finding_per_issue():
    evidence = service(
        product="nginx",
        version="1.18.0",
        scripts={
            "http-server-header": "nginx/1.18.0",
            "http-methods": METHODS_RISKY,
            "http-git": "  Git repository found!",
            "http-config-backup": "  /config.php.bak",
            "http-open-proxy": "  Potentially OPEN proxy.",
        },
    )
    assert sorted(keys(evidence)) == [
        "http.config-backup-exposed",
        "http.dangerous-methods",
        "http.git-exposed",
        "http.open-proxy",
        "http.server-version-disclosed",
        "http.technology",
    ]
