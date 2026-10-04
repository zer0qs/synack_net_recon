"""Tests for the HTML report.

The report embeds strings that came from scanned hosts - page titles, HTTP
headers, JavaScript fragments. Those are attacker-controlled as far as this
tool is concerned, so the escaping tests here are the important ones: a report
that executes a scanned host's markup when an analyst opens it would be a
vulnerability in the tooling.
"""

from __future__ import annotations

import json
import re

import pytest

from netrecon.core.jsonio import write_json
from netrecon.report import build as report_build
from netrecon.report.build import HostSummary
from netrecon.report.categories import group_by_category
from netrecon.report.html import esc, render_html


def _payload(**overrides):
    base = {
        "generated_at": "2024-05-20T10:14:01Z",
        "run": {
            "name": "acme",
            "directory": "/results/acme/20240520T101320Z",
            "started_at": "2024-05-20T10:13:20Z",
            "netrecon_version": "1.1.0",
            "active_stage_enabled": False,
            "web_stage_enabled": True,
            "raw_sockets": True,
        },
        "scope": {
            "source": "scope.txt",
            "total_hosts": 2,
            "ipv4_hosts": 2,
            "ipv6_hosts": 0,
            "first": "10.0.0.1",
            "last": "10.0.0.2",
            "entries": 1,
            "rejected_lines": 0,
        },
        "limits": {
            "sweep_rate_pps": 1000,
            "nuclei_rate_rps": 50,
            "concurrency": 8,
            "nmap_timing": 3,
            "webrecon_rate_rps": 5.0,
        },
        "stages": {
            "sweep": {
                "status": "completed",
                "duration_seconds": 1.2,
                "detail": None,
                "backend": "masscan",
            },
            "report": {"status": "running", "duration_seconds": None, "detail": None},
        },
        "totals": {
            "in_scope_hosts": 2,
            "live_hosts": 1,
            "hosts_reported": 1,
            "hosts_with_open_ports": 1,
            "open_ports": 2,
            "services_identified": 2,
            "nuclei_findings": 0,
            "notable_observations": 1,
            "service_categories": 2,
            "web_endpoints": 1,
            "js_scripts_analysed": 1,
            "js_endpoints": 3,
            "js_secret_candidates": 1,
        },
        "sweep_backend": "masscan",
    }
    base.update(overrides)
    return base


def _hosts():
    host = HostSummary(
        ip="10.0.0.1",
        hostnames=["web01"],
        os_guess="Linux 5.0 - 5.14 (95%)",
        open_ports=[
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "version": "nginx 1.18.0",
                "scripts": {"http-title": "Welcome"},
            },
            {
                "port": 3306,
                "protocol": "tcp",
                "service": "mysql",
                "version": "MySQL 8.0.36",
                "scripts": {},
            },
        ],
        notes=["`3306/tcp` MySQL exposed"],
    )
    return [host]


def _webrecon():
    return {
        "limits": {"rate_per_second": 5.0, "max_scripts_per_endpoint": 25},
        "failures": [],
        "results": [
            {
                "ip": "10.0.0.1",
                "port": 80,
                "scheme": "http",
                "base_url": "http://10.0.0.1:80",
                "error": None,
                "root": {
                    "status": 200,
                    "reason": "OK",
                    "title": "Acme Portal",
                    "technologies": ["React", "Server: nginx/1.18.0"],
                    "disclosure_headers": {"server": "nginx/1.18.0"},
                    "missing_security_headers": ["content-security-policy"],
                    "form_actions": ["POST /login"],
                    "html_comments": ["TODO: remove debug flag"],
                    "redirect_to": None,
                },
                "well_known": [
                    {"path": "/robots.txt", "status": 200, "bytes": 40, "preview": "Disallow: /admin"}
                ],
                "scripts": [
                    {
                        "source": "http://10.0.0.1:80/app.js",
                        "endpoints": ["/api/v1/me", "/api/v1/orders", "/graphql"],
                        "secret_candidates": [
                            {
                                "kind": "assigned_secret",
                                "name": "api_key",
                                "value": "9f2b********e8 (len 32)",
                                "line": "10",
                                "source": "http://10.0.0.1:80/app.js",
                            }
                        ],
                        "source_maps": ["/app.js.map"],
                    }
                ],
                "totals": {"scripts_analysed": 1, "js_endpoints": 3, "secret_candidates": 1},
            }
        ],
    }


@pytest.fixture()
def document():
    hosts = _hosts()
    return render_html(_payload(), hosts, group_by_category(hosts), _webrecon())


# -- structure -----------------------------------------------------------


def test_document_is_a_complete_html_page(document):
    assert document.startswith("<!doctype html>")
    assert document.rstrip().endswith("</html>")
    assert '<meta name="viewport"' in document
    assert "<title>netrecon report - acme</title>" in document


def test_every_tab_has_a_matching_panel(document):
    tabs = set(re.findall(r"data-target='([^']+)'", document))
    panels = set(re.findall(r"<div class='panel' id='([^']+)'", document))
    assert tabs == panels
    assert tabs == {"tab-overview", "tab-hosts", "tab-categories", "tab-web"}


def test_no_external_resources_are_referenced(document):
    # A report opened on a client network must not phone home.
    external = re.findall(r"""(?:src|href)\s*=\s*["'](https?://[^"']+)""", document)
    assert external == []


def test_styles_and_scripts_are_inline(document):
    assert "<style>" in document
    assert "<script>" in document
    assert "stylesheet" not in document


def test_dark_mode_is_supported(document):
    assert "prefers-color-scheme: dark" in document


def test_web_tab_is_omitted_when_the_stage_did_not_run():
    hosts = _hosts()
    doc = render_html(_payload(), hosts, group_by_category(hosts), None)
    assert "tab-web" not in doc
    assert "Web reconnaissance" not in doc


# -- content -------------------------------------------------------------


def test_hosts_section_lists_ports_and_versions(document):
    assert "10.0.0.1" in document
    assert "web01" in document
    assert "nginx 1.18.0" in document
    assert "MySQL 8.0.36" in document
    assert "Linux 5.0 - 5.14 (95%)" in document


def test_category_section_groups_services(document):
    assert "Services by category" in document
    assert "Web services" in document
    assert "Databases" in document
    assert "id='cat-web'" in document
    assert "id='cat-database'" in document


def test_category_rows_link_to_the_host_section(document):
    assert "href='#host-10-0-0-1'" in document
    assert "id='host-10-0-0-1'" in document


def test_web_section_reports_the_read_only_method(document):
    assert "Web reconnaissance" in document
    assert "no form submission" in document
    assert "no path brute forcing" in document


def test_web_section_shows_findings(document):
    assert "Acme Portal" in document
    assert "React" in document
    assert "content-security-policy" in document
    assert "/api/v1/orders" in document
    assert "/app.js.map" in document
    assert "POST /login" in document


def test_masked_secret_is_shown_and_explained(document):
    assert "9f2b********e8 (len 32)" in document
    assert "Values are masked" in document


def test_authorisation_notice_is_present(document):
    assert "Authorised engagement output" in document
    assert "not a verified vulnerability" in document


def test_report_stage_row_is_omitted_from_timings(document):
    assert "<code>sweep</code>" in document
    assert "<code>report</code>" not in document


def test_empty_run_renders_without_hosts():
    payload = _payload()
    payload["totals"]["hosts_reported"] = 0
    doc = render_html(payload, [], [], None)
    assert "No hosts responded" in doc
    assert "No services to categorise" in doc


# -- escaping ------------------------------------------------------------


def test_esc_escapes_markup_and_quotes():
    assert esc("<script>") == "&lt;script&gt;"
    assert esc('a"b') == "a&quot;b"
    assert esc("a'b") == "a&#x27;b"
    assert esc(None) == "&mdash;"


def test_a_hostile_page_title_cannot_inject_markup():
    """A scanned host controls its page title; the report must not execute it."""
    webrecon = _webrecon()
    webrecon["results"][0]["root"]["title"] = "<script>alert(document.domain)</script>"
    hosts = _hosts()
    doc = render_html(_payload(), hosts, group_by_category(hosts), webrecon)
    assert "<script>alert(document.domain)</script>" not in doc
    assert "&lt;script&gt;alert(document.domain)&lt;/script&gt;" in doc


def test_hostile_service_banner_is_escaped():
    hosts = _hosts()
    hosts[0].open_ports[0]["version"] = "<img src=x onerror=alert(1)>"
    doc = render_html(_payload(), hosts, group_by_category(hosts), None)
    assert "<img src=x onerror=alert(1)>" not in doc
    assert "&lt;img src=x onerror=alert(1)&gt;" in doc


def test_hostile_hostname_cannot_break_an_attribute():
    hosts = _hosts()
    hosts[0].hostnames = ["evil' onmouseover='alert(1)"]
    doc = render_html(_payload(), hosts, group_by_category(hosts), None)
    assert "onmouseover='alert(1)" not in doc


def test_hostile_javascript_path_is_escaped():
    webrecon = _webrecon()
    webrecon["results"][0]["scripts"][0]["endpoints"] = ["</pre><script>alert(1)</script>"]
    hosts = _hosts()
    doc = render_html(_payload(), hosts, group_by_category(hosts), webrecon)
    assert "</pre><script>alert(1)" not in doc


def test_hostile_http_header_is_escaped():
    webrecon = _webrecon()
    webrecon["results"][0]["root"]["disclosure_headers"] = {"server": "<svg onload=alert(1)>"}
    hosts = _hosts()
    doc = render_html(_payload(), hosts, group_by_category(hosts), webrecon)
    assert "<svg onload=alert(1)>" not in doc


def test_backticks_in_notes_become_code_not_markup():
    hosts = _hosts()
    hosts[0].notes = ["`3306/tcp` <b>bold</b> attempt"]
    doc = render_html(_payload(), hosts, group_by_category(hosts), None)
    assert "<code>3306/tcp</code>" in doc
    assert "<b>bold</b>" not in doc


# -- integration with build ---------------------------------------------


def test_build_writes_both_markdown_and_html(make_context):
    ctx = make_context(web=True)
    ctx.paths.live_hosts.write_text("10.10.10.5\n", encoding="utf-8")
    write_json(
        ctx.paths.open_ports,
        {"backend": "nmap", "hosts": {"10.10.10.5": [{"port": 80, "protocol": "tcp"}]}},
    )
    write_json(
        ctx.paths.services,
        {
            "services_identified": 1,
            "hosts": [
                {
                    "address": "10.10.10.5",
                    "ports": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "http", "label": "nginx 1.18.0"},
                        }
                    ],
                }
            ],
        },
    )
    payload = report_build.build(ctx)

    assert ctx.paths.report.is_file()
    assert ctx.paths.report_html.is_file()
    assert "Services by category" in ctx.paths.report.read_text()
    assert "Services by category" in ctx.paths.report_html.read_text()
    assert payload["totals"]["service_categories"] == 1
    assert payload["categories"][0]["key"] == "web"


def test_build_folds_webrecon_into_both_reports(make_context):
    ctx = make_context(web=True)
    ctx.paths.live_hosts.write_text("10.10.10.5\n", encoding="utf-8")
    write_json(
        ctx.paths.open_ports,
        {"backend": "nmap", "hosts": {"10.10.10.5": [{"port": 80, "protocol": "tcp"}]}},
    )
    webrecon = _webrecon()
    webrecon["results"][0]["ip"] = "10.10.10.5"
    webrecon["results"][0]["base_url"] = "http://10.10.10.5:80"
    write_json(ctx.paths.webrecon, webrecon)

    payload = report_build.build(ctx)

    host = payload["hosts"][0]
    assert host["web_endpoints"][0]["title"] == "Acme Portal"
    assert payload["totals"]["web_endpoints"] == 1

    notes = " ".join(host["notes"])
    assert "look like embedded credentials" in notes
    assert "no Content-Security-Policy" in notes
    assert "version disclosed via server" in notes

    markdown = ctx.paths.report.read_text()
    assert "Web endpoint `http://10.10.10.5:80`" in markdown
    assert "9f2b********e8" in markdown
    assert "Acme Portal" in ctx.paths.report_html.read_text()


def test_build_drops_webrecon_results_for_out_of_scope_hosts(make_context):
    ctx = make_context(web=True)
    webrecon = _webrecon()
    webrecon["results"][0]["ip"] = "192.168.99.99"
    write_json(ctx.paths.webrecon, webrecon)

    payload = report_build.build(ctx)
    assert all(h["ip"] != "192.168.99.99" for h in payload["hosts"])
    assert payload["totals"]["web_endpoints"] == 1  # counted, but not attributed


def test_summary_json_stays_machine_readable(make_context):
    ctx = make_context(web=True)
    ctx.paths.live_hosts.write_text("10.10.10.5\n", encoding="utf-8")
    write_json(
        ctx.paths.open_ports,
        {"backend": "nmap", "hosts": {"10.10.10.5": [{"port": 3306, "protocol": "tcp"}]}},
    )
    report_build.build(ctx)
    payload = json.loads(ctx.paths.summary.read_text())
    assert payload["categories"][0]["key"] == "database"
    assert payload["hosts"][0]["categories"] == ["database"]
