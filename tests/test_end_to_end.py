"""End-to-end tests against a real local HTTP server.

Every other test in this suite is hermetic. These are not: they bind a server
to 127.0.0.1 and let netrecon make real requests to it, because the properties
worth proving here only exist when the whole chain runs — a page is fetched, its
scripts are crawled, a source map is followed, the analysis runs, artifacts are
written, and the report is rendered from them.

They are still self-contained: the server is a fixture in this process, only
loopback is touched, and nothing external is contacted. Deselect them with::

    pytest -m "not e2e"

The scan stages that need nmap are skipped automatically when it is absent, so
the suite stays green on a machine without the external tools.
"""

from __future__ import annotations

import http.server
import json
import shutil
import socket
import threading
from pathlib import Path

import pytest

from netrecon.core.config import Config
from netrecon.core.jsonio import write_json
from netrecon.core.pipeline import build_context, execute
from netrecon.core.privileges import detect as detect_privileges
from netrecon.core.scope import Scope
from netrecon.core.tools import ToolRegistry

pytestmark = pytest.mark.e2e


# -- the fixture application --------------------------------------------

INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Acme Internal Portal</title>
<meta name="generator" content="Acme CMS 4.2">
</head><body>
<h1>Acme Internal Portal</h1>
<!-- TODO: move the staging config out of app.js before go-live -->
<form action="/login" method="post"><input name="user"><input name="pass"></form>
<script src="/static/app.js"></script>
<script src="/static/jquery-3.4.1.min.js"></script>
<script src="https://cdn.example.com/vendor/analytics.js"></script>
<script>window.__APP_ENV__ = "staging";</script>
</body></html>
"""

# Synthetic. The key is assembled so a secret scanner does not flag this file.
FAKE_API_KEY = "9f2b7c41" + "de8a46f0b35e7a19cc04d2e8"

APP_JS = """
const BASE = "/api/v2";
axios.post("/api/v2/orders?status=open", { customerId, amount, currency });
axios.get("/api/v2/orders", { params: { page: 1, size: 20 } });
fetch(`/api/v2/users/${userId}/roles`, {
  method: "PUT",
  credentials: "include",
  headers: { Authorization: "Bearer " + token, "X-Trace": traceId },
  body: JSON.stringify({ role, scope, expiresAt })
});
$.ajax({ url: "/legacy/report.php", type: "POST", data: { from, to } });
fetch("/graphql", { method: "POST", body: JSON.stringify({ query, variables }) });
const cfg = { api_key: "__API_KEY__", placeholder: "your_api_key_here" };
const DB = "mongodb://svcacct:Tr0ub4dor@10.20.30.40:27017/prod";
const SUPPORT = "lan.pham@acme.vn";
const STAGING = "https://staging.internal.acme.corp/api/v2";
import("/static/chunk-admin.js");
//# sourceMappingURL=/static/app.js.map
""".replace("__API_KEY__", FAKE_API_KEY)

# Only reachable by crawling app.js: nothing in the HTML links it.
CHUNK_JS = """
axios.post("/api/v2/admin/users", { email, role, tenantId, sendInvite });
fetch("/api/v2/admin/audit?from=2024-01-01", { method: "GET" });
"""

# Only reachable by following the source map: these strings are not in app.js.
APP_JS_MAP = json.dumps(
    {
        "version": 3,
        "sources": ["src/config.js"],
        "sourcesContent": [
            'export const VAULT = "https://vault.internal.acme.corp/v1/secret";\n'
            'export const OPS = "ops.team@acme.vn";\n'
        ],
        "names": [],
        "mappings": "",
    }
)

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /api/internal\n"

SITE_FILES: dict[str, str] = {
    "index.html": INDEX_HTML,
    "robots.txt": ROBOTS,
    "static/app.js": APP_JS,
    "static/chunk-admin.js": CHUNK_JS,
    "static/app.js.map": APP_JS_MAP,
    "static/jquery-3.4.1.min.js": "/*! jQuery v3.4.1 */\n",
    ".git/HEAD": "ref: refs/heads/main\n",
    # robots.txt disallows /admin; serve it so the published-path probe gets a
    # classifiable response instead of a 404 that carries no information.
    "admin/index.html": "<html><title>Admin</title></html>\n",
}


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # noqa: ANN002 - stdlib signature
        """Keep the fixture server out of pytest's captured output."""


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> tuple[str, int]:
    """Serve the fixture application on a loopback port for this module."""
    root = tmp_path_factory.mktemp("site")
    for name, content in SITE_FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    handler = type("Handler", (_QuietHandler,), {"directory": str(root)})

    def build(*args, **kwargs):
        return handler(*args, directory=str(root), **kwargs)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), build)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]

    # Fail fast and clearly if the port never came up.
    with socket.create_connection((host, port), timeout=5):
        pass

    yield host, port

    server.shutdown()
    server.server_close()


@pytest.fixture()
def run_dir(tmp_path: Path) -> Path:
    path = tmp_path / "results" / "e2e" / "20240520T101320Z"
    path.mkdir(parents=True)
    return path


def _context(run_dir: Path, host: str, port: int, **config_overrides):
    """A context wired to the fixture server, with the scan stages pre-seeded."""
    config = Config()
    for section, values in config_overrides.items():
        for key, value in values.items():
            setattr(getattr(config, section), key, value)
    config.validate()

    scope = Scope.from_lines([host], source="fixture")
    ctx = build_context(
        config=config,
        scope=scope,
        run_dir=run_dir,
        resuming=False,
        tools=ToolRegistry.detect(),
        privileges=detect_privileges(),
        active=False,
        web=True,
        full_ports=False,
        dry_run=False,
    )
    # Stand in for discovery, the sweep and -sV so the web stages have an input
    # without needing nmap. Those stages have their own tests; the service
    # record is what nmap would report for this server on an ephemeral port.
    ctx.paths.live_hosts.write_text(f"{host}\n", encoding="utf-8")
    write_json(
        ctx.paths.open_ports,
        {"backend": "fixture", "hosts": {host: [{"port": port, "protocol": "tcp"}]}},
    )
    write_json(
        ctx.paths.services,
        {
            "services_identified": 1,
            "hosts": [
                {
                    "address": host,
                    "hostnames": [],
                    "ports": [
                        {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {
                                "name": "http",
                                "product": "SimpleHTTP",
                                "version": "0.6",
                                "label": "SimpleHTTP 0.6",
                            },
                        }
                    ],
                }
            ],
        },
    )
    return ctx


# -- the web pipeline, for real -----------------------------------------


@pytest.fixture(scope="module")
def web_run(tmp_path_factory, site) -> dict:
    """Run webrecon + servicerecon + report once; assert on it many times."""
    from netrecon.stages import servicerecon, webrecon

    host, port = site
    run_dir = tmp_path_factory.mktemp("run")
    ctx = _context(
        run_dir,
        host,
        port,
        webrecon={"hidden_paths": True, "max_hidden_paths": 60, "rate_per_second": 50.0},
    )
    webrecon.run(ctx)
    try:
        servicerecon.run(ctx)
    except Exception:  # noqa: BLE001 - no -sV data here; not what this test covers
        pass

    from netrecon.report import build as report_build

    report_build.build(ctx)
    return {
        "ctx": ctx,
        "webrecon": json.loads(ctx.paths.webrecon.read_text()),
        "summary": json.loads(ctx.paths.summary.read_text()),
        "host": host,
        "port": port,
    }


def test_every_artifact_is_written(web_run):
    paths = web_run["ctx"].paths
    for path in (
        paths.webrecon,
        paths.api_structure,
        paths.api_endpoints,
        paths.js_endpoints,
        paths.parameters_json,
        paths.parameters_txt,
        paths.js_findings,
        paths.summary,
        paths.report,
        paths.report_html,
    ):
        assert path.is_file(), path
        assert path.stat().st_size > 0, path


def test_the_endpoint_was_actually_reached(web_run):
    result = next(r for r in web_run["webrecon"]["results"] if not r.get("error"))
    assert result["root"]["status"] == 200
    assert result["root"]["title"] == "Acme Internal Portal"


def test_both_schemes_were_tried_and_https_failed_on_a_cleartext_port(web_run):
    schemes = {r["scheme"] for r in web_run["webrecon"]["results"]}
    assert schemes == {"http", "https"}
    https = next(r for r in web_run["webrecon"]["results"] if r["scheme"] == "https")
    assert https["error"], "TLS against a cleartext port must fail, not hang"


# -- crawling ------------------------------------------------------------


def test_a_lazy_loaded_chunk_is_found_by_crawling(web_run):
    """chunk-admin.js is referenced only from inside app.js, never from the HTML."""
    sources = {s.get("source", "") for r in web_run["webrecon"]["results"]
               for s in (r.get("scripts") or [])}
    assert any("chunk-admin.js" in s for s in sources)


def test_the_source_map_was_followed(web_run):
    """Its sourcesContent holds strings that appear nowhere in the bundle."""
    hosts = set(web_run["webrecon"]["hosts_referenced"])
    assert "vault.internal.acme.corp" in hosts, (
        "this host exists only in the source map's original sources"
    )


def test_a_third_party_script_is_never_fetched(web_run):
    """cdn.example.com is out of scope, so it must not be contacted."""
    sources = {s.get("source", "") for r in web_run["webrecon"]["results"]
               for s in (r.get("scripts") or [])}
    assert not any("cdn.example.com" in s for s in sources)


# -- API reconstruction --------------------------------------------------


def test_api_endpoints_are_reconstructed_with_methods_and_parameters(web_run):
    structure = json.loads(web_run["ctx"].paths.api_structure.read_text())
    by_path = {e["path"]: e for e in structure["endpoints"]}

    orders = by_path["/api/v2/orders"]
    assert orders["methods"] == ["GET", "POST"]
    assert set(orders["body_params"]) == {"customerId", "amount", "currency"}
    assert set(orders["query_params"]) >= {"status", "page", "size"}

    roles = by_path["/api/v2/users/{userId}/roles"]
    assert roles["methods"] == ["PUT"]
    assert roles["path_params"] == ["userId"]
    assert set(roles["body_params"]) == {"role", "scope", "expiresAt"}


def test_request_headers_never_become_parameters(web_run):
    """headers:{Authorization: ...} must not read as a body parameter."""
    structure = json.loads(web_run["ctx"].paths.api_structure.read_text())
    every_param = {
        name
        for endpoint in structure["endpoints"]
        for key in ("body_params", "query_params", "path_params")
        for name in endpoint[key]
    }
    assert "Authorization" not in every_param
    assert "X-Trace" not in every_param
    assert "credentials" not in every_param
    assert "headers" not in every_param


def test_a_graphql_body_keeps_its_query_and_variables(web_run):
    structure = json.loads(web_run["ctx"].paths.api_structure.read_text())
    graphql = next(e for e in structure["endpoints"] if e["path"] == "/graphql")
    assert set(graphql["body_params"]) == {"query", "variables"}


def test_endpoints_from_the_crawled_chunk_are_included(web_run):
    structure = json.loads(web_run["ctx"].paths.api_structure.read_text())
    paths = {e["path"] for e in structure["endpoints"]}
    assert "/api/v2/admin/users" in paths
    assert "/api/v2/admin/audit" in paths


def test_the_parameter_wordlist_is_plain_names(web_run):
    lines = web_run["ctx"].paths.parameters_txt.read_text().split()
    assert lines == sorted(set(lines), key=lines.index), "no duplicates"
    assert all(line.isidentifier() for line in lines), lines
    assert {"customerId", "tenantId", "expiresAt"} <= set(lines)


def test_the_parameter_index_records_where_each_name_is_accepted(web_run):
    parameters = json.loads(web_run["ctx"].paths.parameters_json.read_text())["parameters"]
    by_name = {p["name"]: p for p in parameters}
    assert by_name["role"]["endpoint_count"] >= 2, "role is accepted by two endpoints"
    assert "body" in by_name["role"]["kinds"]


# -- findings ------------------------------------------------------------


def test_a_hardcoded_secret_is_found_and_masked(web_run):
    secrets = json.loads(web_run["ctx"].paths.js_findings.read_text())["secrets"]
    kinds = {s["kind"] for s in secrets}
    assert "assigned_secret" in kinds
    for secret in secrets:
        assert FAKE_API_KEY not in secret["value"]
        assert FAKE_API_KEY not in (secret.get("context") or "")


def test_a_placeholder_is_not_reported_as_a_secret(web_run):
    secrets = json.loads(web_run["ctx"].paths.js_findings.read_text())["secrets"]
    reported = {s["value"] for s in secrets} | {s.get("name") for s in secrets}
    assert "your_api_key_here" not in reported


def test_personal_data_is_found_and_masked(web_run):
    pii = json.loads(web_run["ctx"].paths.js_findings.read_text())["pii"]
    assert {p["kind"] for p in pii} >= {"email"}
    for entry in pii:
        assert "lan.pham@acme.vn" != entry["value"]
        assert entry["value"].endswith("@acme.vn"), "the domain is the useful part"


def test_internal_infrastructure_is_reported(web_run):
    hosts = set(web_run["webrecon"]["hosts_referenced"])
    assert "staging.internal.acme.corp" in hosts
    assert "10.20.30.40" in hosts


def test_a_sensitive_path_is_found_when_probing_is_enabled(web_run):
    result = next(r for r in web_run["webrecon"]["results"] if not r.get("error"))
    accessible = [p for p in result["hidden_paths"] if p["classification"] == "accessible"]
    assert any(p["path"] == "/.git/HEAD" for p in accessible)
    assert any(p["high_value"] for p in accessible)


def test_published_paths_are_followed_without_guessing(web_run):
    result = next(r for r in web_run["webrecon"]["results"] if not r.get("error"))
    origins = {p["origin"] for p in result["hidden_paths"]}
    assert "robots" in origins, "/admin is published in robots.txt"


def test_the_technology_stack_is_identified_with_versions(web_run):
    technologies = set(web_run["webrecon"]["technologies"])
    assert any(t.startswith("jQuery 3.4.1") for t in technologies), technologies


# -- the report ----------------------------------------------------------


def test_the_summary_totals_match_the_artifacts(web_run):
    totals = web_run["summary"]["totals"]
    structure = json.loads(web_run["ctx"].paths.api_structure.read_text())
    parameters = json.loads(web_run["ctx"].paths.parameters_json.read_text())["parameters"]
    assert totals["api_endpoints"] == len(structure["endpoints"])
    assert totals["api_parameters"] == len(parameters)
    assert totals["web_endpoints"] == 1


def test_the_markdown_report_carries_the_api_surface(web_run):
    text = web_run["ctx"].paths.report.read_text()
    assert "## API surface reconstructed from front-end code" in text
    assert "## Parameter index" in text
    assert "/api/v2/users/{userId}/roles" in text


def test_the_html_report_is_self_contained_and_escaped(web_run):
    import re

    html = web_run["ctx"].paths.report_html.read_text()
    assert html.startswith("<!doctype html>")
    assert re.findall(r"""(?:src|href)\s*=\s*["'](https?://[^"']+)""", html) == []
    assert FAKE_API_KEY not in html, "a secret must never reach the report unmasked"


def test_the_run_directory_holds_the_fetched_evidence(web_run):
    saved = list(web_run["ctx"].paths.webrecon_dir.rglob("*"))
    names = {p.name for p in saved if p.is_file()}
    assert "root.body" in names
    assert any(n.endswith("app.js") for n in names)
    assert "robots.txt" in names


# -- the full CLI, when the external tools are present ------------------


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
def test_the_whole_pipeline_runs_against_the_fixture_server(tmp_path, site):
    """Discovery through reporting, with the real scan stages."""
    host, port = site
    config = Config()
    config.run_name = "e2e"
    config.output_dir = str(tmp_path / "results")
    config.ports.sweep = str(port)
    config.discovery.method = "skip"
    config.stages.servicerecon = True
    config.stages.webrecon = True
    config.sweep.backend = "nmap"
    config.webrecon.rate_per_second = 50.0
    config.validate()

    run_dir = tmp_path / "results" / "e2e" / "20240520T101320Z"
    run_dir.mkdir(parents=True)
    ctx = build_context(
        config=config,
        scope=Scope.from_lines([host], source="fixture"),
        run_dir=run_dir,
        resuming=False,
        tools=ToolRegistry.detect(),
        privileges=detect_privileges(),
        active=False,
        web=True,
        full_ports=False,
        dry_run=False,
    )
    outcome = execute(ctx)

    assert outcome.ok, outcome.failed_stages
    summary = json.loads(ctx.paths.summary.read_text())
    assert summary["totals"]["live_hosts"] == 1
    assert summary["totals"]["open_ports"] == 1
    assert summary["totals"]["api_endpoints"] >= 5
    assert ctx.paths.report_html.is_file()

    state = json.loads((ctx.paths.root / "state.json").read_text())
    assert state["stages"]["webrecon"]["status"] == "completed"
    assert state["stages"]["servicerecon"]["status"] == "completed"


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
def test_a_host_outside_the_scope_is_never_contacted(tmp_path, site):
    """The invariant, proved against a live server rather than a mock.

    The scope holds an address the fixture server does not listen on, and the
    server's real address is left out. Nothing may reach it.
    """
    host, port = site
    config = Config()
    config.run_name = "e2e-scope"
    config.output_dir = str(tmp_path / "results")
    config.ports.sweep = str(port)
    config.discovery.method = "skip"
    config.stages.webrecon = True
    config.validate()

    run_dir = tmp_path / "results" / "e2e-scope" / "20240520T101320Z"
    run_dir.mkdir(parents=True)
    # 127.0.0.2 is loopback but not where the fixture server is bound.
    ctx = build_context(
        config=config,
        scope=Scope.from_lines(["127.0.0.2"], source="fixture"),
        run_dir=run_dir,
        resuming=False,
        tools=ToolRegistry.detect(),
        privileges=detect_privileges(),
        active=False,
        web=True,
        full_ports=False,
        dry_run=False,
    )
    execute(ctx)

    summary = json.loads(ctx.paths.summary.read_text())
    assert host not in json.dumps(summary), "an out-of-scope address reached the report"
    assert summary["totals"]["api_endpoints"] == 0
