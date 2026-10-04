"""Tests for the read-only web recon stage.

Nothing here opens a socket: the HTTP client is replaced with a fake, and the
analysis functions are pure. The point of most of these tests is the stage's
boundaries - that it stays on the authorised endpoint and never escalates
beyond a GET.
"""

from __future__ import annotations

import pytest

from netrecon.core.config import (
    WEBRECON_RATE_HARD_MAX,
    WEBRECON_RESPONSE_BYTES_HARD_MAX,
    Config,
    ConfigError,
)
from netrecon.core.jsonio import write_json
from netrecon.stages import webrecon
from netrecon.stages.base import StageSkipped
from netrecon.stages.webrecon import (
    Endpoint,
    HttpResponse,
    RateLimiter,
    _PageParser,
    _same_endpoint_scripts,
    analyse_script,
    detect_technologies,
    disclosure_headers,
    load_endpoints,
    mask_secret,
    missing_security_headers,
)

IN_SCOPE = "10.10.10.5"
OUT_OF_SCOPE = "192.168.99.99"


# -- JavaScript analysis -------------------------------------------------


def test_api_paths_are_extracted():
    body = """
      const base = "/api/v2";
      fetch("/api/v2/users/me");
      axios.get("/admin/export.json");
      const g = "/graphql";
    """
    result = analyse_script(body, source="app.js", redact=True)
    assert "/api/v2" in result["endpoints"]
    assert "/api/v2/users/me" in result["endpoints"]
    assert "/admin/export.json" in result["endpoints"]
    assert "/graphql" in result["endpoints"]


def test_absolute_urls_are_extracted():
    result = analyse_script('var u = "https://api.internal.example/v1/token";', source="s", redact=True)
    assert "https://api.internal.example/v1/token" in result["endpoints"]


def test_endpoints_are_deduplicated_and_sorted():
    body = 'fetch("/a/x.json"); fetch("/a/x.json"); fetch("/b/y.json");'
    endpoints = analyse_script(body, source="s", redact=True)["endpoints"]
    assert endpoints == sorted(set(endpoints))


def test_source_maps_are_reported():
    body = "var a=1;\n//# sourceMappingURL=/static/app.js.map"
    assert analyse_script(body, source="s", redact=True)["source_maps"] == ["/static/app.js.map"]


#: Token shapes, assembled at runtime from halves.
#:
#: These are invented values, but they are shaped closely enough to the real
#: thing that a secret scanner flags them - which is the point of the patterns
#: under test. Splitting each one across a concatenation keeps the literal out
#: of the source file so this test suite does not itself trip push protection.
TOKEN_SHAPES: list[tuple[str, str]] = [
    ("AKIA" + "ZZ7QQQ3MMMNNN42X", "aws_access_key_id"),
    ("AIza" + "SyB1c3fFakeFakeFakeFakeFakeFakeQ7zX", "google_api_key"),
    ("xox" + "b-99887766554433-aabbccddeeffgg", "slack_token"),
    ("ghp" + "_7f3Kq92ZmWvQ4tLbN8xRcY1dAe6JhS0uPgTz", "github_token"),
    ("sk" + "_live_9Qw3ErTy7UiOpAsDfGhJkL2z", "stripe_key"),
    ("-----BEGIN RSA " + "PRIVATE KEY-----", "private_key_block"),
]


@pytest.mark.parametrize(("token", "kind"), TOKEN_SHAPES, ids=[k for _, k in TOKEN_SHAPES])
def test_secret_shapes_are_detected(token, kind):
    found = analyse_script(f'k = "{token}"', source="s", redact=False)["secret_candidates"]
    assert kind in {item["kind"] for item in found}


def test_detected_tokens_are_masked_in_the_report():
    for token, _kind in TOKEN_SHAPES:
        found = analyse_script(f'k = "{token}"', source="s", redact=True)["secret_candidates"]
        for item in found:
            assert token not in item["value"], "a masked value must not contain the token"


def test_assigned_secrets_record_the_variable_name():
    body = 'const config = { api_key: "9f2b7c41de8a46f0b35e7a19cc04d2e8" };'
    found = analyse_script(body, source="s", redact=False)["secret_candidates"]
    entry = next(item for item in found if item["kind"] == "assigned_secret")
    assert entry["name"] == "api_key"
    assert entry["value"] == "9f2b7c41de8a46f0b35e7a19cc04d2e8"


def test_secrets_are_masked_by_default():
    body = 'api_key = "9f2b7c41de8a46f0b35e7a19cc04d2e8"'
    found = analyse_script(body, source="s", redact=True)["secret_candidates"]
    value = found[0]["value"]
    assert "9f2b7c41de8a46f0b35e7a19cc04d2e8" not in value
    assert value.startswith("9f2b")
    assert "len 32" in value


def test_mask_keeps_short_values_unusable():
    assert "secret12" not in mask_secret("secret12")
    assert mask_secret("abcd") == "ab**"


@pytest.mark.parametrize(
    "placeholder",
    [
        'api_key = "your_api_key_here"',
        'api_key = "YOUR_KEY"',
        'api_key = "xxxxxxxxxxxx"',
        'api_key = "<insert-key>"',
        'api_key = "${API_KEY}"',
        'api_key = "example-key-value"',
        'api_key = "aaaaaaaaaaaa"',
        'api_key = "undefined"',
    ],
)
def test_obvious_placeholders_are_not_reported(placeholder):
    assert analyse_script(placeholder, source="s", redact=True)["secret_candidates"] == []


def test_the_documented_aws_example_key_is_treated_as_a_placeholder():
    body = 'k = "AKIAIOSFODNN7EXAMPLE"'
    assert analyse_script(body, source="s", redact=True)["secret_candidates"] == []


def test_line_numbers_are_recorded():
    body = 'var a = 1;\nvar b = 2;\napi_key = "9f2b7c41de8a46f0b35e7a19cc04d2e8";'
    found = analyse_script(body, source="s", redact=True)["secret_candidates"]
    assert found[0]["line"] == "3"


def test_duplicate_secrets_are_reported_once():
    body = (
        'api_key = "9f2b7c41de8a46f0b35e7a19cc04d2e8";\n'
        'apikey = "9f2b7c41de8a46f0b35e7a19cc04d2e8";'
    )
    found = analyse_script(body, source="s", redact=True)["secret_candidates"]
    assert len(found) == 1


def test_analysis_of_an_empty_body_is_empty():
    result = analyse_script("", source="s", redact=True)
    assert result["endpoints"] == []
    assert result["secret_candidates"] == []
    assert result["bytes"] == 0


# -- header analysis -----------------------------------------------------


def test_missing_security_headers():
    missing = missing_security_headers({"content-security-policy": "default-src 'self'"})
    assert "content-security-policy" not in missing
    assert "x-frame-options" in missing


def test_disclosure_headers_are_picked_out():
    headers = {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1", "date": "now"}
    assert disclosure_headers(headers) == {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1"}


def test_technology_detection_from_headers_and_body():
    tech = detect_technologies({"server": "nginx/1.18.0"}, "<div data-reactroot>/_next/static</div>")
    assert "React" in tech
    assert "Next.js" in tech
    assert "Server: nginx/1.18.0" in tech


# -- HTML parsing --------------------------------------------------------


def test_page_parser_extracts_what_the_report_shows():
    parser = _PageParser()
    parser.feed(
        '<html><head><title>Portal</title>'
        '<meta name="generator" content="Acme CMS 4.2"></head><body>'
        "<!-- staging note -->"
        '<form action="/login" method="post"></form>'
        '<script src="/static/app.js"></script>'
        '<script>var inline = 1;</script></body></html>'
    )
    assert parser.title == "Portal"
    assert parser.generator == "Acme CMS 4.2"
    assert parser.script_srcs == ["/static/app.js"]
    assert parser.inline_scripts == ["var inline = 1;"]
    assert parser.form_actions == ["POST /login"]
    assert parser.comments == ["staging note"]


def test_page_parser_survives_malformed_html():
    parser = _PageParser()
    parser.feed("<html><title>Broken<body><script src=x.js>")
    parser.close()
    assert parser.title is not None
    assert parser.title.startswith("Broken")


# -- staying on the authorised endpoint ---------------------------------


def test_only_same_endpoint_scripts_are_fetched():
    endpoint = Endpoint(ip=IN_SCOPE, port=8080, scheme="http")
    srcs = [
        "/static/app.js",
        "bundle.js",
        f"http://{IN_SCOPE}:8080/abs.js",
        "https://cdn.example.com/jquery.min.js",
        f"http://{OUT_OF_SCOPE}:8080/evil.js",
        f"http://{IN_SCOPE}:9999/other-port.js",
        "data:text/javascript,alert(1)",
        "javascript:alert(1)",
    ]
    kept = _same_endpoint_scripts(srcs, endpoint)
    assert kept == [
        f"http://{IN_SCOPE}:8080/static/app.js",
        f"http://{IN_SCOPE}:8080/bundle.js",
        f"http://{IN_SCOPE}:8080/abs.js",
    ]


def test_a_cdn_script_is_never_fetched():
    endpoint = Endpoint(ip=IN_SCOPE, port=80, scheme="http")
    assert _same_endpoint_scripts(["https://cdn.jsdelivr.net/x.js"], endpoint) == []


def test_script_urls_are_deduplicated():
    endpoint = Endpoint(ip=IN_SCOPE, port=80, scheme="http")
    kept = _same_endpoint_scripts(["/a.js", "/a.js", f"http://{IN_SCOPE}:80/a.js"], endpoint)
    assert len(kept) == 1


def test_ipv6_endpoint_url_is_bracketed():
    endpoint = Endpoint(ip="2001:db8::1", port=8443, scheme="https")
    assert endpoint.base_url == "https://[2001:db8::1]:8443"


# -- endpoint discovery --------------------------------------------------


def _seed(ctx, services_hosts=None, sweep_hosts=None):
    if services_hosts is not None:
        write_json(ctx.paths.services, {"hosts": services_hosts})
    if sweep_hosts is not None:
        write_json(ctx.paths.open_ports, {"hosts": sweep_hosts})


def test_endpoints_come_from_service_data_with_scheme(make_context):
    ctx = make_context(web=True)
    _seed(
        ctx,
        services_hosts=[
            {
                "address": IN_SCOPE,
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": {"name": "http"}},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": {"name": "https"}},
                    {"port": 22, "protocol": "tcp", "state": "open", "service": {"name": "ssh"}},
                ],
            }
        ],
    )
    endpoints = load_endpoints(ctx)
    assert [(e.port, e.scheme) for e in endpoints] == [(80, "http"), (443, "https")]


def test_out_of_scope_hosts_never_become_endpoints(make_context):
    ctx = make_context(web=True)
    _seed(
        ctx,
        services_hosts=[
            {
                "address": OUT_OF_SCOPE,
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": {"name": "http"}}
                ],
            }
        ],
    )
    assert load_endpoints(ctx) == []


def test_sweep_data_fills_in_ports_without_service_detection(make_context):
    ctx = make_context(web=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 8080, "protocol": "tcp"}]})
    endpoints = load_endpoints(ctx)
    assert [(e.ip, e.port, e.scheme) for e in endpoints] == [(IN_SCOPE, 8080, "http")]


def test_service_data_wins_over_sweep_data(make_context):
    ctx = make_context(web=True)
    _seed(
        ctx,
        services_hosts=[
            {
                "address": IN_SCOPE,
                "ports": [
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "http", "tunnel": "ssl"},
                    }
                ],
            }
        ],
        sweep_hosts={IN_SCOPE: [{"port": 8080, "protocol": "tcp"}]},
    )
    endpoints = load_endpoints(ctx)
    assert len(endpoints) == 1
    assert endpoints[0].scheme == "https", "the TLS tunnel from -sV must be honoured"


def test_closed_ports_are_not_endpoints(make_context):
    ctx = make_context(web=True)
    _seed(
        ctx,
        services_hosts=[
            {
                "address": IN_SCOPE,
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "closed", "service": {"name": "http"}}
                ],
            }
        ],
    )
    assert load_endpoints(ctx) == []


# -- stage gating --------------------------------------------------------


def test_stage_requires_the_web_flag(make_context):
    ctx = make_context(web=False)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    with pytest.raises(StageSkipped, match="--web"):
        webrecon.run(ctx)


def test_stage_skips_when_there_is_nothing_to_probe(make_context):
    ctx = make_context(web=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 22, "protocol": "tcp"}]})
    with pytest.raises(StageSkipped, match="no in-scope HTTP"):
        webrecon.run(ctx)


def test_dry_run_sends_nothing(make_context, monkeypatch):
    ctx = make_context(web=True, dry_run=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})

    def explode(*_args, **_kwargs):
        raise AssertionError("no request may be made during a dry run")

    monkeypatch.setattr(webrecon.GetOnlyClient, "get", explode)
    result = webrecon.run(ctx)
    assert result.detail == "dry run"
    assert not ctx.paths.webrecon.exists()


# -- end to end with a fake client --------------------------------------


class FakeClient:
    """Stands in for GetOnlyClient; records every URL it is asked for."""

    def __init__(self, pages: dict[str, tuple[int, str, dict[str, str]]]) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def get(self, url: str) -> HttpResponse:
        self.requested.append(url)
        if url not in self.pages:
            return HttpResponse(url, 404, "Not Found", {}, b"", False, 0.0)
        status, body, headers = self.pages[url]
        return HttpResponse(url, status, "OK", headers, body.encode(), False, 0.01)


def test_stage_probes_only_allowed_paths(make_context, monkeypatch):
    ctx = make_context(web=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    base = f"http://{IN_SCOPE}:80"

    client = FakeClient(
        {
            f"{base}/": (
                200,
                '<html><title>App</title><script src="/app.js"></script>'
                '<script src="https://cdn.example.com/x.js"></script></html>',
                {"server": "nginx/1.18.0"},
            ),
            f"{base}/robots.txt": (200, "User-agent: *\nDisallow: /admin\n", {}),
            f"{base}/app.js": (200, 'fetch("/api/v1/me"); key = "9f2b7c41de8a46f0b35e7a19cc04d2e8";', {}),
        }
    )
    monkeypatch.setattr(webrecon, "GetOnlyClient", lambda **_kwargs: client)

    result = webrecon.run(ctx)

    assert client.requested == [
        f"{base}/",
        f"{base}/robots.txt",
        f"{base}/sitemap.xml",
        f"{base}/app.js",
    ], "only '/', the two well-known files and the page's own script may be requested"
    assert "https://cdn.example.com/x.js" not in client.requested
    assert result.counts["endpoints_reachable"] == 1
    assert result.counts["js_endpoints"] >= 1
    assert result.counts["secret_candidates"] == 1


def test_stage_output_records_the_method_and_limits(make_context, monkeypatch):
    import json

    ctx = make_context(web=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    client = FakeClient({f"http://{IN_SCOPE}:80/": (200, "<html></html>", {})})
    monkeypatch.setattr(webrecon, "GetOnlyClient", lambda **_kwargs: client)

    webrecon.run(ctx)
    payload = json.loads(ctx.paths.webrecon.read_text())
    assert "GET only" in payload["method"]
    assert payload["limits"]["rate_per_second"] == ctx.config.webrecon.rate_per_second
    assert payload["limits"]["redact_secrets"] is True


def test_redirects_are_recorded_not_followed(make_context, monkeypatch):
    import json

    ctx = make_context(web=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    client = FakeClient(
        {
            f"http://{IN_SCOPE}:80/": (
                302,
                "",
                {"location": "https://elsewhere.example.com/login"},
            )
        }
    )
    monkeypatch.setattr(webrecon, "GetOnlyClient", lambda **_kwargs: client)

    webrecon.run(ctx)
    payload = json.loads(ctx.paths.webrecon.read_text())
    root = payload["results"][0]["root"]
    assert root["redirect_to"] == "https://elsewhere.example.com/login"
    assert not any("elsewhere.example.com" in url for url in client.requested)


def test_unreachable_endpoint_is_reported_not_fatal(make_context, monkeypatch):
    ctx = make_context(web=True)
    _seed(ctx, sweep_hosts={IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})

    class Dead:
        def get(self, url):
            raise webrecon.WebReconError("ConnectionRefusedError: [Errno 111]")

    monkeypatch.setattr(webrecon, "GetOnlyClient", lambda **_kwargs: Dead())
    result = webrecon.run(ctx)
    assert result.counts["endpoints_reachable"] == 0
    assert result.counts["failures"] == 1


def test_max_endpoints_truncates(make_context, monkeypatch):
    ctx = make_context(web=True)
    ctx.config.webrecon.max_endpoints = 2
    _seed(
        ctx,
        sweep_hosts={
            "10.10.10.5": [{"port": 80, "protocol": "tcp"}, {"port": 8080, "protocol": "tcp"}],
            "10.10.10.6": [{"port": 80, "protocol": "tcp"}],
        },
    )
    client = FakeClient({})
    monkeypatch.setattr(webrecon, "GetOnlyClient", lambda **_kwargs: client)
    result = webrecon.run(ctx)
    assert result.counts["endpoints_probed"] == 2


# -- rate limiting -------------------------------------------------------


def test_rate_limiter_spaces_requests_out():
    import time

    limiter = RateLimiter(50.0)  # 20 ms apart
    started = time.monotonic()
    for _ in range(4):
        limiter.wait()
    assert time.monotonic() - started >= 0.05


def test_rate_limiter_of_zero_does_not_block():
    import time

    limiter = RateLimiter(0)
    started = time.monotonic()
    limiter.wait()
    assert time.monotonic() - started < 0.05


# -- configuration caps --------------------------------------------------


def test_webrecon_rate_is_clamped():
    config = Config.from_dict({"webrecon": {"rate_per_second": 10_000}})
    assert config.webrecon.rate_per_second == WEBRECON_RATE_HARD_MAX
    assert any("clamped" in w for w in config.warnings)


def test_webrecon_response_size_is_clamped():
    config = Config.from_dict({"webrecon": {"max_response_bytes": 10**9}})
    assert config.webrecon.max_response_bytes == WEBRECON_RESPONSE_BYTES_HARD_MAX


def test_turning_redaction_off_warns():
    config = Config.from_dict({"webrecon": {"redact_secrets": False}})
    assert any("redact_secrets is off" in w for w in config.warnings)


@pytest.mark.parametrize(
    "bad",
    [
        {"rate_per_second": 0},
        {"max_endpoints": 0},
        {"max_scripts_per_endpoint": 0},
        {"max_response_bytes": 10},
        {"request_timeout_seconds": 0},
        {"user_agent": "   "},
    ],
)
def test_invalid_webrecon_config_is_rejected(bad):
    with pytest.raises(ConfigError):
        Config.from_dict({"webrecon": bad})


def test_webrecon_stage_is_off_by_default():
    assert Config().stages.webrecon is False


def test_template_blocklist_still_applies_to_nuclei():
    # The web stage must not have loosened the existing nuclei policy.
    from netrecon.stages.nuclei import validate_templates

    with pytest.raises(Exception):
        validate_templates(["fuzzing/"])
