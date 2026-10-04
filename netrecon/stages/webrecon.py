"""Stage 8: read-only web reconnaissance and front-end analysis.

What this stage does:

* One HTTP **GET** of ``/`` per in-scope web endpoint, plus ``robots.txt`` and
  ``sitemap.xml``. With ``probe_both_schemes`` each open web port is tried over
  both http and https rather than guessing a scheme from the port number.
* Records the status line, response headers, page title, technology stack with
  versions, version-disclosing headers, absent security headers, forms (recorded,
  never submitted) and HTML comments.
* Collects front-end assets that live on the **same in-scope endpoint**: linked
  scripts, and the source maps those scripts reference. Source maps carry the
  original unminified sources, so they are usually the richest artifact.
* Runs :mod:`netrecon.analyze.jsdata` over every asset: the API surface, strings
  shaped like credentials, personal data, and internal hostnames or private
  addresses the code refers to.
* With ``--hidden-paths``, requests a short curated list of commonly exposed
  files (see :mod:`netrecon.stages.wellknown`).

What this stage never does:

* No request method other than GET. No form submission, no authentication, no
  credential or session handling.
* No redirect following. A ``Location`` header is recorded and left alone, so a
  redirect cannot walk the scan off the authorised endpoint.
* No request to any address outside the expanded in-scope set. Every endpoint is
  re-checked with ``enforce_strict`` immediately before the socket is opened,
  and the URL host is always the in-scope IP literal, never a name. Hostnames
  discovered in front-end code are **reported, never contacted** - they are out
  of scope until the operator adds them to the scope file.
* No parameter fuzzing and no injection payloads, ever.

**On path probing.** By default the only paths requested are ``/``, the two
well-known files, assets the page itself linked, and paths the site published in
its own robots.txt and sitemap.xml - none of which is guessing. ``--hidden-paths``
additionally tries a curated list, capped at 400 entries and rate-limited. That
is path probing and it *will* appear as 404s in the target's access log; it is
off by default and announced in the pre-flight summary. It is not, and must not
become, a directory brute-force wordlist.

Everything is capped: endpoints per run, scripts per endpoint, paths per
endpoint, bytes per response, requests per second, and per-request timeout.
"""

from __future__ import annotations

import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from netrecon.analyze import apistructure, jsdata, techstack
from netrecon.analyze.jsdata import JsAnalysis
from netrecon.core.jsonio import read_json, write_json, write_lines
from netrecon.core.runner import RunContext, run_parallel
from netrecon.core.state import utc_now
from netrecon.report.categories import is_tls, is_web_service
from netrecon.stages.base import StageResult, StageSkipped
from netrecon.stages.wellknown import (
    PathCandidate,
    classify_response,
    curated_paths,
    paths_from_robots,
    paths_from_sitemap,
)

NAME = "webrecon"

#: The only paths netrecon requests on its own initiative. Everything else
#: comes from a reference the page itself published.
WELL_KNOWN_PATHS: tuple[str, ...] = ("/robots.txt", "/sitemap.xml")

#: Security headers whose absence is worth reporting.
SECURITY_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

#: Response headers that commonly disclose software and version.
DISCLOSURE_HEADERS: tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "via",
)

class WebReconError(Exception):
    """A web recon request could not be completed."""


# -- HTML parsing --------------------------------------------------------


class _PageParser(HTMLParser):
    """Pulls the few elements this stage reports on out of an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self.generator: str | None = None
        self.form_actions: list[str] = []
        self.comments: list[str] = []
        self._in_title = False
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): (value or "") for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            src = attributes.get("src", "").strip()
            if src:
                self.script_srcs.append(src)
            else:
                self._in_script = True
        elif tag == "meta":
            if attributes.get("name", "").lower() == "generator":
                self.generator = attributes.get("content", "").strip() or None
        elif tag == "form":
            action = attributes.get("action", "").strip()
            method = attributes.get("method", "get").strip().lower() or "get"
            # Recorded only. netrecon never submits a form.
            self.form_actions.append(f"{method.upper()} {action or '(self)'}")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            text = data.strip()
            if text and not self.title:
                self.title = text[:200]
        elif self._in_script:
            body = data.strip()
            if body:
                self.inline_scripts.append(body)

    def handle_comment(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.comments.append(text[:300])

    def error(self, message: str) -> None:  # pragma: no cover - py3.11 compat
        return


# -- rate-limited GET-only client ---------------------------------------


class RateLimiter:
    """Blocking token-less limiter: spaces requests out across all threads."""

    def __init__(self, rate_per_second: float) -> None:
        self._min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                delay = self._next_allowed - now
            else:
                delay = 0.0
                self._next_allowed = now
            self._next_allowed += self._min_interval
        if delay > 0:
            time.sleep(delay)


@dataclass
class HttpResponse:
    url: str
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    truncated: bool
    elapsed: float

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";")[0].strip().lower()


class GetOnlyClient:
    """An HTTP client that can only issue GET requests.

    Deliberately minimal: no redirect following, no cookie jar, no auth
    handler, no proxy (the target is reached directly, by IP), and a hard byte
    cap so a huge or endless response cannot exhaust memory.
    """

    def __init__(
        self,
        *,
        limiter: RateLimiter,
        timeout: int,
        max_bytes: int,
        user_agent: str,
        verify_tls: bool,
    ) -> None:
        self._limiter = limiter
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._user_agent = user_agent

        context = ssl.create_default_context()
        if not verify_tls:
            # In-scope hosts routinely present self-signed or expired
            # certificates; failing on that would hide the service entirely.
            # Certificate problems are reported rather than fatal.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
            # An empty ProxyHandler disables proxy env vars: scan traffic must
            # go straight to the in-scope address, not through a proxy.
            urllib.request.ProxyHandler({}),
        )

    def get(self, url: str) -> HttpResponse:
        self._limiter.wait()
        headers = {
            "User-Agent": self._user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        request = urllib.request.Request(  # noqa: S310 - scheme checked by caller
            url,
            method="GET",
            headers=headers,
        )
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read(self._max_bytes + 1)
                status = response.status
                reason = response.reason or ""
                headers = {k.lower(): v for k, v in response.headers.items()}
        except urllib.error.HTTPError as exc:
            # A 4xx/5xx is a result, not a failure.
            body = exc.read(self._max_bytes + 1) if exc.fp else b""
            status, reason = exc.code, exc.reason or ""
            headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        except urllib.error.URLError as exc:
            raise WebReconError(
                f"{type(exc.reason).__name__ if exc.reason else 'URLError'}: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError, ValueError) as exc:
            raise WebReconError(f"{type(exc).__name__}: {exc}") from exc

        truncated = len(body) > self._max_bytes
        return HttpResponse(
            url=url,
            status=status,
            reason=reason,
            headers=headers,
            body=body[: self._max_bytes],
            truncated=truncated,
            elapsed=round(time.monotonic() - started, 3),
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turns redirects into plain responses instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


# -- analysis ------------------------------------------------------------


def missing_security_headers(headers: dict[str, str]) -> list[str]:
    return [name for name in SECURITY_HEADERS if name not in headers]


def disclosure_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: headers[name] for name in DISCLOSURE_HEADERS if name in headers}


# -- stage ---------------------------------------------------------------


@dataclass
class Endpoint:
    ip: str
    port: int
    scheme: str
    service: str | None = None

    @property
    def host_part(self) -> str:
        return f"[{self.ip}]" if ":" in self.ip else self.ip

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host_part}:{self.port}"

    @property
    def netloc(self) -> str:
        return f"{self.host_part}:{self.port}"

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port} ({self.scheme})"

    def with_scheme(self, scheme: str) -> Endpoint:
        return Endpoint(self.ip, self.port, scheme, self.service)


@dataclass
class EndpointResult:
    endpoint: Endpoint
    root: dict[str, Any] | None = None
    well_known: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    hidden_paths: list[dict[str, Any]] = field(default_factory=list)
    #: Merged JavaScript analysis across every asset fetched for this endpoint.
    js: dict[str, Any] = field(default_factory=dict)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    cve_matches: list[dict[str, Any]] = field(default_factory=list)
    #: Reconstructed API endpoints for this web endpoint, richest first.
    api_endpoints: list[dict[str, Any]] = field(default_factory=list)
    #: The raw call sites, kept for run-level merging. Not serialised: the
    #: per-endpoint view above is what the report needs.
    raw_call_sites: list[Any] = field(default_factory=list, repr=False)

    @property
    def call_sites(self) -> int:
        return len(self.raw_call_sites)
    error: str | None = None

    def _js_total(self, key: str) -> int:
        return int((self.js.get("totals") or {}).get(key, 0))

    @property
    def endpoint_count(self) -> int:
        return self._js_total("endpoints")

    @property
    def secret_count(self) -> int:
        return self._js_total("secrets")

    @property
    def pii_count(self) -> int:
        return self._js_total("pii")

    @property
    def accessible_paths(self) -> list[dict[str, Any]]:
        return [p for p in self.hidden_paths if p.get("classification") == "accessible"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.endpoint.ip,
            "port": self.endpoint.port,
            "scheme": self.endpoint.scheme,
            "service": self.endpoint.service,
            "base_url": self.endpoint.base_url,
            "error": self.error,
            "root": self.root,
            "well_known": self.well_known,
            "hidden_paths": self.hidden_paths,
            "scripts": self.scripts,
            "javascript": self.js,
            "api_endpoints": self.api_endpoints,
            "technologies": self.technologies,
            "cve_matches": self.cve_matches,
            "totals": {
                "scripts_analysed": len(self.scripts),
                "js_endpoints": self.endpoint_count,
                "secret_candidates": self.secret_count,
                "pii_candidates": self.pii_count,
                "paths_accessible": len(self.accessible_paths),
                "technologies": len(self.technologies),
                "cve_matches": len(self.cve_matches),
                "api_endpoints": len(self.api_endpoints),
                "call_sites": self.call_sites,
            },
        }


def load_endpoints(ctx: RunContext) -> list[Endpoint]:
    """Web endpoints from the services/sweep checkpoints, scope-filtered.

    With ``probe_both_schemes`` the port yields both an http and an https
    endpoint rather than netrecon guessing one from the port number: a service
    on 8080 speaking TLS, or 443 speaking cleartext, is common enough that
    guessing loses real findings. The wrong scheme fails fast on the first
    request and is recorded as unreachable.
    """
    services = read_json(ctx.paths.services, default={}) or {}
    sweep = read_json(ctx.paths.open_ports, default={}) or {}

    candidates: dict[tuple[str, int], Endpoint] = {}

    # Prefer service data: it knows the service name and TLS tunnel.
    for host in services.get("hosts") or []:
        ip = host.get("address")
        if not ip:
            continue
        for port in host.get("ports") or []:
            if port.get("state") != "open" or port.get("protocol", "tcp") != "tcp":
                continue
            number = port.get("port")
            service = port.get("service") or {}
            name = service.get("name")
            tunnel = service.get("tunnel")
            if not isinstance(number, int) or not is_web_service(name, number, tunnel):
                continue
            candidates[(ip, number)] = Endpoint(
                ip=ip,
                port=number,
                scheme="https" if is_tls(name, number, tunnel) else "http",
                service=name,
            )

    # Fall back to the sweep for ports that never got a -sV pass.
    for ip, entries in (sweep.get("hosts") or {}).items():
        for entry in entries or []:
            if not isinstance(entry, dict) or entry.get("protocol", "tcp") != "tcp":
                continue
            number = entry.get("port")
            if not isinstance(number, int) or (ip, number) in candidates:
                continue
            if not is_web_service(None, number, None):
                continue
            candidates[(ip, number)] = Endpoint(
                ip=ip,
                port=number,
                scheme="https" if is_tls(None, number, None) else "http",
                service=None,
            )

    # Final scope gate: drop anything not in the expanded in-scope set.
    allowed = set(ctx.scope.enforce(ip for ip, _ in candidates).allowed_str)
    endpoints: list[Endpoint] = []
    for (ip, _port), endpoint in sorted(candidates.items()):
        if ip not in allowed:
            continue
        endpoints.append(endpoint)
        if ctx.config.webrecon.probe_both_schemes:
            other = "http" if endpoint.scheme == "https" else "https"
            endpoints.append(endpoint.with_scheme(other))
    return endpoints


def run(ctx: RunContext) -> StageResult:
    log = ctx.logger(NAME)
    cfg = ctx.config.webrecon

    if not ctx.web:
        raise StageSkipped("web recon needs --web; skipped")

    endpoints = load_endpoints(ctx)
    if not endpoints:
        raise StageSkipped("no in-scope HTTP(S) endpoints found")

    if len(endpoints) > cfg.max_endpoints:
        log.warning(
            "%d web endpoint(s) found, limiting to webrecon.max_endpoints=%d",
            len(endpoints),
            cfg.max_endpoints,
        )
        endpoints = endpoints[: cfg.max_endpoints]

    log.warning(
        "web recon: GET-only requests to %d endpoint(s) at <=%.1f rps "
        "(max %d script(s) each, %d KiB per response)%s",
        len(endpoints),
        cfg.rate_per_second,
        cfg.max_scripts_per_endpoint,
        cfg.max_response_bytes // 1024,
        f"; probing up to {cfg.max_hidden_paths} well-known path(s) per endpoint"
        if cfg.hidden_paths
        else "",
    )

    if ctx.dry_run:
        log.warning("dry run: skipping web requests")
        return StageResult(
            counts={"endpoints": len(endpoints)}, detail="dry run", backend="webrecon"
        )

    limiter = RateLimiter(cfg.rate_per_second)
    client = GetOnlyClient(
        limiter=limiter,
        timeout=cfg.request_timeout_seconds,
        max_bytes=cfg.max_response_bytes,
        user_agent=cfg.user_agent,
        verify_tls=cfg.verify_tls,
    )
    ctx.paths.webrecon_dir.mkdir(parents=True, exist_ok=True)

    def worker(endpoint: Endpoint) -> EndpointResult:
        return _probe_endpoint(ctx, client, endpoint)

    results = run_parallel(
        endpoints, worker, concurrency=min(cfg.concurrency, ctx.config.limits.concurrency),
        label="web",
    )

    reachable = [r for r in results if r.error is None]
    failures = [f"{r.endpoint.label}: {r.error}" for r in results if r.error]
    total_scripts = sum(len(r.scripts) for r in reachable)
    total_endpoints = sum(r.endpoint_count for r in reachable)
    total_secrets = sum(r.secret_count for r in reachable)
    total_pii = sum(r.pii_count for r in reachable)
    total_paths = sum(len(r.accessible_paths) for r in reachable)
    high_value_paths = [
        f"{r.endpoint.base_url}{p['path']}"
        for r in reachable
        for p in r.accessible_paths
        if p.get("high_value")
    ]
    technologies = sorted(
        {
            f"{tech['name']} {tech['version']}" if tech.get("version") else tech["name"]
            for r in reachable
            for tech in r.technologies
        }
    )
    hosts_referenced = sorted(
        {host for r in reachable for host in (r.js.get("hosts_referenced") or [])}
    )
    cve_matches = [m for r in reachable for m in r.cve_matches]

    # Merge the per-endpoint API reconstruction into one view of the whole run.
    api = _merge_api(reachable)

    # Correlate detected versions against the operator's local CVE feed, if any.
    if cfg.cve_feed:
        cve_matches = _correlate_cves(ctx, reachable)

    write_json(
        ctx.paths.webrecon,
        {
            "generated_at": utc_now(),
            "method": "GET only; no redirects followed; no form submission",
            "limits": {
                "max_endpoints": cfg.max_endpoints,
                "max_scripts_per_endpoint": cfg.max_scripts_per_endpoint,
                "max_response_bytes": cfg.max_response_bytes,
                "rate_per_second": cfg.rate_per_second,
                "request_timeout_seconds": cfg.request_timeout_seconds,
                "verify_tls": cfg.verify_tls,
                "redact_secrets": cfg.redact_secrets,
                "hidden_paths": cfg.hidden_paths,
                "max_hidden_paths": cfg.max_hidden_paths,
                "follow_published_paths": cfg.follow_published_paths,
                "fetch_source_maps": cfg.fetch_source_maps,
                "probe_both_schemes": cfg.probe_both_schemes,
                "detect_pii": cfg.detect_pii,
                "cve_feed": cfg.cve_feed or None,
            },
            "endpoints_probed": len(results),
            "endpoints_reachable": len(reachable),
            "scripts_analysed": total_scripts,
            "js_endpoints_found": total_endpoints,
            "secret_candidates": total_secrets,
            "pii_candidates": total_pii,
            "paths_accessible": total_paths,
            "high_value_paths": high_value_paths,
            "technologies": technologies,
            "hosts_referenced": hosts_referenced,
            "cve_matches": len(cve_matches),
            "api_endpoints": len(api["endpoints"]),
            "api_parameters": len(api["parameters"]),
            "api_structure": api["structure"],
            "parameters": api["parameters"],
            "api_call_sites": api["call_sites"],
            "failures": failures,
            "results": [r.to_dict() for r in results],
        },
    )
    _write_api_artifacts(ctx, api, total_pii, total_secrets, reachable)

    log.info(
        "web recon: %d/%d endpoint(s) reachable, %d asset(s) analysed, "
        "%d API endpoint(s) from %d call site(s), %d parameter(s), %d technolog(ies)",
        len(reachable),
        len(results),
        total_scripts,
        len(api["endpoints"]),
        api["call_sites"],
        len(api["parameters"]),
        len(technologies),
    )
    if total_secrets:
        log.warning(
            "%d string(s) in front-end assets look like embedded credentials - "
            "verify manually in %s before reporting",
            total_secrets,
            ctx.paths.webrecon_dir,
        )
    if total_pii:
        log.warning(
            "%d string(s) look like personal data in front-end assets; values are "
            "masked in the report and the run directory now holds personal data - "
            "handle and dispose of it accordingly",
            total_pii,
        )
    for url in high_value_paths[:10]:
        log.warning("accessible sensitive path: %s", url)
    if hosts_referenced:
        log.info(
            "%d host(s) referenced by front-end code; they are OUT of scope until "
            "added to the scope file and were not contacted",
            len(hosts_referenced),
        )

    return StageResult(
        counts={
            "endpoints_probed": len(results),
            "endpoints_reachable": len(reachable),
            "scripts_analysed": total_scripts,
            "js_endpoints": total_endpoints,
            "secret_candidates": total_secrets,
            "pii_candidates": total_pii,
            "paths_accessible": total_paths,
            "technologies": len(technologies),
            "cve_matches": len(cve_matches),
            "hosts_referenced": len(hosts_referenced),
            "api_endpoints": len(api["endpoints"]),
            "api_parameters": len(api["parameters"]),
            "failures": len(failures),
        },
        outputs={"webrecon": ctx.paths.webrecon},
        backend="webrecon",
        detail=f"{len(failures)} endpoint(s) unreachable" if failures else None,
    )


def _probe_endpoint(
    ctx: RunContext, client: GetOnlyClient, endpoint: Endpoint
) -> EndpointResult:
    log = ctx.logger(NAME)
    cfg = ctx.config.webrecon
    result = EndpointResult(endpoint)

    # Last line of defence: the IP about to be contacted must be in scope.
    try:
        ctx.scope.enforce_strict([endpoint.ip])
    except Exception as exc:  # ScopeViolation
        result.error = f"scope violation: {exc}"
        return result

    out_dir = ctx.paths.webrecon_host_dir(endpoint.ip, endpoint.port) / endpoint.scheme
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        root = client.get(endpoint.base_url + "/")
    except WebReconError as exc:
        result.error = str(exc)
        log.debug("endpoint %s unreachable: %s", endpoint.label, exc)
        return result

    parser = _PageParser()
    body_text = root.text
    try:
        parser.feed(body_text)
        # close() is required: with convert_charrefs=True the parser buffers
        # text and only flushes it here, so without this the title and any
        # trailing inline script are silently lost.
        parser.close()
    except Exception as exc:  # noqa: BLE001 - malformed HTML must not kill the stage
        log.debug("could not parse HTML from %s: %s", endpoint.label, exc)

    (out_dir / "root.body").write_bytes(root.body)
    (out_dir / "root.headers.json").write_text(
        json.dumps({"status": root.status, "headers": root.headers}, indent=2),
        encoding="utf-8",
    )

    technologies = techstack.merge(
        techstack.detect_from_headers(root.headers)
        + techstack.detect_from_html(body_text)
        + techstack.detect_from_scripts(parser.script_srcs)
    )
    result.technologies = [tech.to_dict() for tech in technologies]

    result.root = {
        "url": root.url,
        "status": root.status,
        "reason": root.reason,
        "elapsed_seconds": root.elapsed,
        "content_type": root.content_type,
        "bytes": len(root.body),
        "truncated": root.truncated,
        "title": parser.title,
        "generator": parser.generator,
        "redirect_to": root.headers.get("location"),
        "technologies": [tech.name if not tech.version else f"{tech.name} {tech.version}"
                         for tech in technologies],
        "disclosure_headers": disclosure_headers(root.headers),
        "missing_security_headers": missing_security_headers(root.headers),
        "form_actions": parser.form_actions[:20],
        "html_comments": parser.comments[:20],
        "script_references": parser.script_srcs[:100],
    }

    # Well-known files first: robots.txt and sitemap.xml are published by the
    # site, so reading them is not guessing, and they tell us where to look.
    published: list[PathCandidate] = []
    for path in WELL_KNOWN_PATHS:
        try:
            response = client.get(endpoint.base_url + path)
        except WebReconError as exc:
            result.well_known.append({"path": path, "error": str(exc)})
            continue
        preview = response.text[:2000] if response.status == 200 else None
        result.well_known.append(
            {
                "path": path,
                "status": response.status,
                "bytes": len(response.body),
                "content_type": response.content_type,
                "preview": preview,
            }
        )
        if response.status == 200:
            (out_dir / path.lstrip("/").replace("/", "_")).write_bytes(response.body)
            if cfg.follow_published_paths:
                if path == "/robots.txt":
                    published += paths_from_robots(response.text)
                elif path == "/sitemap.xml":
                    published += paths_from_sitemap(response.text, endpoint.netloc)

    result.hidden_paths = _probe_paths(ctx, client, endpoint, published, out_dir)

    # --- JavaScript and front-end assets -------------------------------
    analyses: list[JsAnalysis] = []
    call_sites: list[apistructure.CallSite] = []

    def record(body: str, source: str, *, truncated: bool = False) -> JsAnalysis:
        """Run both analyses over one body and keep the results together."""
        analysis = jsdata.analyse_javascript(
            body, source=source, redact=cfg.redact_secrets, truncated=truncated
        )
        analyses.append(analysis)
        call_sites.extend(apistructure.analyse_api(body, source=source))
        return analysis

    # The page itself is analysed without any further request: inline scripts,
    # and any sensitive data pasted straight into the markup.
    record(body_text, "(page)")
    for index, inline in enumerate(parser.inline_scripts[: cfg.max_scripts_per_endpoint]):
        record(inline, f"inline#{index + 1}")
        result.scripts.append({"source": f"inline#{index + 1}", "bytes": len(inline)})

    # Crawl: start from the scripts the page linked, then follow further .js
    # references found inside each fetched body. Bounded by the script budget,
    # and restricted to this one in-scope endpoint throughout.
    queue: list[str] = _same_endpoint_scripts(parser.script_srcs, endpoint)
    fetched: set[str] = set()
    source_maps: list[str] = []

    while queue and len(result.scripts) < cfg.max_scripts_per_endpoint:
        src = queue.pop(0)
        if src in fetched:
            continue
        fetched.add(src)
        try:
            response = client.get(src)
        except WebReconError as exc:
            result.scripts.append({"source": src, "error": str(exc)})
            continue
        if response.status != 200 or not response.body:
            result.scripts.append({"source": src, "status": response.status})
            continue

        analysis = record(response.text, src, truncated=response.truncated)
        source_maps += analysis.source_maps
        result.scripts.append(
            {
                "source": src,
                "status": response.status,
                "bytes": len(response.body),
                "truncated": response.truncated,
                "endpoints": [e.value for e in analysis.endpoints],
                "secret_candidates": [s.to_dict() for s in analysis.secrets],
            }
        )
        _save_script(out_dir, src, response.body)

        if cfg.crawl_scripts:
            for found in _same_endpoint_scripts(_js_references(response.text), endpoint):
                if found not in fetched and found not in queue:
                    queue.append(found)

    # Source maps carry the original, unminified sources - usually the richest
    # single artifact a front-end hands out.
    if cfg.fetch_source_maps and source_maps:
        _fetch_source_maps(ctx, client, endpoint, source_maps, out_dir, result, record)

    result.raw_call_sites = call_sites
    result.api_endpoints = [e.to_dict() for e in apistructure.group_endpoints(call_sites)]
    result.js = jsdata.merge_analyses(analyses)
    if not cfg.detect_pii:
        result.js["pii_candidates"] = []
        result.js["pii_summary"] = {}
        result.js["totals"]["pii"] = 0

    return result


def _probe_paths(
    ctx: RunContext,
    client: GetOnlyClient,
    endpoint: Endpoint,
    published: list[PathCandidate],
    out_dir: Path,
) -> list[dict[str, Any]]:
    """Request the published paths, plus the curated list when opted in."""
    cfg = ctx.config.webrecon
    candidates: list[PathCandidate] = list(published)
    if cfg.hidden_paths:
        candidates += curated_paths(cfg.max_hidden_paths)
    if not candidates:
        return []

    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.path in seen:
            continue
        seen.add(candidate.path)
        try:
            response = client.get(endpoint.base_url + candidate.path)
        except WebReconError:
            continue  # an unreachable path is the normal case; not worth a row
        classification = classify_response(
            response.status, len(response.body), response.content_type
        )
        if classification is None:
            continue
        record = {
            "path": candidate.path,
            "origin": candidate.origin,
            "reason": candidate.reason,
            "status": response.status,
            "bytes": len(response.body),
            "content_type": response.content_type,
            "classification": classification,
            "high_value": candidate.high_value,
        }
        if classification == "accessible":
            record["preview"] = response.text[:1000]
            name = re.sub(r"[^A-Za-z0-9._-]", "_", candidate.path.strip("/")) or "root"
            (out_dir / "paths").mkdir(parents=True, exist_ok=True)
            (out_dir / "paths" / name[:120]).write_bytes(response.body)
        elif classification == "redirected":
            record["location"] = response.headers.get("location")
        results.append(record)
    return results


def _fetch_source_maps(
    ctx: RunContext,
    client: GetOnlyClient,
    endpoint: Endpoint,
    source_maps: list[str],
    out_dir: Path,
    result: EndpointResult,
    record: Callable[..., Any],
) -> None:
    """Fetch same-endpoint .map files and analyse their embedded sources.

    A source map carries ``sourcesContent``: the original, unminified files.
    Analysing those beats analysing the bundle, so each embedded source is fed
    through the same ``record`` callback as a real file.
    """
    for url in _same_endpoint_scripts(sorted(set(source_maps)), endpoint)[:5]:
        try:
            response = client.get(url)
        except WebReconError as exc:
            result.scripts.append({"source": url, "error": str(exc)})
            continue
        if response.status != 200 or not response.body:
            continue
        _save_script(out_dir, url, response.body)
        body = response.text
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None

        if isinstance(payload, dict) and isinstance(payload.get("sourcesContent"), list):
            names = payload.get("sources") or []
            for index, content in enumerate(payload["sourcesContent"][:50]):
                if not isinstance(content, str) or not content.strip():
                    continue
                name = names[index] if index < len(names) else f"source#{index}"
                record(content, f"{url} -> {name}")
        else:
            record(body, url)

        result.scripts.append(
            {"source": url, "status": response.status, "bytes": len(response.body)}
        )


#: Further ``.js`` references inside an already-fetched body, for the crawl.
_JS_REFERENCE_RE = re.compile(r"""["'`](/?[A-Za-z0-9_\-./]{1,200}\.js)(?:\?[^"'`]{0,80})?["'`]""")


def _js_references(body: str, limit: int = 60) -> list[str]:
    """Script URLs mentioned inside a body, for one more crawl hop."""
    found: list[str] = []
    for match in _JS_REFERENCE_RE.finditer(body):
        value = match.group(1)
        if value not in found:
            found.append(value)
        if len(found) >= limit:
            break
    return found


def _same_endpoint_scripts(srcs: list[str], endpoint: Endpoint) -> list[str]:
    """Absolute script URLs that stay on this exact in-scope endpoint.

    A script hosted somewhere else (a CDN, another host) is deliberately not
    fetched: that address is not in the engagement's scope.
    """
    base = endpoint.base_url + "/"
    host = f"[{endpoint.ip}]" if ":" in endpoint.ip else endpoint.ip
    expected_netloc = f"{host}:{endpoint.port}".lower()
    kept: list[str] = []
    seen: set[str] = set()

    for src in srcs:
        candidate = src.strip()
        if not candidate or candidate.startswith(("data:", "javascript:", "#")):
            continue
        absolute = urljoin(base, candidate)
        parts = urlsplit(absolute)
        if parts.scheme not in {"http", "https"}:
            continue
        netloc = parts.netloc.lower()
        # Accept the bare host too, for a default-port URL.
        if netloc not in {expected_netloc, host.lower()}:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        kept.append(absolute)
    return kept


def _save_script(out_dir: Path, url: str, body: bytes) -> None:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", urlsplit(url).path.lstrip("/")) or "script.js"
    (out_dir / "js").mkdir(parents=True, exist_ok=True)
    (out_dir / "js" / name[:120]).write_bytes(body)


def _correlate_cves(ctx: RunContext, results: list[EndpointResult]) -> list[dict[str, Any]]:
    """Match detected technology versions against the operator's local CVE feed.

    This is a *correlation*, not a verification: it says "this version appears
    in a feed entry", never "this host is exploitable". netrecon ships no CVE
    data and makes no network request to fetch any - the feed is a file the
    operator downloads and points at.
    """
    log = ctx.logger(NAME)
    feed_path = ctx.config.webrecon.cve_feed
    try:
        from netrecon.analyze import cve as cve_mod
    except ImportError:  # pragma: no cover - module always ships
        return []

    try:
        feed = cve_mod.CveFeed.load(feed_path)
    except Exception as exc:  # noqa: BLE001 - a bad feed must not fail the run
        log.warning("CVE feed %s could not be loaded: %s", feed_path, exc)
        return []

    log.info("correlating detected versions against %d feed entr(ies)", len(feed))
    all_matches: list[dict[str, Any]] = []
    for result in results:
        technologies = [techstack.Technology(**_tech_kwargs(t)) for t in result.technologies]
        matches = cve_mod.correlate(technologies, feed)
        result.cve_matches = [m.to_dict() for m in matches]
        all_matches.extend(result.cve_matches)
    return all_matches


def _tech_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
    """Rebuild Technology kwargs from its dict form, ignoring extra keys."""
    import dataclasses

    fields = {f.name for f in dataclasses.fields(techstack.Technology)}
    kwargs = {k: v for k, v in payload.items() if k in fields}
    for key in ("categories",):
        if key in kwargs and isinstance(kwargs[key], list):
            kwargs[key] = tuple(kwargs[key])
    return kwargs


def _merge_api(results: list[EndpointResult]) -> dict[str, Any]:
    """Fold every endpoint's reconstruction into one API view for the run.

    Regrouping from the raw call sites rather than merging already-grouped
    dicts keeps one code path for the grouping rules, so a parameter seen on
    two different web endpoints is merged exactly as one seen twice on one.
    """
    call_sites = apistructure.merge_call_sites([r.raw_call_sites for r in results])
    endpoints = apistructure.group_endpoints(call_sites)
    parameters = apistructure.build_parameter_index(endpoints)
    return {
        "endpoints": [e.to_dict() for e in endpoints],
        "endpoint_objects": endpoints,
        "parameters": [p.to_dict() for p in parameters],
        "parameter_objects": parameters,
        "structure": apistructure.api_structure(call_sites),
        "call_sites": len(call_sites),
    }


def _write_api_artifacts(
    ctx: RunContext,
    api: dict[str, Any],
    pii_count: int,
    secret_count: int,
    results: list[EndpointResult],
) -> None:
    """Write the standalone API and parameter artifacts.

    ``parameters.txt`` is a plain wordlist on purpose: it is meant to be piped
    straight into a parameter-mining or fuzzing tool during the testing phase
    that follows reconnaissance.
    """
    write_json(ctx.paths.api_structure, api["structure"])
    write_json(ctx.paths.parameters_json, {"parameters": api["parameters"]})

    write_lines(
        ctx.paths.api_endpoints,
        apistructure.endpoint_lines(api["endpoint_objects"]),
    )
    write_lines(
        ctx.paths.js_endpoints,
        sorted(
            {
                str(entry.get("value"))
                for r in results
                for entry in (r.js.get("endpoints") or [])
                if entry.get("value")
            }
        ),
    )
    write_lines(
        ctx.paths.parameters_txt,
        apistructure.parameter_wordlist(api["parameter_objects"]),
    )

    write_json(
        ctx.paths.js_findings,
        {
            "generated_at": utc_now(),
            "endpoints": sorted(
                {
                    str(entry.get("value"))
                    for r in results
                    for entry in (r.js.get("endpoints") or [])
                    if entry.get("value")
                }
            ),
            "api_structure": api["structure"],
            "parameters": api["parameters"],
            "secrets": [
                s for r in results for s in (r.js.get("secret_candidates") or [])
            ],
            "pii": [p for r in results for p in (r.js.get("pii_candidates") or [])],
            "totals": {
                "secrets": secret_count,
                "pii": pii_count,
                "api_endpoints": len(api["endpoints"]),
                "parameters": len(api["parameters"]),
            },
        },
    )
