"""Stage 9: read-only web reconnaissance and JavaScript analysis.

What this stage does, and only this:

* One HTTP **GET** of ``/`` per in-scope web endpoint, plus a GET of
  ``/robots.txt`` and ``/sitemap.xml`` if the root responded.
* Records the status line, response headers, page title, detected technology
  hints, and which common security headers are absent.
* Collects ``<script src=...>`` references that point at the *same* in-scope
  endpoint, fetches each one with a GET, and runs read-only pattern matching
  over the body to surface API paths and strings that look like embedded
  secrets, so a human can triage them.

What this stage never does:

* No request method other than GET. No form submission, no authentication, no
  credential or session handling.
* No parameter fuzzing, no injection payloads, no path brute forcing - the only
  paths requested are ``/``, ``robots.txt``, ``sitemap.xml`` and script URLs the
  page itself linked.
* No redirect following. A ``Location`` header is recorded and left alone, so a
  redirect cannot walk the scan off the authorised endpoint.
* No request to any address outside the expanded in-scope set. Every endpoint is
  re-checked with ``enforce_strict`` immediately before the socket is opened,
  and the URL host is always the in-scope IP literal, never a name.

Everything is capped: endpoints per run, scripts per endpoint, bytes per
response, requests per second, and per-request timeout.
"""

from __future__ import annotations

import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from netrecon.core.jsonio import read_json, write_json
from netrecon.core.runner import RunContext, run_parallel
from netrecon.core.state import utc_now
from netrecon.report.categories import is_tls, is_web_service
from netrecon.stages.base import StageResult, StageSkipped

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

#: API-ish paths referenced from JavaScript. Reported for manual review.
ENDPOINT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""['"`](/(?:api|v\d|rest|graphql|internal|admin|auth|oauth)[^'"`\s]{0,180})['"`]"""),
    re.compile(r"""['"`](/[a-zA-Z0-9_\-./]{2,120}\.(?:json|xml|php|aspx?|jsp|do|action))['"`]"""),
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request)|open)\s*\(\s*['"`]([^'"`\s]{2,200})['"`]"""),
    re.compile(r"""['"`](https?://[^'"`\s]{4,200})['"`]"""),
)

#: Patterns that look like embedded credentials or keys. These are *reported*
#: with the value masked so an operator can go and verify them in the saved
#: file; netrecon never authenticates with anything it finds.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b")),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("slack_token", re.compile(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,70})\b")),
    ("github_token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,100})\b")),
    ("stripe_key", re.compile(r"\b((?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,64})\b")),
    ("private_key_block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b")),
    ("basic_auth_in_url", re.compile(r"(https?://[^/\s:@'\"]{1,64}:[^/\s@'\"]{1,64}@[^\s'\"]{1,120})")),
    (
        "assigned_secret",
        re.compile(
            r"""["']?\b((?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|"""
            r"""auth[_-]?token|private[_-]?key|secret|password|passwd|token|key))"""
            r"""["']?\s*[:=]\s*["']([^"'\s]{8,120})["']""",
            re.IGNORECASE,
        ),
    ),
)

#: Lightweight technology hints from headers and markup. Informational only.
TECH_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("WordPress", re.compile(r"wp-(?:content|includes|json)", re.IGNORECASE)),
    ("Drupal", re.compile(r"Drupal|/sites/default/files", re.IGNORECASE)),
    ("Joomla", re.compile(r"Joomla|/media/jui/", re.IGNORECASE)),
    ("React", re.compile(r"__REACT_DEVTOOLS|data-reactroot|react(?:-dom)?(?:\.min)?\.js", re.IGNORECASE)),
    ("Vue", re.compile(r"__VUE_|vue(?:\.runtime)?(?:\.min)?\.js", re.IGNORECASE)),
    ("Angular", re.compile(r"ng-version|angular(?:\.min)?\.js", re.IGNORECASE)),
    ("Next.js", re.compile(r"__NEXT_DATA__|/_next/static", re.IGNORECASE)),
    ("Nuxt", re.compile(r"__NUXT__|/_nuxt/", re.IGNORECASE)),
    ("jQuery", re.compile(r"jquery[.\-/]", re.IGNORECASE)),
    ("Bootstrap", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.IGNORECASE)),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.IGNORECASE)),
    ("Django", re.compile(r"csrfmiddlewaretoken|__admin_media_prefix__", re.IGNORECASE)),
    ("Rails", re.compile(r"csrf-param|/assets/application-[0-9a-f]{8}", re.IGNORECASE)),
    ("Spring", re.compile(r"JSESSIONID|org\.springframework", re.IGNORECASE)),
    ("Swagger/OpenAPI", re.compile(r"swagger-ui|openapi\.json|/v\d/swagger", re.IGNORECASE)),
    ("GraphQL", re.compile(r"graphql", re.IGNORECASE)),
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
        request = urllib.request.Request(  # noqa: S310 - scheme checked by caller
            url,
            method="GET",
            headers={
                "User-Agent": self._user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
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
            raise WebReconError(f"{type(exc.reason).__name__ if exc.reason else 'URLError'}: {exc.reason}") from exc
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


def mask_secret(value: str) -> str:
    """Mask a candidate secret, keeping enough to locate it in the saved file."""
    if len(value) <= 8:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return f"{value[:4]}{'*' * 8}{value[-2:]} (len {len(value)})"


def analyse_script(
    body: str, *, source: str, redact: bool, max_findings: int = 200
) -> dict[str, Any]:
    """Pattern-match a JavaScript body. Pure function, no I/O."""
    endpoints: set[str] = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(body):
            candidate = match.group(1).strip()
            if 2 <= len(candidate) <= 200:
                endpoints.add(candidate)
            if len(endpoints) >= max_findings:
                break

    secrets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(body):
            groups = match.groups()
            if kind == "assigned_secret" and len(groups) >= 2:
                name, value = groups[0], groups[1]
            else:
                name, value = kind, groups[0]
            if _looks_like_placeholder(value):
                continue
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            line = body.count("\n", 0, match.start()) + 1
            secrets.append(
                {
                    "kind": kind,
                    "name": name,
                    "value": mask_secret(value) if redact else value,
                    "line": str(line),
                    "source": source,
                }
            )
            if len(secrets) >= max_findings:
                break

    sourcemaps = sorted(
        set(re.findall(r"//[#@]\s*sourceMappingURL=([^\s*'\"]{1,200})", body))
    )

    return {
        "source": source,
        "bytes": len(body),
        "endpoints": sorted(endpoints),
        "secret_candidates": secrets,
        "source_maps": sourcemaps,
    }


def _looks_like_placeholder(value: str) -> bool:
    """Filter the obvious non-secrets so the report stays readable."""
    lowered = value.strip().lower()
    if not lowered or len(lowered) < 8:
        return True
    if lowered in {"undefined", "null", "none", "false", "true", "password", "changeme"}:
        return True
    placeholder_markers = (
        "example", "your_", "yourkey", "placeholder", "xxxx", "<", "{{", "${",
        "test_key", "dummy", "redacted", "insert", "todo", "abc123", "123456",
    )
    if any(marker in lowered for marker in placeholder_markers):
        return True
    # A value with no variety is almost certainly a template, not a key.
    return len(set(lowered)) <= 3


def detect_technologies(headers: dict[str, str], body: str) -> list[str]:
    haystack = " ".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body[:200_000]
    found = [name for name, pattern in TECH_HINTS if pattern.search(haystack)]
    server = headers.get("server")
    if server:
        found.append(f"Server: {server}")
    powered = headers.get("x-powered-by")
    if powered:
        found.append(f"X-Powered-By: {powered}")
    return sorted(set(found))


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
    def base_url(self) -> str:
        host = f"[{self.ip}]" if ":" in self.ip else self.ip
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def label(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass
class EndpointResult:
    endpoint: Endpoint
    root: dict[str, Any] | None = None
    well_known: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def endpoint_count(self) -> int:
        return sum(len(s.get("endpoints") or []) for s in self.scripts)

    @property
    def secret_count(self) -> int:
        return sum(len(s.get("secret_candidates") or []) for s in self.scripts)

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
            "scripts": self.scripts,
            "totals": {
                "scripts_analysed": len(self.scripts),
                "js_endpoints": self.endpoint_count,
                "secret_candidates": self.secret_count,
            },
        }


def load_endpoints(ctx: RunContext) -> list[Endpoint]:
    """Web endpoints from the services/sweep checkpoints, scope-filtered."""
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
            service = (port.get("service") or {})
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
    endpoints = [ep for (ip, _port), ep in sorted(candidates.items()) if ip in allowed]
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
        "(max %d script(s) each, %d KiB per response)",
        len(endpoints),
        cfg.rate_per_second,
        cfg.max_scripts_per_endpoint,
        cfg.max_response_bytes // 1024,
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
            },
            "endpoints_probed": len(results),
            "endpoints_reachable": len(reachable),
            "scripts_analysed": total_scripts,
            "js_endpoints_found": total_endpoints,
            "secret_candidates": total_secrets,
            "failures": failures,
            "results": [r.to_dict() for r in results],
        },
    )

    log.info(
        "web recon: %d/%d endpoint(s) reachable, %d script(s) analysed, "
        "%d JS path(s), %d secret candidate(s)",
        len(reachable),
        len(results),
        total_scripts,
        total_endpoints,
        total_secrets,
    )
    if total_secrets:
        log.warning(
            "%d string(s) in JavaScript look like embedded credentials - verify "
            "manually in %s before reporting",
            total_secrets,
            ctx.paths.webrecon_dir,
        )

    return StageResult(
        counts={
            "endpoints_probed": len(results),
            "endpoints_reachable": len(reachable),
            "scripts_analysed": total_scripts,
            "js_endpoints": total_endpoints,
            "secret_candidates": total_secrets,
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

    out_dir = ctx.paths.webrecon_host_dir(endpoint.ip, endpoint.port)
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
        "technologies": detect_technologies(root.headers, body_text),
        "disclosure_headers": disclosure_headers(root.headers),
        "missing_security_headers": missing_security_headers(root.headers),
        "form_actions": parser.form_actions[:20],
        "html_comments": parser.comments[:20],
        "script_references": parser.script_srcs[:100],
    }

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

    # Inline scripts are analysed without any further request.
    for index, inline in enumerate(parser.inline_scripts[: cfg.max_scripts_per_endpoint]):
        result.scripts.append(
            analyse_script(
                inline,
                source=f"inline#{index + 1}",
                redact=cfg.redact_secrets,
            )
        )

    remaining = cfg.max_scripts_per_endpoint - len(result.scripts)
    if remaining > 0:
        for src in _same_endpoint_scripts(parser.script_srcs, endpoint)[:remaining]:
            try:
                response = client.get(src)
            except WebReconError as exc:
                result.scripts.append({"source": src, "error": str(exc)})
                continue
            if response.status != 200 or not response.body:
                result.scripts.append(
                    {"source": src, "status": response.status, "endpoints": [], "secret_candidates": []}
                )
                continue
            analysis = analyse_script(
                response.text, source=src, redact=cfg.redact_secrets
            )
            analysis["status"] = response.status
            analysis["truncated"] = response.truncated
            result.scripts.append(analysis)
            _save_script(out_dir, src, response.body)

    return result


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
