"""Reconstruct an application's API surface from its JavaScript.

:mod:`netrecon.analyze.jsdata` answers "what paths does this bundle mention?".
That is a starting point, not attack surface. A path on its own cannot be
tested: an assessor still has to guess the verb, invent parameter names and
discover which of them the server actually reads. This module answers the next
question - **what does a call to that endpoint look like?** - by recovering a
call *signature* per endpoint:

    POST /api/v2/orders?include={include}   body: id, qty, coupon   [app.js +1]

That is testable. Each parameter name came out of the application's own code, so
it is a name the server almost certainly binds; each endpoint carries the file
and line it was reconstructed from, so an operator can read the original call
before sending anything. The merged parameter index doubles as a target-specific
fuzzing wordlist, which is worth far more than a generic one.

Everything here is a **pure function over a string**. No requests, no file I/O,
no subprocesses: the web stage fetches the bodies and calls in, and these
functions can be re-run offline against a saved run directory.

Two things make this harder than a regex sweep, and both are deliberate here:

* **Option objects must not leak.** ``headers: {Authorization: "Bearer x"}`` is
  transport configuration, not a parameter. A naive key regex reports
  ``Authorization`` as an API parameter, and a report full of those is worse
  than no report. Keys are therefore read by a brace-aware scanner that knows
  about nested objects, arrays, strings and template literals, and the
  transport-key filter applies **only** at the top level of an options object -
  a GraphQL body legitimately contains ``query`` and ``variables``.
* **Only literal URLs are recovered.** A URL assembled entirely from variables
  is not recoverable from source, so the call site is skipped rather than
  guessed at. Everything reported is quoted from the file.

The results are still heuristics: a lead to verify, not a finding to assert.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# -- limits --------------------------------------------------------------

#: Caps per analysis, so one minified megabyte cannot swamp a report.
MAX_CALL_SITES = 2000
MAX_ENDPOINTS = 500
#: How far the brace-aware scanner will walk from a single opening bracket.
MAX_SCAN_CHARS = 20000
#: Keys read from one object literal, and characters of URL kept.
MAX_OBJECT_KEYS = 200
MAX_URL_CHARS = 400

# -- vocabulary ----------------------------------------------------------

#: HTTP verbs that appear as method names on a client object.
VERBS: tuple[str, ...] = ("get", "post", "put", "patch", "delete", "head", "options")

#: Transport configuration, filtered out at the TOP level of an options object
#: only. The same words are legitimate parameter names inside a body, so this
#: set is never applied while reading a body/data/json/variables object.
TRANSPORT_KEYS: frozenset[str] = frozenset(
    {
        "method", "type", "headers", "credentials", "mode", "cache", "redirect",
        "referrer", "referrerPolicy", "integrity", "keepalive", "signal", "agent",
        "timeout", "responseType", "withCredentials", "baseURL", "url", "body",
        "data", "params", "json", "variables", "success", "error", "complete",
        "dataType", "contentType", "async", "xhrFields", "beforeSend",
    }
)

#: Keys whose values are the request body.
BODY_KEYS: tuple[str, ...] = ("body", "data", "json", "variables")

#: Keys that mark a second argument as a client *config* object rather than a
#: body. ``axios.get(url, {params: {...}})`` is config; ``axios.post(url,
#: {query, variables})`` is a body, so the body-ish keys are deliberately not
#: listed here.
CONFIG_MARKERS: frozenset[str] = frozenset(
    {
        "params", "headers", "method", "type", "withCredentials", "responseType",
        "baseURL", "timeout", "signal", "credentials", "mode", "dataType",
        "contentType", "success", "error", "complete", "beforeSend", "xhrFields",
    }
)

#: Kinds of call site, used for grouping and for the report.
KINDS: tuple[str, ...] = ("fetch", "axios", "jquery", "generic", "xhr")


# -- data types ----------------------------------------------------------


def short_source(source: str) -> str:
    """A readable label for a source: the file name, not the whole URL.

    ``http://10.0.0.1:8080/static/js/app.min.js`` renders as ``app.min.js``;
    a source-map entry ``<url> -> src/config.js`` renders as ``config.js``.
    """
    text = str(source or "")
    if " -> " in text:
        text = text.split(" -> ")[-1]
    if "://" in text or text.startswith("/"):
        from urllib.parse import urlsplit

        path = urlsplit(text).path if "://" in text else text
        tail = path.rstrip("/").rsplit("/", 1)[-1]
        if tail:
            return tail
    return text


@dataclass(frozen=True)
class CallSite:
    """One reconstructed request, as the source wrote it."""

    url: str
    method: str
    path: str  # url with the query string and fragment removed
    query_params: tuple[str, ...] = ()
    path_params: tuple[str, ...] = ()
    body_params: tuple[str, ...] = ()
    source: str = ""
    line: int = 0
    kind: str = "generic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "path": self.path,
            "query_params": list(self.query_params),
            "path_params": list(self.path_params),
            "body_params": list(self.body_params),
            "source": self.source,
            "line": self.line,
            "kind": self.kind,
        }


@dataclass
class Endpoint:
    """One path, merged across every call site that targets it."""

    path: str
    methods: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()
    path_params: tuple[str, ...] = ()
    body_params: tuple[str, ...] = ()
    call_sites: int = 0
    sources: tuple[str, ...] = ()
    #: One ``{"source", "line", "method"}`` per call site, so every claim in
    #: the report can be read back in the original file.
    refs: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def param_count(self) -> int:
        """Distinct parameter names, however they are passed."""
        return len(set(self.query_params) | set(self.path_params) | set(self.body_params))

    @property
    def source_label(self) -> str:
        """``"app.js"``, or ``"app.js +2"`` when three files call this path.

        Shortened for display only. The full source stays in ``sources`` and in
        every entry of ``refs``, which is what traceability needs.
        """
        if not self.sources:
            return ""
        first = short_source(self.sources[0])
        if len(self.sources) == 1:
            return first
        return f"{first} +{len(self.sources) - 1}"

    @property
    def signature(self) -> str:
        """``GET/POST /api/v2/orders?id={id}&status={status}``."""
        methods = "/".join(self.methods) if self.methods else "GET"
        query = "&".join(f"{name}={{{name}}}" for name in self.query_params)
        return f"{methods} {self.path}?{query}" if query else f"{methods} {self.path}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "methods": list(self.methods),
            "signature": self.signature,
            "query_params": list(self.query_params),
            "path_params": list(self.path_params),
            "body_params": list(self.body_params),
            "param_count": self.param_count,
            "call_sites": self.call_sites,
            "sources": list(self.sources),
            "source_label": self.source_label,
            "refs": [dict(ref) for ref in self.refs],
        }


@dataclass(frozen=True)
class Parameter:
    """One parameter name, and everywhere the application passes it."""

    name: str
    kinds: tuple[str, ...] = ()  # subset of ("body", "query", "path"), sorted
    endpoints: tuple[str, ...] = ()
    occurrences: int = 0

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kinds": list(self.kinds),
            "endpoints": list(self.endpoints),
            "endpoint_count": self.endpoint_count,
            "occurrences": self.occurrences,
        }


# -- the brace-aware scanner --------------------------------------------
#
# Minified bundles contain nested objects, arrays, strings holding braces,
# template literals with `${}` expressions inside them, and regex-looking
# slashes. A regex cannot tell the top level of an object from its third level,
# so both primitives below walk the text with an explicit context stack:
#
#   "br"   an open { [ (
#   "sub"  a ${ ... } expression inside a template literal
#   "sq"   a '...' string        "dq"  a "..." string       "tmpl"  a `...`
#
# Inside "sq"/"dq"/"tmpl" nothing is structural, so braces in strings cannot
# move the depth. Line and block comments are skipped in code context.

_OPENERS: dict[str, str] = {"{": "}", "[": "]", "(": ")"}
_CLOSERS = frozenset(")]}")


def _match_bracket(text: str, index: int, limit: int = MAX_SCAN_CHARS) -> int:
    """Index of the bracket closing the one at *index*, or ``-1``.

    ``-1`` is also returned for truncated input, which callers treat as "take
    what is left" rather than as an error.
    """
    if index < 0 or index >= len(text) or text[index] not in _OPENERS:
        return -1
    ctx: list[str] = []
    i = index
    end = min(len(text), index + limit)
    while i < end:
        char = text[i]
        top = ctx[-1] if ctx else None
        if top in ("sq", "dq"):
            if char == "\\":
                i += 2
                continue
            if (top == "sq" and char == "'") or (top == "dq" and char == '"'):
                ctx.pop()
        elif top == "tmpl":
            if char == "\\":
                i += 2
                continue
            if char == "`":
                ctx.pop()
            elif char == "$" and text[i + 1 : i + 2] == "{":
                ctx.append("sub")
                i += 2
                continue
        else:
            if char == "/" and text[i + 1 : i + 2] == "/":
                newline = text.find("\n", i)
                i = end if newline == -1 else newline
                continue
            if char == "/" and text[i + 1 : i + 2] == "*":
                closed = text.find("*/", i + 2)
                i = end if closed == -1 else closed + 2
                continue
            if char == "'":
                ctx.append("sq")
            elif char == '"':
                ctx.append("dq")
            elif char == "`":
                ctx.append("tmpl")
            elif char in _OPENERS:
                ctx.append("br")
            elif char in _CLOSERS:
                if ctx and ctx[-1] in ("br", "sub"):
                    ctx.pop()
                    if not ctx:
                        return i
                else:
                    return -1
        i += 1
    return -1


def _split_top_level(inner: str) -> list[str]:
    """Split on commas that sit at the top level of *inner*.

    Used for both argument lists and object literals. Commas inside nested
    brackets, strings or template expressions do not split.
    """
    parts: list[str] = []
    buf: list[str] = []
    ctx: list[str] = []
    i = 0
    end = min(len(inner), MAX_SCAN_CHARS)
    while i < end:
        char = inner[i]
        top = ctx[-1] if ctx else None
        if top in ("sq", "dq"):
            if char == "\\":
                buf.append(inner[i : i + 2])
                i += 2
                continue
            if (top == "sq" and char == "'") or (top == "dq" and char == '"'):
                ctx.pop()
        elif top == "tmpl":
            if char == "\\":
                buf.append(inner[i : i + 2])
                i += 2
                continue
            if char == "`":
                ctx.pop()
            elif char == "$" and inner[i + 1 : i + 2] == "{":
                ctx.append("sub")
                buf.append("${")
                i += 2
                continue
        else:
            if char == "/" and inner[i + 1 : i + 2] == "/":
                newline = inner.find("\n", i)
                i = end if newline == -1 else newline
                continue
            if char == "/" and inner[i + 1 : i + 2] == "*":
                closed = inner.find("*/", i + 2)
                i = end if closed == -1 else closed + 2
                continue
            if char == "'":
                ctx.append("sq")
            elif char == '"':
                ctx.append("dq")
            elif char == "`":
                ctx.append("tmpl")
            elif char in _OPENERS:
                ctx.append("br")
            elif char in _CLOSERS:
                if ctx and ctx[-1] in ("br", "sub"):
                    ctx.pop()
            elif char == "," and not ctx:
                parts.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(char)
        i += 1
    parts.append("".join(buf))
    return [part for part in parts if part.strip()]


# -- object literals ----------------------------------------------------

_KEY_RE = re.compile(r"""^\s*(?:"([^"]*)"|'([^']*)'|([A-Za-z_$][\w$]*))\s*:""")
_SHORTHAND_RE = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*$")
_JSON_STRINGIFY_RE = re.compile(r"^\s*(?:JSON\.stringify|qs\.stringify|stringify)\s*\(")


def _object_inner(text: str) -> str | None:
    """Body of the object literal *text* starts with, or ``None``."""
    stripped = text.lstrip()
    offset = len(text) - len(stripped)
    if not stripped.startswith("{"):
        return None
    close = _match_bracket(text, offset)
    if close == -1:
        # Truncated file: read what is there rather than raising.
        return text[offset + 1 :]
    return text[offset + 1 : close]


def _object_entries(inner: str) -> list[tuple[str, str]]:
    """``(key, raw value text)`` for the top level of an object body.

    Source order is preserved, shorthand ``{a, b}`` is read (its value text is
    the name itself), and spreads and computed keys are skipped.
    """
    entries: list[tuple[str, str]] = []
    for part in _split_top_level(inner):
        if len(entries) >= MAX_OBJECT_KEYS:
            break
        match = _KEY_RE.match(part)
        if match:
            key = next(group for group in match.groups() if group is not None)
            if key:
                entries.append((key, part[match.end() :]))
            continue
        shorthand = _SHORTHAND_RE.match(part)
        if shorthand:
            entries.append((shorthand.group(1), shorthand.group(1)))
    return entries


def _object_keys(text: str) -> list[str]:
    """Top-level keys of the object literal *text* starts with, unfiltered."""
    inner = _object_inner(text)
    if inner is None:
        return []
    return _unique([key for key, _ in _object_entries(inner)])


def _body_keys(value: str) -> list[str]:
    """Keys of a body value: an object literal, or ``JSON.stringify({...})``."""
    stripped = value.strip()
    if stripped.startswith("{"):
        return _object_keys(stripped)
    wrapper = _JSON_STRINGIFY_RE.match(stripped)
    if wrapper:
        paren = wrapper.end() - 1
        close = _match_bracket(stripped, paren)
        argument = stripped[paren + 1 : close if close != -1 else len(stripped)]
        return _body_keys(argument)
    return []  # a variable, FormData, a function call: nothing recoverable


# -- URLs ---------------------------------------------------------------

_TEMPLATE_EXPR = re.compile(r"\$\{([^}]{0,200})\}")
_SIMPLE_NAME = re.compile(r"^[A-Za-z_$][\w$]*$")
_DOTTED_NAME = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")
_WRAPPED_NAME = re.compile(r"^[\w$.]+\(\s*([A-Za-z_$][\w$.]*)\s*\)$")
#: Express/Angular style ``/users/:id`` segments, and ``{id}`` placeholders.
_PLACEHOLDER_RE = re.compile(r"\{([^{}]{1,80})\}|/:([A-Za-z_$][\w$]*)")


def _expression_name(expression: str) -> str:
    """A readable parameter name for a ``${...}`` expression."""
    text = expression.strip()
    if _SIMPLE_NAME.match(text) or _DOTTED_NAME.match(text):
        return text
    wrapped = _WRAPPED_NAME.match(text)  # encodeURIComponent(id) -> id
    if wrapped:
        return wrapped.group(1)
    return "param"


def _normalise_url(raw: str) -> str:
    """Rewrite ``${expr}`` as ``{name}`` so one path groups across call sites."""
    return _TEMPLATE_EXPR.sub(lambda m: "{" + _expression_name(m.group(1)) + "}", raw)


def _split_url(url: str) -> tuple[str, str]:
    """``(path, query string)``, with any fragment dropped."""
    without_fragment = url.split("#", 1)[0]
    path, _, query = without_fragment.partition("?")
    return path, query


def _path_placeholders(path: str) -> list[str]:
    """Path parameter names, in the order they appear in the path."""
    names: list[str] = []
    for match in _PLACEHOLDER_RE.finditer(path):
        name = match.group(1) or match.group(2) or ""
        if name:
            names.append(name.strip())
    return _unique(names)


def _query_keys(query: str) -> list[str]:
    keys: list[str] = []
    for pair in query.split("&"):
        key = pair.split("=", 1)[0].strip()
        # A whole query string interpolated from a variable has no known keys.
        if key and "{" not in key and "}" not in key:
            keys.append(key)
    return _unique(keys)


def _literal_prefix(argument: str) -> str | None:
    """The literal string an argument starts with, or ``None``.

    Template literals keep their ``${...}`` expressions. A truncated literal
    yields what was readable; a non-literal argument (a bare variable) yields
    ``None``, which is how unrecoverable URLs get skipped.
    """
    text = argument.lstrip()
    if not text or text[0] not in "\"'`":
        return None
    quote = text[0]
    out: list[str] = []
    i = 1
    while i < len(text) and len(out) < MAX_URL_CHARS:
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(nxt if nxt in "\"'`/\\" else text[i : i + 2])
            i += 2
            continue
        if char == quote:
            return "".join(out)
        if quote == "`" and char == "$" and text[i + 1 : i + 2] == "{":
            close = _match_bracket(text, i + 1)
            if close == -1:
                break
            out.append(text[i : close + 1])
            i = close + 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _is_url_like(value: str) -> bool:
    """Reject literals that are plainly not request targets.

    ``map.get("userName")`` matches the generic client-call shape, so a value
    that looks nothing like a path or URL is dropped rather than reported.
    """
    if not value or len(value) > MAX_URL_CHARS:
        return False
    if any(char.isspace() for char in value):
        return False
    lowered = value.lower()
    if lowered.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return False
    return "/" in value or "?" in value


# -- call-site extraction ------------------------------------------------

#: Ordered most specific first; the first pattern to claim a call wins, so
#: ``axios.get(...)`` is an axios call rather than a generic client call.
_VERB_GROUP = "|".join(VERBS)
_CALL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fetch", re.compile(r"(?<![\w$.])fetch\s*\(")),
    ("axios", re.compile(rf"(?<![\w$.])axios\.(?P<verb>{_VERB_GROUP})\s*\(")),
    ("axios", re.compile(r"(?<![\w$.])axios\s*\(")),
    (
        "jquery",
        re.compile(r"(?<![\w$.])(?:\$|jQuery)\.(?P<verb>get|post|getJSON|ajax)\s*\("),
    ),
    ("xhr", re.compile(r"\.open\s*\(")),
    (
        "generic",
        re.compile(
            r"(?<![\w$])[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
            rf"\.(?P<verb>{_VERB_GROUP})\s*\("
        ),
    ),
)

#: jQuery helper -> the method it sends.
_JQUERY_METHODS: dict[str, str] = {"get": "GET", "getJSON": "GET", "post": "POST"}


def extract_call_sites(body: str, source: str = "") -> list[CallSite]:
    """Every recoverable HTTP call in one JavaScript or HTML body."""
    if not body:
        return []

    claimed: dict[int, CallSite] = {}
    for kind, pattern in _CALL_PATTERNS:
        for match in pattern.finditer(body):
            paren = match.end() - 1
            if paren in claimed:
                continue  # a more specific pattern already read this call
            verb = match.groupdict().get("verb") if pattern.groupindex else None
            site = _read_call(body, paren, kind, verb, source, match.start())
            if site is not None:
                claimed[paren] = site
            if len(claimed) >= MAX_CALL_SITES:
                break
        if len(claimed) >= MAX_CALL_SITES:
            break

    return [claimed[position] for position in sorted(claimed)]


def _read_call(
    body: str, paren: int, kind: str, verb: str | None, source: str, start: int
) -> CallSite | None:
    """Reconstruct one call site, or ``None`` when the URL is not literal."""
    close = _match_bracket(body, paren)
    if close == -1:
        # Truncated or unbalanced source: read a bounded window and try anyway.
        close = min(len(body), paren + MAX_SCAN_CHARS)
    arguments = _split_top_level(body[paren + 1 : close])

    first = arguments[0] if arguments else ""
    second = arguments[1] if len(arguments) > 1 else ""

    method: str | None = None
    options: str | None = None  # a client options object
    data: str | None = None  # a second argument that is a body or a config

    if kind == "xhr":
        # XMLHttpRequest: .open("POST", url)
        verb_literal = _literal_prefix(first)
        if verb_literal is None:
            return None
        method = verb_literal.strip().upper() or None
        raw_url = _literal_prefix(second)
    elif verb:
        # `$.ajax` names no verb of its own; every other helper does.
        method = _JQUERY_METHODS.get(verb) if kind == "jquery" else verb.upper()
        raw_url = _literal_prefix(first)
        if raw_url is None:
            inner = _object_inner(first)
            if inner is None:
                return None
            options = inner
            raw_url = _url_from_options(inner)
        else:
            data = second
    else:
        # fetch(url, opts), axios(url, opts), axios({url, ...}), $.ajax({...})
        raw_url = _literal_prefix(first)
        if raw_url is None:
            inner = _object_inner(first)
            if inner is None:
                return None
            options = inner
            raw_url = _url_from_options(inner)
        else:
            options = _object_inner(second)

    if raw_url is None:
        return None
    # Normalise before the shape test: `${i + 1}` contains a space, and only
    # after it becomes `{param}` does the URL look like the path it is.
    url = _normalise_url(raw_url)
    if not _is_url_like(url):
        return None

    query_params: list[str] = []
    body_params: list[str] = []

    if options is None and data is not None:
        inner = _object_inner(data)
        if inner is not None:
            keys = {key for key, _ in _object_entries(inner)}
            if keys & CONFIG_MARKERS:
                # A client config object, not a body: read it as options.
                options = inner
            else:
                body_params = _unique([key for key, _ in _object_entries(inner)])

    if options is not None:
        option_method, query_params, extra_body = _read_options(options)
        # Verb precedence: an explicit verb in the call beats `method:`/`type:`.
        method = method or option_method
        body_params = _unique(body_params + extra_body)

    path, query = _split_url(url)
    return CallSite(
        url=url,
        method=(method or "GET").upper(),
        path=path,
        query_params=tuple(_unique(_query_keys(query) + query_params)),
        path_params=tuple(_path_placeholders(path)),
        body_params=tuple(body_params),
        source=source,
        line=body.count("\n", 0, start) + 1,
        kind=kind,
    )


def _url_from_options(inner: str) -> str | None:
    for key, value in _object_entries(inner):
        if key == "url":
            return _literal_prefix(value)
    return None


def _read_options(inner: str) -> tuple[str | None, list[str], list[str]]:
    """``(method, query params, body params)`` from an options object.

    The transport filter applies here and nowhere else: keys of a body are read
    with no filtering at all, which is what keeps a GraphQL ``{query,
    variables}`` body intact.
    """
    method: str | None = None
    query: list[str] = []
    body: list[str] = []
    for key, value in _object_entries(inner):
        if key in ("method", "type"):
            literal = _literal_prefix(value)
            if literal and literal.strip():
                method = literal.strip().upper()
        elif key == "params":
            query.extend(_object_keys(value))
        elif key in BODY_KEYS:
            body.extend(_body_keys(value))
        elif key not in TRANSPORT_KEYS:
            # Not transport, so it is a parameter this client passes.
            body.append(key)
    return method, _unique(query), _unique(body)


# -- grouping ------------------------------------------------------------


def group_endpoints(call_sites: list[CallSite]) -> list[Endpoint]:
    """One :class:`Endpoint` per path, richest first."""
    methods: dict[str, list[str]] = {}
    query: dict[str, list[str]] = {}
    paths: dict[str, list[str]] = {}
    bodies: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    sources: dict[str, list[str]] = {}
    refs: dict[str, list[dict[str, Any]]] = {}

    for site in call_sites:
        path = site.path
        if path not in counts and len(counts) >= MAX_ENDPOINTS:
            continue
        methods.setdefault(path, []).append(site.method)
        query.setdefault(path, []).extend(site.query_params)
        paths.setdefault(path, []).extend(site.path_params)
        bodies.setdefault(path, []).extend(site.body_params)
        counts[path] = counts.get(path, 0) + 1
        if site.source:
            sources.setdefault(path, [])
            if site.source not in sources[path]:
                sources[path].append(site.source)
        refs.setdefault(path, []).append(
            {"source": site.source, "line": site.line, "method": site.method}
        )

    endpoints = [
        Endpoint(
            path=path,
            methods=tuple(sorted(set(methods[path]))),
            query_params=tuple(sorted(set(query[path]))),
            path_params=tuple(sorted(set(paths[path]))),
            body_params=tuple(sorted(set(bodies[path]))),
            call_sites=counts[path],
            sources=tuple(sources.get(path, [])),
            refs=tuple(refs[path]),
        )
        for path in counts
    ]
    return sort_endpoints(endpoints)


def sort_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Richest first: the endpoint with most parameters is the one to read."""
    return sorted(endpoints, key=lambda e: (-e.param_count, -e.call_sites, e.path))


def build_parameter_index(endpoints: list[Endpoint]) -> list[Parameter]:
    """Every parameter name, most widely accepted first.

    The result is a target-specific wordlist: a name this application sends to
    four endpoints is worth trying against the fifth.
    """
    kinds: dict[str, set[str]] = {}
    where: dict[str, list[str]] = {}
    counts: dict[str, int] = {}

    for endpoint in endpoints:
        for kind, names in (
            ("body", endpoint.body_params),
            ("query", endpoint.query_params),
            ("path", endpoint.path_params),
        ):
            for name in set(names):
                kinds.setdefault(name, set()).add(kind)
                counts[name] = counts.get(name, 0) + 1
                seen = where.setdefault(name, [])
                if endpoint.path not in seen:
                    seen.append(endpoint.path)

    parameters = [
        Parameter(
            name=name,
            kinds=tuple(sorted(kinds[name])),
            endpoints=tuple(sorted(where[name])),
            occurrences=counts[name],
        )
        for name in counts
    ]
    return sorted(parameters, key=lambda p: (-p.endpoint_count, -p.occurrences, p.name))


# -- entry points --------------------------------------------------------


def analyse_api(body: str, source: str = "") -> list[CallSite]:
    """Analyse one body. Alias of :func:`extract_call_sites`, for symmetry."""
    return extract_call_sites(body, source)


def merge_call_sites(batches: list[list[CallSite]]) -> list[CallSite]:
    """Flatten per-file results into one list, dropping exact repeats."""
    merged: list[CallSite] = []
    seen: set[tuple[str, str, str, int]] = set()
    for batch in batches or []:
        for site in batch or []:
            identity = (site.source, site.url, site.method, site.line)
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(site)
            if len(merged) >= MAX_CALL_SITES:
                return merged
    return merged


def api_structure(call_sites: list[CallSite]) -> dict[str, Any]:
    """The reconstructed API surface, ready for ``summary.json``."""
    endpoints = group_endpoints(call_sites)
    parameters = build_parameter_index(endpoints)
    return {
        "endpoints": [endpoint.to_dict() for endpoint in endpoints],
        "parameters": [parameter.to_dict() for parameter in parameters],
        "totals": {
            "call_sites": len(call_sites),
            "endpoints": len(endpoints),
            "parameters": len(parameters),
            "methods": sorted({site.method for site in call_sites}),
            "sources": sorted({site.source for site in call_sites if site.source}),
        },
    }


def endpoint_lines(endpoints: list[Endpoint]) -> list[str]:
    """Lines for ``api_endpoints.txt``: one signature per endpoint."""
    lines: list[str] = []
    for endpoint in endpoints:
        methods = "/".join(endpoint.methods) if endpoint.methods else "GET"
        line = f"{methods} {endpoint.path}"
        if endpoint.source_label:
            line = f"{line}  [{endpoint.source_label}]"
        lines.append(line)
    return lines


def parameter_wordlist(parameters: list[Parameter]) -> list[str]:
    """Plain parameter names, one per line, for a fuzzing wordlist."""
    return _unique([parameter.name for parameter in parameters])


def _unique(values: list[str]) -> list[str]:
    """Deduplicate, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
