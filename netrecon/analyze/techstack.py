"""Structured technology fingerprinting from evidence netrecon already holds.

Two callers need the same answer in the same shape. The web stage has response
headers, HTML and ``<script src>`` references from its single GET per endpoint;
the HTTP service analyzer has only ``nmap -sV`` fields and NSE text. Both route
through here so the report never says "jQuery" in one place and "jquery 3.6.0"
in another, and so the CVE correlator has one structured record - name, version,
CPE - to work from instead of a list of free-text hints.

Everything here is a pure function over strings: no sockets, no subprocesses, no
file reads. A fingerprint is a claim about a *banner*, never a claim about what
is actually installed, so every :class:`Technology` carries the literal string it
came from and a confidence that says how far the evidence goes:

* ``certain``  - the target named the product *and* a version itself
  (``Server:``, ``X-Powered-By:``, ``<meta name=generator>``, ``nmap -sV``).
* ``likely``   - a self-identifying source with no version, a framework cookie,
  or an unambiguous markup/path marker such as ``__NEXT_DATA__``.
* ``possible`` - an indirect marker (a generic bundle filename, a ``Via`` proxy
  token, markup that several versions of a library all emit).

Versions parsed out of a filename are never better than ``likely``: a bundle
called ``jquery-3.6.0.min.js`` is routinely a different build with the old name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from netrecon.analyze.base import ServiceEvidence

#: Most reliable first; used for sorting and for picking a winner in :func:`merge`.
CONFIDENCE_ORDER: dict[str, int] = {"certain": 0, "likely": 1, "possible": 2}


@dataclass(frozen=True)
class Technology:
    """One piece of software netrecon believes is in play on one target."""

    #: Display name, canonicalised: "nginx", "WordPress", "jQuery".
    name: str
    version: str | None
    #: "web-server", "cms", "js-library", "framework", "language", ...
    categories: tuple[str, ...]
    #: "certain" | "likely" | "possible" - see the module docstring.
    confidence: str
    #: "header:server" | "meta:generator" | "script-url" | "nmap-sV" | "cookie" | ...
    source: str
    #: The literal string the claim was derived from.
    evidence: str
    #: Best-effort CPE 2.3, or None when netrecon cannot name a vendor.
    cpe: str | None = None

    @property
    def key(self) -> str:
        """Identity for deduplication: the lowercased name."""
        return self.name.strip().lower()

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name

    @property
    def rank(self) -> int:
        return CONFIDENCE_ORDER.get(self.confidence, len(CONFIDENCE_ORDER))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "categories": list(self.categories),
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence,
            "cpe": self.cpe,
        }


# -- product tables ------------------------------------------------------

#: Lowercase product name -> (CPE vendor, categories). Membership here is what
#: lets :func:`build_cpe` name a vendor; anything missing still yields a
#: Technology, just with ``cpe=None``. Aliases share a row on purpose so a
#: banner saying "Apache" and one saying "Apache httpd" land in the same place.
KNOWN_PRODUCTS: dict[str, tuple[str, tuple[str, ...]]] = {
    # web servers and proxies
    "nginx": ("nginx", ("web-server",)),
    "openresty": ("openresty", ("web-server",)),
    "apache": ("apache", ("web-server",)),
    "apache httpd": ("apache", ("web-server",)),
    "httpd": ("apache", ("web-server",)),
    "iis": ("microsoft", ("web-server",)),
    "microsoft-iis": ("microsoft", ("web-server",)),
    "tomcat": ("apache", ("web-server", "application-server")),
    "apache tomcat": ("apache", ("web-server", "application-server")),
    "jetty": ("eclipse", ("web-server", "application-server")),
    "lighttpd": ("lighttpd", ("web-server",)),
    "caddy": ("caddyserver", ("web-server",)),
    "squid": ("squid-cache", ("proxy",)),
    "varnish": ("varnish-cache", ("proxy",)),
    "haproxy": ("haproxy", ("proxy",)),
    "traefik": ("traefik", ("proxy",)),
    # other services that show up in -sV output
    "openssh": ("openbsd", ("remote-access",)),
    "mysql": ("oracle", ("database",)),
    "mariadb": ("mariadb", ("database",)),
    "postgresql": ("postgresql", ("database",)),
    "redis": ("redis", ("database",)),
    "mongodb": ("mongodb", ("database",)),
    "openssl": ("openssl", ("library",)),
    "exim": ("exim", ("mail-server",)),
    "postfix": ("postfix", ("mail-server",)),
    "proftpd": ("proftpd", ("file-transfer",)),
    "vsftpd": ("vsftpd", ("file-transfer",)),
    "bind": ("isc", ("dns",)),
    # languages and runtimes
    "php": ("php", ("language",)),
    "python": ("python", ("language",)),
    "perl": ("perl", ("language",)),
    "ruby": ("ruby-lang", ("language",)),
    "java": ("oracle", ("language",)),
    "node.js": ("nodejs", ("runtime",)),
    # application frameworks
    "asp.net": ("microsoft", ("framework",)),
    "django": ("djangoproject", ("framework",)),
    "rails": ("rubyonrails", ("framework",)),
    "laravel": ("laravel", ("framework",)),
    "express": ("expressjs", ("framework",)),
    "spring": ("vmware", ("framework",)),
    "next.js": ("vercel", ("framework",)),
    "nuxt": ("nuxt", ("framework",)),
    "gatsby": ("gatsbyjs", ("static-site-generator",)),
    # content management and commerce
    "wordpress": ("wordpress", ("cms",)),
    "drupal": ("drupal", ("cms",)),
    "joomla": ("joomla", ("cms",)),
    "magento": ("magento", ("e-commerce",)),
    "shopify": ("shopify", ("e-commerce",)),
    "typo3": ("typo3", ("cms",)),
    # browser-side libraries
    "jquery": ("jquery", ("js-library",)),
    "jquery ui": ("jquery", ("js-library",)),
    "bootstrap": ("getbootstrap", ("ui-framework",)),
    "react": ("facebook", ("js-library",)),
    "angular": ("angular", ("framework", "js-library")),
    "vue": ("vuejs", ("framework", "js-library")),
    "vue.js": ("vuejs", ("framework", "js-library")),
    "svelte": ("svelte", ("framework",)),
    "lodash": ("lodash", ("js-library",)),
    "moment.js": ("momentjs", ("js-library",)),
    "d3.js": ("d3js", ("js-library",)),
    "underscore.js": ("underscorejs", ("js-library",)),
    "axios": ("axios", ("js-library",)),
    "chart.js": ("chartjs", ("js-library",)),
    "handlebars": ("handlebarsjs", ("js-library",)),
    "backbone.js": ("backbonejs", ("js-library",)),
    "ember.js": ("emberjs", ("framework", "js-library")),
    "dojo": ("dojotoolkit", ("js-library",)),
    "mootools": ("mootools", ("js-library",)),
    "prototype": ("prototypejs", ("js-library",)),
    "tinymce": ("tiny", ("js-library",)),
    "ckeditor": ("ckeditor", ("js-library",)),
    "datatables": ("sprymedia", ("js-library",)),
    "leaflet": ("leafletjs", ("js-library",)),
    "mathjax": ("mathjax", ("js-library",)),
    "socket.io": ("socket", ("js-library",)),
}

#: Alias -> display name. Keeps "MICROSOFT-IIS", "httpd" and "angularjs" from
#: appearing as three separate technologies.
CANONICAL_NAMES: dict[str, str] = {
    "apache": "Apache httpd",
    "apache httpd": "Apache httpd",
    "apache/httpd": "Apache httpd",
    "httpd": "Apache httpd",
    "apache-coyote": "Apache Tomcat",
    "coyote": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "apache tomcat": "Apache Tomcat",
    "nginx": "nginx",
    "openresty": "OpenResty",
    "iis": "IIS",
    "microsoft-iis": "IIS",
    "microsoft iis": "IIS",
    "jetty": "Jetty",
    "lighttpd": "lighttpd",
    "caddy": "Caddy",
    "squid": "Squid",
    "squid-cache": "Squid",
    "varnish": "Varnish",
    "haproxy": "HAProxy",
    "traefik": "Traefik",
    "openssh": "OpenSSH",
    "openssl": "OpenSSL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "php": "PHP",
    "python": "Python",
    "perl": "Perl",
    "ruby": "Ruby",
    "java": "Java",
    "node": "Node.js",
    "nodejs": "Node.js",
    "node.js": "Node.js",
    "asp.net": "ASP.NET",
    "aspnet": "ASP.NET",
    "asp.net mvc": "ASP.NET",
    "django": "Django",
    "rails": "Rails",
    "ruby on rails": "Rails",
    "phusion passenger": "Phusion Passenger",
    "laravel": "Laravel",
    "express": "Express",
    "spring": "Spring",
    "next": "Next.js",
    "next.js": "Next.js",
    "nuxt": "Nuxt",
    "nuxt.js": "Nuxt",
    "gatsby": "Gatsby",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "joomla!": "Joomla",
    "magento": "Magento",
    "shopify": "Shopify",
    "typo3": "TYPO3",
    "jquery": "jQuery",
    "jquery-ui": "jQuery UI",
    "jquery.ui": "jQuery UI",
    "jquery ui": "jQuery UI",
    "bootstrap": "Bootstrap",
    "react": "React",
    "react-dom": "React",
    "angular": "Angular",
    "angularjs": "Angular",
    "angular.js": "Angular",
    "vue": "Vue.js",
    "vue.js": "Vue.js",
    "vuejs": "Vue.js",
    "svelte": "Svelte",
    "lodash": "Lodash",
    "moment": "Moment.js",
    "moment.js": "Moment.js",
    "d3": "D3.js",
    "d3.js": "D3.js",
    "underscore": "Underscore.js",
    "axios": "Axios",
    "chart": "Chart.js",
    "chart.js": "Chart.js",
    "chartjs": "Chart.js",
    "handlebars": "Handlebars",
    "backbone": "Backbone.js",
    "ember": "Ember.js",
    "dojo": "Dojo",
    "mootools": "MooTools",
    "prototype": "Prototype",
    "tinymce": "TinyMCE",
    "ckeditor": "CKEditor",
    "datatables": "DataTables",
    "leaflet": "Leaflet",
    "mathjax": "MathJax",
    "socket.io": "Socket.IO",
    "modernizr": "Modernizr",
    "requirejs": "RequireJS",
    "require": "RequireJS",
    "popper": "Popper.js",
    "swiper": "Swiper",
    "alpine": "Alpine.js",
    "alpinejs": "Alpine.js",
    "htmx": "htmx",
    "select2": "Select2",
    "three": "three.js",
    "gsap": "GSAP",
    "preact": "Preact",
    "redux": "Redux",
    "zepto": "Zepto",
}

#: Where the CPE product token is not just the lowercased display name.
CPE_PRODUCTS: dict[str, str] = {
    "apache httpd": "http_server",
    "apache tomcat": "tomcat",
    "iis": "internet_information_services",
    "jquery ui": "jquery_ui",
    "rails": "rails",
    "moment.js": "moment",
    "d3.js": "d3",
    "underscore.js": "underscore",
    "backbone.js": "backbone",
    "ember.js": "ember.js",
    "chart.js": "chart.js",
    "java": "jre",
}

#: Reverse of the CPE product token, for naming a technology found via a CPE.
_CPE_PRODUCT_TO_NAME: dict[str, str] = {
    **{token: name for name, token in CPE_PRODUCTS.items()},
    **{name: name for name in KNOWN_PRODUCTS},
}

#: Service names worth a category when nmap gave a product but we know nothing
#: else about it.
SERVICE_CATEGORY_HINTS: dict[str, tuple[str, ...]] = {
    "http": ("web-server",),
    "https": ("web-server",),
    "http-alt": ("web-server",),
    "http-proxy": ("proxy",),
    "ssh": ("remote-access",),
    "ftp": ("file-transfer",),
    "smtp": ("mail-server",),
    "imap": ("mail-server",),
    "pop3": ("mail-server",),
    "domain": ("dns",),
    "mysql": ("database",),
    "postgresql": ("database",),
}


def canonical_name(raw: str | None) -> str | None:
    """Map a banner token to a stable display name, or None when empty."""
    if not raw:
        return None
    text = " ".join(str(raw).split()).strip(" ,;")
    if not text:
        return None
    lowered = text.lower()
    if lowered in CANONICAL_NAMES:
        return CANONICAL_NAMES[lowered]
    # nmap writes "Apache httpd", "Microsoft IIS httpd", "OpenSSH" - try the
    # product words with nmap's trailing "httpd"/"server" noise removed.
    trimmed = re.sub(r"\s+(httpd|server|daemon)$", "", lowered).strip()
    if trimmed in CANONICAL_NAMES:
        return CANONICAL_NAMES[trimmed]
    if trimmed in KNOWN_PRODUCTS:
        return trimmed
    return text


def product_key(name: str | None) -> str | None:
    """The KNOWN_PRODUCTS lookup key for a display name."""
    if not name:
        return None
    return " ".join(str(name).split()).lower() or None


def categories_for(name: str | None, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Categories from the product table, falling back to the caller's guess."""
    key = product_key(name)
    if key and key in KNOWN_PRODUCTS:
        return KNOWN_PRODUCTS[key][1]
    return default


def vendor_for(name: str | None) -> str | None:
    key = product_key(name)
    if key and key in KNOWN_PRODUCTS:
        return KNOWN_PRODUCTS[key][0]
    return None


# -- CPE handling --------------------------------------------------------

#: Characters that would break a CPE 2.3 formatted string if left bare. ``.``
#: and ``-`` are deliberately *not* escaped: NVD itself writes
#: ``cpe:2.3:a:nginx:nginx:1.18.0:*:...``, and escaping them here would stop
#: feed CPEs from comparing equal to ours.
_CPE_ESCAPE = set(":!\"#$%&'()+,/;<=>?@[\\]^{|}~* ")


def _cpe_escape(value: str) -> str:
    out: list[str] = []
    for char in value.strip():
        if char.isspace():
            out.append("_")
        elif char in _CPE_ESCAPE:
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def _cpe_token(value: str) -> str:
    """Normalise a product/vendor word into a CPE component."""
    lowered = re.sub(r"\s+", "_", value.strip().lower())
    return _cpe_escape(re.sub(r"[^a-z0-9._+\-]", "_", lowered))


def build_cpe(vendor: str | None, product: str, version: str | None) -> str | None:
    """Format a CPE 2.3 application string, or None for an unknown product.

    A CPE with a guessed vendor is worse than no CPE: it will silently fail to
    match a feed and look like "no known vulnerabilities". So a vendor must come
    from the caller or from :data:`KNOWN_PRODUCTS`.
    """
    key = product_key(product)
    if not key:
        return None
    known = KNOWN_PRODUCTS.get(key)
    resolved_vendor = vendor or (known[0] if known else None)
    if not resolved_vendor:
        return None
    token = CPE_PRODUCTS.get(key) or _cpe_token(key)
    version_part = _cpe_escape(version) if version else "*"
    return f"cpe:2.3:a:{_cpe_token(resolved_vendor)}:{token}:{version_part}:*:*:*:*:*:*:*"


def split_cpe(cpe: str) -> list[str]:
    """Split a CPE string into components, honouring backslash escapes."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in cpe:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def normalise_cpe(cpe: str | None) -> str | None:
    """Return a CPE 2.3 formatted string, converting 2.2 URIs when needed.

    nmap supplies 2.2 (``cpe:/a:igor_sysoev:nginx:1.18.0``). Feeds are 2.3. One
    form has to win or nothing ever matches.
    """
    if not cpe:
        return None
    text = cpe.strip()
    if not text.lower().startswith("cpe:"):
        return None
    if text.lower().startswith("cpe:2.3:"):
        parts = split_cpe(text)[2:]
    elif text.lower().startswith("cpe:/"):
        # 2.2: part:vendor:product:version:update:edition:language
        parts = split_cpe(text[len("cpe:/") :])
    else:
        return None
    parts = [part if part not in {"", "-"} else "*" for part in parts]
    if not parts or parts[0] not in {"a", "o", "h", "*"}:
        return None
    parts = (parts + ["*"] * 11)[:11]
    return "cpe:2.3:" + ":".join(parts)


def cpe_fields(cpe: str | None) -> tuple[str | None, str | None, str | None, str | None]:
    """``(part, vendor, product, version)`` from any CPE form, or Nones."""
    normalised = normalise_cpe(cpe)
    if not normalised:
        return (None, None, None, None)
    parts = split_cpe(normalised)
    # cpe:2.3:part:vendor:product:version:...
    if len(parts) < 6:
        return (None, None, None, None)
    return (parts[2], parts[3], parts[4], parts[5])


def _unescape_cpe_component(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"\\(.)", r"\1", value)


# -- header detection ----------------------------------------------------

#: ``nginx/1.18.0``, ``PHP/7.4.3``, ``mod_wsgi/4.6.8`` - the one shape nearly
#: every server banner agrees on.
_PRODUCT_VERSION = re.compile(r"([A-Za-z][A-Za-z0-9_.+\-]{1,40})/v?(\d[A-Za-z0-9.\-_]*)")

#: Bare product words that identify a product even without a version.
_BARE_PRODUCTS: tuple[str, ...] = (
    "cloudflare",
    "cloudfront",
    "varnish",
    "squid",
    "haproxy",
    "traefik",
    "openresty",
    "nginx",
    "apache",
    "express",
    "asp.net",
    "php",
    "next.js",
    "nuxt",
    "vegur",
    "akamaighost",
    "litespeed",
    "gunicorn",
    "waitress",
    "werkzeug",
    "kestrel",
    "jetty",
    "tomcat",
)

#: Cookie name marker -> (display name, categories). A session cookie name is
#: set by the framework, not by content, so it is decent evidence - but it never
#: carries a version.
COOKIE_MARKERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("jsessionid", "Java", ("language",)),
    ("laravel_session", "Laravel", ("framework",)),
    ("phpsessid", "PHP", ("language",)),
    ("asp.net_sessionid", "ASP.NET", ("framework",)),
    ("csrftoken", "Django", ("framework",)),
    ("_rails_session", "Rails", ("framework",)),
)


def _header_items(headers: dict[str, str]) -> list[tuple[str, str]]:
    return [(str(k).strip().lower(), str(v)) for k, v in (headers or {}).items() if v]


def _technology(
    name: str | None,
    version: str | None,
    *,
    source: str,
    evidence: str,
    categories: tuple[str, ...] = (),
    confidence: str | None = None,
    cpe: str | None = None,
) -> Technology | None:
    """Build a Technology, applying the confidence ladder and the CPE table."""
    display = canonical_name(name)
    if not display:
        return None
    clean_version = _clean_version(version)
    if confidence is None:
        confidence = "certain" if clean_version else "likely"
    return Technology(
        name=display,
        version=clean_version,
        categories=categories_for(display, categories),
        confidence=confidence,
        source=source,
        evidence=evidence.strip()[:300],
        cpe=cpe or build_cpe(None, display, clean_version),
    )


def _clean_version(version: str | None) -> str | None:
    if version is None:
        return None
    text = str(version).strip().strip(",;()")
    if not text or not re.match(r"^\d", text):
        return None
    return text[:60]


def detect_from_headers(headers: dict[str, str]) -> list[Technology]:
    """Technologies disclosed by HTTP response headers and session cookies."""
    found: list[Technology] = []
    items = _header_items(headers)

    for name, value in items:
        if name in {"server", "x-powered-by", "x-generator", "powered-by"}:
            source = f"header:{name}"
            matched = False
            for product, version in _PRODUCT_VERSION.findall(value):
                matched = True
                tech = _technology(
                    product,
                    version,
                    source=source,
                    evidence=f"{name}: {value}",
                    categories=("web-server",) if name == "server" else (),
                )
                if tech:
                    found.append(tech)
            if not matched:
                for tech in _bare_products(value, source=source, evidence=f"{name}: {value}"):
                    found.append(tech)
                # "Drupal 10 (https://www.drupal.org)" and friends.
                name_part, version_part = _split_name_version(value)
                tech = _technology(
                    name_part,
                    version_part,
                    source=source,
                    evidence=f"{name}: {value}",
                    confidence="certain" if version_part else "likely",
                )
                if tech and not any(t.key == tech.key for t in found):
                    found.append(tech)

        elif name in {"x-aspnet-version", "x-aspnetmvc-version"}:
            tech = _technology(
                "ASP.NET",
                value.strip(),
                source=f"header:{name}",
                evidence=f"{name}: {value}",
            )
            if tech:
                found.append(tech)

        elif name.startswith("x-drupal"):
            tech = _technology(
                "Drupal",
                None,
                source=f"header:{name}",
                evidence=f"{name}: {value}",
                confidence="likely",
            )
            if tech:
                found.append(tech)

        elif name == "via":
            for product, version in _PRODUCT_VERSION.findall(value):
                tech = _technology(
                    product,
                    version,
                    source="header:via",
                    evidence=f"via: {value}",
                    categories=("proxy",),
                    confidence="likely",
                )
                if tech:
                    found.append(tech)
            found.extend(
                _bare_products(
                    value,
                    source="header:via",
                    evidence=f"via: {value}",
                    categories=("proxy",),
                    confidence="possible",
                )
            )

        elif name == "x-runtime":
            # Rails sets this on every response; the value is a duration.
            tech = _technology(
                "Rails",
                None,
                source="header:x-runtime",
                evidence=f"x-runtime: {value}",
                confidence="possible",
            )
            if tech:
                found.append(tech)

    found.extend(_cookie_technologies(items))
    return found


def _bare_products(
    value: str,
    *,
    source: str,
    evidence: str,
    categories: tuple[str, ...] = (),
    confidence: str = "likely",
) -> list[Technology]:
    lowered = value.lower()
    out: list[Technology] = []
    for product in _BARE_PRODUCTS:
        if re.search(r"(?<![a-z0-9.])" + re.escape(product) + r"(?![a-z0-9])", lowered):
            tech = _technology(
                product,
                None,
                source=source,
                evidence=evidence,
                categories=categories,
                confidence=confidence,
            )
            if tech:
                out.append(tech)
    return out


def _cookie_technologies(items: list[tuple[str, str]]) -> list[Technology]:
    out: list[Technology] = []
    for header, value in items:
        if header not in {"set-cookie", "cookie"}:
            continue
        for cookie_name in _cookie_names(value):
            lowered = cookie_name.lower()
            for marker, display, categories in COOKIE_MARKERS:
                if marker in lowered:
                    tech = _technology(
                        display,
                        None,
                        source="cookie",
                        evidence=cookie_name,
                        categories=categories,
                        confidence="likely",
                    )
                    if tech:
                        out.append(tech)
    return out


def _cookie_names(value: str) -> list[str]:
    """Cookie names from a Set-Cookie value, including joined multi-values."""
    names: list[str] = []
    for chunk in re.split(r"[,\n]", value):
        for pair in chunk.split(";"):
            if "=" not in pair:
                continue
            candidate = pair.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_.\-$]{2,64}", candidate or ""):
                names.append(candidate)
            # Only the first pair of a cookie is its name; the rest are attrs.
            break
    return names


def _split_name_version(text: str) -> tuple[str | None, str | None]:
    """Split "WordPress 6.4.2" / "Drupal 10 (drupal.org)" into name + version."""
    cleaned = re.sub(r"\s*\([^)]*\)", "", str(text)).strip()
    cleaned = cleaned.split(" - ")[0].strip()
    if not cleaned:
        return (None, None)
    match = re.match(r"^(?P<name>[A-Za-z][\w .+!#-]*?)[\s/_-]+v?(?P<version>\d[\w.]*)\s*$", cleaned)
    if match:
        return (match.group("name").strip(), match.group("version"))
    return (cleaned[:80], None)


# -- HTML detection ------------------------------------------------------

_META_TAG = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_ATTR = re.compile(
    r"""([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)

#: ``(display name, default categories, pattern, base confidence)``. A pattern
#: may expose a ``version`` group; when it matches, confidence is raised to
#: "likely" because the markup stated the version itself.
HTML_MARKERS: tuple[tuple[str, tuple[str, ...], re.Pattern[str], str], ...] = (
    (
        "WordPress",
        ("cms",),
        re.compile(r"/wp-(?:content|includes|json)/|wp-embed\.min\.js", re.IGNORECASE),
        "likely",
    ),
    (
        "Drupal",
        ("cms",),
        re.compile(
            r"Drupal\.settings|drupal-data|data-drupal-|/sites/(?:default|all)/(?:files|modules|themes)",
            re.IGNORECASE,
        ),
        "likely",
    ),
    (
        "Joomla",
        ("cms",),
        re.compile(r"/media/jui/|/media/system/js/|Joomla!|option=com_", re.IGNORECASE),
        "likely",
    ),
    (
        "Next.js",
        ("framework",),
        re.compile(r"__NEXT_DATA__|/_next/static/", re.IGNORECASE),
        "likely",
    ),
    ("Nuxt", ("framework",), re.compile(r"__NUXT__|/_nuxt/", re.IGNORECASE), "likely"),
    (
        "Gatsby",
        ("static-site-generator",),
        re.compile(r"___gatsby|/page-data/(?:app-data\.json|sq/)|gatsby-chunk", re.IGNORECASE),
        "likely",
    ),
    (
        "Shopify",
        ("e-commerce",),
        re.compile(r"cdn\.shopify\.com|Shopify\.theme|/cdn/shop/", re.IGNORECASE),
        "likely",
    ),
    (
        "Magento",
        ("e-commerce",),
        re.compile(r"Magento_|mage/cookies|/static/(?:version\d+/)?frontend/", re.IGNORECASE),
        "likely",
    ),
    (
        "React",
        ("js-library",),
        re.compile(r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom", re.IGNORECASE),
        "possible",
    ),
    (
        "Vue.js",
        ("framework",),
        re.compile(r"__VUE[A-Z_]*__|data-v-app|\sv-(?:cloak|bind|if|for)[\s=>]", re.IGNORECASE),
        "possible",
    ),
    (
        "Angular",
        ("framework",),
        re.compile(
            r"""ng-version=["'](?P<version>[0-9][0-9.]*)["']|\sng-app[\s=>]|_nghost-|_ngcontent-""",
            re.IGNORECASE,
        ),
        "possible",
    ),
    (
        "Svelte",
        ("framework",),
        re.compile(r"\bsvelte-[0-9a-z]{6,}\b|__SVELTE|/_app/immutable/", re.IGNORECASE),
        "possible",
    ),
)


def meta_generator(html: str) -> str | None:
    """The ``<meta name=generator>`` content, if the page has one."""
    for tag in _META_TAG.findall(html or ""):
        attrs: dict[str, str] = {}
        for match in _ATTR.finditer(tag):
            key = match.group(1).lower()
            attrs[key] = match.group(2) or match.group(3) or match.group(4) or ""
        if attrs.get("name", "").strip().lower() == "generator":
            content = attrs.get("content", "").strip()
            return content or None
    return None


def detect_from_html(html: str) -> list[Technology]:
    """Technologies named by the markup: meta generator plus known markers."""
    if not html:
        return []
    found: list[Technology] = []

    generator = meta_generator(html)
    if generator:
        name, version = _split_name_version(generator)
        tech = _technology(
            name,
            version,
            source="meta:generator",
            evidence=generator,
            confidence="certain" if version else "likely",
        )
        if tech:
            found.append(tech)

    for display, categories, pattern, confidence in HTML_MARKERS:
        match = pattern.search(html)
        if not match:
            continue
        version = (match.groupdict().get("version") or None) if match.groupdict() else None
        tech = _technology(
            display,
            version,
            source="markup",
            evidence=match.group(0)[:120],
            categories=categories,
            confidence="likely" if version else confidence,
        )
        if tech:
            found.append(tech)
    return found


# -- script URL detection ------------------------------------------------

#: Filename token -> (display name, categories). The table exists so a bundle
#: called ``react-dom.production.min.js`` is reported as React rather than as a
#: library called "react-dom.production".
KNOWN_LIBRARIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "jquery": ("jQuery", ("js-library",)),
    "jquery-ui": ("jQuery UI", ("js-library",)),
    "jquery.ui": ("jQuery UI", ("js-library",)),
    "jquery-migrate": ("jQuery Migrate", ("js-library",)),
    "bootstrap": ("Bootstrap", ("ui-framework",)),
    "react": ("React", ("js-library",)),
    "react-dom": ("React", ("js-library",)),
    "preact": ("Preact", ("js-library",)),
    "vue": ("Vue.js", ("framework", "js-library")),
    "angular": ("Angular", ("framework", "js-library")),
    "angularjs": ("Angular", ("framework", "js-library")),
    "angular.js": ("Angular", ("framework", "js-library")),
    "svelte": ("Svelte", ("framework",)),
    "lodash": ("Lodash", ("js-library",)),
    "underscore": ("Underscore.js", ("js-library",)),
    "moment": ("Moment.js", ("js-library",)),
    "d3": ("D3.js", ("js-library",)),
    "axios": ("Axios", ("js-library",)),
    "backbone": ("Backbone.js", ("js-library",)),
    "ember": ("Ember.js", ("framework", "js-library")),
    "knockout": ("Knockout", ("js-library",)),
    "handlebars": ("Handlebars", ("js-library",)),
    "mustache": ("Mustache", ("js-library",)),
    "three": ("three.js", ("js-library",)),
    "gsap": ("GSAP", ("js-library",)),
    "popper": ("Popper.js", ("js-library",)),
    "modernizr": ("Modernizr", ("js-library",)),
    "require": ("RequireJS", ("js-library",)),
    "requirejs": ("RequireJS", ("js-library",)),
    "swiper": ("Swiper", ("js-library",)),
    "alpine": ("Alpine.js", ("js-library",)),
    "htmx": ("htmx", ("js-library",)),
    "chart": ("Chart.js", ("js-library",)),
    "select2": ("Select2", ("js-library",)),
    "datatables": ("DataTables", ("js-library",)),
    "jquery.datatables": ("DataTables", ("js-library",)),
    "tinymce": ("TinyMCE", ("js-library",)),
    "ckeditor": ("CKEditor", ("js-library",)),
    "leaflet": ("Leaflet", ("js-library",)),
    "mathjax": ("MathJax", ("js-library",)),
    "prototype": ("Prototype", ("js-library",)),
    "mootools": ("MooTools", ("js-library",)),
    "socket.io": ("Socket.IO", ("js-library",)),
    "redux": ("Redux", ("js-library",)),
    "zepto": ("Zepto", ("js-library",)),
    "dojo": ("Dojo", ("js-library",)),
}

#: Build-pipeline words in a filename that are not part of the library name.
_MODIFIER_PARTS: frozenset[str] = frozenset(
    {
        "min",
        "prod",
        "production",
        "development",
        "dev",
        "slim",
        "bundle",
        "runtime",
        "esm",
        "umd",
        "cjs",
        "common",
        "global",
        "browser",
        "pack",
        "compat",
        "legacy",
        "modern",
        "full",
        "standalone",
        "mjs",
        "module",
    }
)

#: Names that carry no information about what the site is built with.
_GENERIC_SCRIPT_NAMES: frozenset[str] = frozenset(
    {
        "app",
        "application",
        "main",
        "index",
        "bundle",
        "script",
        "scripts",
        "vendor",
        "vendors",
        "chunk",
        "chunks",
        "runtime",
        "polyfill",
        "polyfills",
        "common",
        "commons",
        "styles",
        "style",
        "site",
        "custom",
        "theme",
        "all",
        "manifest",
        "inline",
        "global",
        "init",
        "config",
        "analytics",
        "tracking",
        "sw",
        "service-worker",
        "client",
        "server",
        "page",
        "pages",
        "header",
        "footer",
        "core",
        "utils",
        "util",
        "lib",
        "js",
    }
)

#: Path fragments that identify a stack regardless of the filename.
PATH_MARKERS: tuple[tuple[str, tuple[str, ...], re.Pattern[str], str], ...] = (
    ("Next.js", ("framework",), re.compile(r"/_next/(?:static|image)", re.IGNORECASE), "likely"),
    ("Nuxt", ("framework",), re.compile(r"/_nuxt/", re.IGNORECASE), "likely"),
    ("WordPress", ("cms",), re.compile(r"/wp-(?:content|includes)/", re.IGNORECASE), "likely"),
    (
        "Drupal",
        ("cms",),
        re.compile(r"/sites/(?:default|all)/(?:modules|themes|files)/", re.IGNORECASE),
        "likely",
    ),
    ("Joomla", ("cms",), re.compile(r"/media/(?:jui|system)/js/", re.IGNORECASE), "likely"),
    ("Shopify", ("e-commerce",), re.compile(r"cdn\.shopify\.com|/cdn/shop/", re.IGNORECASE), "likely"),
    (
        "Magento",
        ("e-commerce",),
        re.compile(r"/static/(?:version\d+/)?frontend/", re.IGNORECASE),
        "likely",
    ),
    ("Gatsby", ("static-site-generator",), re.compile(r"/page-data/|gatsby-", re.IGNORECASE), "likely"),
)

#: ``bootstrap@5.3.0`` (npm CDNs).
_AT_VERSION = re.compile(r"(?:^|[/@])([a-zA-Z][a-zA-Z0-9._\-]{1,40})@v?(\d[\w.\-]*)")
#: ``/ajax/libs/angular/1.7.9/angular.js`` (cdnjs and lookalikes).
_PATH_VERSION = re.compile(r"/([a-zA-Z][a-zA-Z0-9._\-]{1,40})/v?(\d+(?:\.\d+)+)/")
#: ``jquery-3.6.0``, ``jquery.3.6.0``, ``lodash_4.17.21``.
_NAME_DASH_VERSION = re.compile(r"^(?P<name>[a-zA-Z][\w.\-]*?)[-_.]v?(?P<version>\d+(?:\.\d+)+)$")
#: ``d3.v7``, ``plotly-v2``.
_NAME_V_VERSION = re.compile(r"^(?P<name>[a-zA-Z][\w.\-]*?)[-_.]v(?P<version>\d+(?:\.\d+)*)$")


def _resolve_library(token: str) -> tuple[str, tuple[str, ...]] | None:
    """Look a filename token up in the library table, narrowing as we go."""
    candidate = token.strip(" .-_").lower()
    if not candidate:
        return None
    seen: set[str] = set()
    while candidate and candidate not in seen:
        seen.add(candidate)
        if candidate in KNOWN_LIBRARIES:
            return KNOWN_LIBRARIES[candidate]
        if "." in candidate:
            candidate = candidate.rsplit(".", 1)[0]
            continue
        if "-" in candidate:
            candidate = candidate.rsplit("-", 1)[0]
            continue
        break
    return None


def _strip_modifiers(stem: str) -> str:
    """Drop ``.min``, ``.production``, ``.runtime`` and friends from a stem."""
    parts = re.split(r"[.]", stem)
    kept = [part for part in parts if part.lower() not in _MODIFIER_PARTS]
    if not kept:
        kept = parts[:1]
    name = ".".join(kept)
    # ``react-dom.production`` style modifiers also appear hyphenated.
    pieces = name.split("-")
    while len(pieces) > 1 and pieces[-1].lower() in _MODIFIER_PARTS:
        pieces.pop()
    return "-".join(pieces)


def _version_from_query(url: str) -> str | None:
    query = urlsplit(url).query
    if not query:
        return None
    for key, value in parse_qsl(query, keep_blank_values=False):
        if key.lower() in {"ver", "v", "version"} and re.match(r"^\d", value or ""):
            return value
    return None


def extract_library(url: str) -> tuple[str | None, str | None]:
    """``(name token, version)`` parsed out of a script URL, best effort.

    Pure string work on the URL netrecon already saw referenced; nothing is
    requested. The name is a *token* (``react-dom``), not yet a display name.
    """
    raw = (url or "").strip()
    if not raw:
        return (None, None)
    path = urlsplit(raw).path or raw

    match = _AT_VERSION.search(raw)
    if match:
        return (match.group(1), match.group(2))

    match = _PATH_VERSION.search(path)
    if match:
        return (match.group(1), match.group(2))

    stem = path.rstrip("/").rsplit("/", 1)[-1]
    stem = re.sub(r"\.(?:js|mjs|cjs|jsx|ts|css|map)$", "", stem, flags=re.IGNORECASE)
    if not stem:
        return (None, None)

    # Modifiers are stripped before the version patterns run, so that
    # ``jquery-3.6.0.min`` still ends in its version.
    cleaned = _strip_modifiers(stem)
    for pattern in (_NAME_V_VERSION, _NAME_DASH_VERSION):
        match = pattern.match(cleaned)
        if match:
            return (_strip_modifiers(match.group("name")), match.group("version"))
    return (cleaned or None, _version_from_query(raw))


def detect_from_scripts(script_urls: list[str]) -> list[Technology]:
    """Libraries and frameworks named by ``<script src>`` URLs."""
    found: list[Technology] = []
    for url in script_urls or []:
        text = str(url).strip()
        if not text:
            continue

        for display, categories, pattern, confidence in PATH_MARKERS:
            if pattern.search(text):
                tech = _technology(
                    display,
                    None,
                    source="script-url",
                    evidence=text,
                    categories=categories,
                    confidence=confidence,
                )
                if tech:
                    found.append(tech)

        token, version = extract_library(text)
        if not token:
            continue
        known = _resolve_library(token)
        if known:
            display, categories = known
            # A filename is cheap to get wrong (pinned name, patched build), so
            # a version read out of one never reaches "certain".
            tech = _technology(
                display,
                version,
                source="script-url",
                evidence=text,
                categories=categories,
                confidence="likely",
            )
            if tech:
                found.append(tech)
            continue

        lowered = token.lower()
        if not version or lowered in _GENERIC_SCRIPT_NAMES:
            continue
        if not re.fullmatch(r"[a-z][a-z0-9._\-]{1,30}", lowered):
            continue
        tech = _technology(
            token,
            version,
            source="script-url",
            evidence=text,
            categories=("js-library",),
            confidence="possible",
        )
        if tech:
            found.append(tech)
    return found


# -- service (nmap) detection -------------------------------------------


def detect_from_service(evidence: ServiceEvidence) -> list[Technology]:
    """Technologies from ``nmap -sV`` fields and the CPEs nmap supplied."""
    found: list[Technology] = []
    service_categories = SERVICE_CATEGORY_HINTS.get((evidence.service or "").lower(), ())

    if evidence.product:
        tech = _technology(
            evidence.product,
            evidence.version,
            source="nmap-sV",
            evidence=evidence.banner,
            categories=service_categories,
        )
        if tech:
            found.append(tech)

    if evidence.extrainfo:
        # nmap parks secondary products here: "PHP/7.4.3", "(Ubuntu)".
        for product, version in _PRODUCT_VERSION.findall(evidence.extrainfo):
            tech = _technology(
                product,
                version,
                source="nmap-sV",
                evidence=evidence.extrainfo,
                confidence="likely",
            )
            if tech:
                found.append(tech)

    for raw_cpe in evidence.cpes or ():
        part, vendor, product, version = cpe_fields(raw_cpe)
        # Only application CPEs: an ``o:`` CPE describes the host's OS, which is
        # not this service's technology stack.
        if part != "a" or not product or product == "*":
            continue
        token = _unescape_cpe_component(product) or product
        display = _CPE_PRODUCT_TO_NAME.get(token, token.replace("_", " "))
        cpe_version = _unescape_cpe_component(version)
        if cpe_version in {"*", "-", ""}:
            cpe_version = None
        tech = _technology(
            display,
            cpe_version,
            source="nmap-sV",
            evidence=raw_cpe,
            categories=service_categories,
            confidence="likely",
            cpe=normalise_cpe(raw_cpe),
        )
        if tech:
            found.append(tech)

    return found


# -- merging -------------------------------------------------------------


def merge(technologies: list[Technology]) -> list[Technology]:
    """Collapse duplicates by name, keeping the best-supported record.

    "Best" means: a record with a version beats one without, then higher
    confidence wins, then one carrying a CPE wins. Categories are unioned so a
    detection that only knew "js-library" does not erase "framework".
    """
    best: dict[str, Technology] = {}
    categories: dict[str, list[str]] = {}

    for tech in technologies or []:
        if not tech or not tech.name:
            continue
        key = tech.key
        bucket = categories.setdefault(key, [])
        for category in tech.categories:
            if category not in bucket:
                bucket.append(category)

        current = best.get(key)
        if current is None or _is_better(tech, current):
            # Do not lose a CPE the loser had: the winner is usually the more
            # specific banner, while the CPE often came from nmap's own table.
            if current is not None and tech.cpe is None and current.cpe:
                tech = replace(tech, cpe=current.cpe)
            best[key] = tech
        elif current.cpe is None and tech.cpe:
            best[key] = replace(current, cpe=tech.cpe)

    merged = [
        Technology(
            name=tech.name,
            version=tech.version,
            categories=tuple(sorted(categories.get(key, ()))),
            confidence=tech.confidence,
            source=tech.source,
            evidence=tech.evidence,
            cpe=tech.cpe,
        )
        for key, tech in best.items()
    ]
    return sorted(merged, key=lambda t: (t.key, t.name))


def _is_better(candidate: Technology, current: Technology) -> bool:
    candidate_score = (
        candidate.version is not None,
        -candidate.rank,
        candidate.cpe is not None,
    )
    current_score = (current.version is not None, -current.rank, current.cpe is not None)
    return candidate_score > current_score


def detect_web(
    headers: dict[str, str] | None = None,
    html: str = "",
    script_urls: list[str] | None = None,
) -> list[Technology]:
    """Everything the web stage can fingerprint from one response, merged."""
    found: list[Technology] = []
    found.extend(detect_from_headers(headers or {}))
    found.extend(detect_from_html(html or ""))
    found.extend(detect_from_scripts(script_urls or []))
    return merge(found)


def summarise(technologies: list[Technology]) -> dict[str, Any]:
    """Compact view for a checkpoint: labels, categories and version coverage."""
    merged = merge(technologies)
    by_category: dict[str, list[str]] = {}
    for tech in merged:
        for category in tech.categories or ("other",):
            by_category.setdefault(category, []).append(tech.label)
    return {
        "count": len(merged),
        "with_version": sum(1 for t in merged if t.version),
        "labels": [t.label for t in merged],
        "by_category": {k: sorted(v) for k, v in sorted(by_category.items())},
        "technologies": [t.to_dict() for t in merged],
    }
