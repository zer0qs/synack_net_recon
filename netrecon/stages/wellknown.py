"""The curated path list used by web recon.

This is deliberately **not** a directory brute-force wordlist. It is a short,
hand-picked set of paths that are (a) frequently exposed by accident and (b)
disclose something concrete when they are. The distinction matters: a 120-path
check against each endpoint is a handful of extra log lines, where a 100k-entry
wordlist is an attack on the application's availability and a very different
conversation with the client.

Two sources of paths exist:

* this list, which only runs when the operator passes ``--hidden-paths``; and
* paths the site itself publishes in ``robots.txt`` and ``sitemap.xml``, which
  are not guessing at all - the site advertised them.

Anything that would modify state, or that only exists in an exploit chain, is
out of scope. Every entry here is a plain GET of a file that should not be
world-readable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: ``(path, why it matters)``. The note is shown in the report so a reader does
#: not have to guess why a 200 on some path is interesting.
WELL_KNOWN_PATHS: tuple[tuple[str, str], ...] = (
    # Version control metadata - the highest-value accidental exposure there is.
    ("/.git/HEAD", "Git repository exposed; the full source history may be retrievable"),
    ("/.git/config", "Git config exposed; may contain remote URLs with credentials"),
    ("/.svn/entries", "Subversion metadata exposed"),
    ("/.hg/requires", "Mercurial repository exposed"),
    ("/.bzr/README", "Bazaar repository exposed"),
    # Environment and configuration.
    ("/.env", "Environment file exposed; these routinely hold database and API credentials"),
    ("/.env.local", "Local environment file exposed"),
    ("/.env.production", "Production environment file exposed"),
    ("/config.json", "Application configuration exposed"),
    ("/config.yml", "Application configuration exposed"),
    ("/config.yaml", "Application configuration exposed"),
    ("/appsettings.json", "ASP.NET configuration exposed; often contains connection strings"),
    ("/web.config", "IIS configuration exposed"),
    ("/.htaccess", "Apache per-directory config readable"),
    ("/.htpasswd", "Apache password file readable"),
    ("/wp-config.php.bak", "WordPress configuration backup exposed"),
    ("/.aws/credentials", "AWS credentials file exposed"),
    ("/.npmrc", "npm config exposed; may contain a registry token"),
    ("/.dockerenv", "Container marker"),
    ("/docker-compose.yml", "Compose file exposed; often lists services and secrets"),
    # Dependency manifests - low severity, but they pin exact versions.
    ("/package.json", "Dependency manifest; pins exact front-end versions"),
    ("/package-lock.json", "Dependency lockfile; full transitive version list"),
    ("/composer.json", "PHP dependency manifest"),
    ("/composer.lock", "PHP dependency lockfile"),
    ("/requirements.txt", "Python dependency manifest"),
    ("/Gemfile", "Ruby dependency manifest"),
    ("/Gemfile.lock", "Ruby dependency lockfile"),
    ("/go.mod", "Go module manifest"),
    ("/yarn.lock", "Yarn lockfile"),
    # Backups and dumps.
    ("/backup.zip", "Backup archive exposed"),
    ("/backup.tar.gz", "Backup archive exposed"),
    ("/backup.sql", "Database dump exposed"),
    ("/dump.sql", "Database dump exposed"),
    ("/database.sql", "Database dump exposed"),
    ("/db.sqlite3", "SQLite database exposed"),
    ("/site.tar.gz", "Site archive exposed"),
    ("/www.zip", "Site archive exposed"),
    # API documentation and schemas.
    ("/swagger.json", "OpenAPI schema; documents the full API surface"),
    ("/swagger/v1/swagger.json", "OpenAPI schema"),
    ("/openapi.json", "OpenAPI schema"),
    ("/api-docs", "API documentation"),
    ("/api/swagger.json", "OpenAPI schema"),
    ("/v2/api-docs", "Springfox API documentation"),
    ("/graphql", "GraphQL endpoint; check whether introspection is enabled"),
    ("/.well-known/security.txt", "Security contact information"),
    ("/.well-known/openid-configuration", "OIDC discovery document"),
    # Status, metrics and debug surfaces.
    ("/server-status", "Apache mod_status; discloses live requests and client addresses"),
    ("/server-info", "Apache mod_info; discloses the server configuration"),
    ("/nginx_status", "nginx stub status"),
    ("/status", "Application status endpoint"),
    ("/health", "Health endpoint"),
    ("/metrics", "Prometheus metrics; often discloses internal hostnames and paths"),
    ("/actuator", "Spring Boot Actuator root"),
    ("/actuator/health", "Spring Boot health endpoint"),
    ("/actuator/env", "Spring Boot environment; discloses configuration and secrets"),
    ("/actuator/mappings", "Spring Boot route list"),
    ("/debug/pprof/", "Go pprof debug endpoint exposed"),
    ("/phpinfo.php", "phpinfo() exposed; discloses full PHP configuration"),
    ("/info.php", "phpinfo() exposed"),
    ("/test.php", "Test script left in place"),
    ("/trace.axd", "ASP.NET trace viewer exposed"),
    ("/elmah.axd", "ELMAH error log viewer exposed"),
    # Admin and management interfaces.
    ("/admin", "Administrative interface"),
    ("/administrator", "Administrative interface (Joomla)"),
    ("/wp-admin/", "WordPress administration"),
    ("/wp-login.php", "WordPress login"),
    ("/user/login", "Drupal login"),
    ("/phpmyadmin/", "phpMyAdmin exposed"),
    ("/pma/", "phpMyAdmin exposed"),
    ("/adminer.php", "Adminer database client exposed"),
    ("/manager/html", "Tomcat manager exposed"),
    ("/console", "Application console"),
    ("/jenkins/", "Jenkins exposed"),
    ("/.well-known/acme-challenge/", "ACME challenge directory"),
    # Editors, IDE and OS leftovers.
    ("/.vscode/settings.json", "Editor settings committed to the webroot"),
    ("/.idea/workspace.xml", "IDE project files committed to the webroot"),
    ("/.DS_Store", "macOS directory index; discloses file names"),
    ("/Thumbs.db", "Windows thumbnail cache"),
    ("/.bash_history", "Shell history exposed"),
    ("/.ssh/id_rsa", "Private SSH key exposed"),
    ("/.ssh/authorized_keys", "SSH authorised keys exposed"),
    # CI/CD and deployment metadata.
    ("/.gitlab-ci.yml", "CI configuration exposed"),
    ("/.github/workflows/", "CI workflow directory"),
    ("/Jenkinsfile", "CI pipeline definition exposed"),
    ("/Dockerfile", "Dockerfile exposed"),
    ("/.travis.yml", "CI configuration exposed"),
    # Logs and temporary files.
    ("/error_log", "Error log readable"),
    ("/debug.log", "Debug log readable"),
    ("/logs/", "Log directory listing"),
    ("/tmp/", "Temporary directory listing"),  # noqa: S108 - a URL path, not a filesystem path
    ("/.well-known/change-password", "Password change endpoint declaration"),
    # Common sensitive directories.
    ("/backup/", "Backup directory listing"),
    ("/old/", "Old-version directory listing"),
    ("/test/", "Test directory listing"),
    ("/uploads/", "Upload directory listing"),
    ("/files/", "File directory listing"),
    ("/private/", "Private directory listing"),
    ("/includes/", "Include directory listing"),
    ("/vendor/", "Dependency directory listing"),
    ("/node_modules/", "Dependency directory exposed in the webroot"),
    ("/storage/logs/laravel.log", "Laravel log exposed"),
    ("/.well-known/assetlinks.json", "Android app link declaration"),
    ("/apple-app-site-association", "iOS universal link declaration"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain policy"),
    ("/sitemap_index.xml", "Sitemap index"),
    ("/feed", "Content feed"),
    ("/rss", "Content feed"),
)

#: Paths whose presence is worth a higher severity than a plain 200.
HIGH_VALUE_PREFIXES: tuple[str, ...] = (
    "/.git", "/.svn", "/.hg", "/.bzr", "/.env", "/.aws", "/.ssh", "/.htpasswd",
    "/backup", "/dump.sql", "/database.sql", "/db.sqlite3", "/actuator/env",
    "/web.config", "/appsettings.json", "/wp-config", "/.npmrc", "/.bash_history",
)


@dataclass(frozen=True)
class PathCandidate:
    """One path to request, and where the idea came from."""

    path: str
    reason: str
    #: "curated" for this list, "robots" / "sitemap" for site-published paths.
    origin: str = "curated"

    @property
    def high_value(self) -> bool:
        return self.path.startswith(HIGH_VALUE_PREFIXES)


def curated_paths(limit: int) -> list[PathCandidate]:
    """The first *limit* entries of the curated list, in declaration order.

    Declaration order is deliberate: the highest-value paths come first, so a
    reduced limit still checks the things most worth checking.
    """
    return [
        PathCandidate(path, reason, "curated")
        for path, reason in WELL_KNOWN_PATHS[: max(limit, 0)]
    ]


_ROBOTS_RULE = re.compile(r"^\s*(?:dis)?allow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]{1,300})\s*</loc>", re.IGNORECASE)


def paths_from_robots(body: str, limit: int = 60) -> list[PathCandidate]:
    """Paths the site itself listed in robots.txt.

    A ``Disallow`` entry is the site telling crawlers where something is. That
    is published information, not a guess, so these are fetched even without
    ``--hidden-paths``.
    """
    found: list[PathCandidate] = []
    seen: set[str] = set()
    for rule in _ROBOTS_RULE.findall(body or ""):
        path = rule.strip()
        if not path.startswith("/") or path in seen or "*" in path:
            continue
        seen.add(path)
        found.append(PathCandidate(path, "listed in robots.txt", "robots"))
        if len(found) >= limit:
            break
    return found


def paths_from_sitemap(body: str, base_netloc: str, limit: int = 60) -> list[PathCandidate]:
    """Paths from a sitemap, restricted to this endpoint's own host."""
    from urllib.parse import urlsplit

    found: list[PathCandidate] = []
    seen: set[str] = set()
    for location in _SITEMAP_LOC.findall(body or ""):
        parts = urlsplit(location.strip())
        if parts.netloc and parts.netloc.lower() != base_netloc.lower():
            continue  # another host is not in scope
        path = parts.path or "/"
        if not path.startswith("/") or path in seen:
            continue
        seen.add(path)
        found.append(PathCandidate(path, "listed in sitemap.xml", "sitemap"))
        if len(found) >= limit:
            break
    return found


def classify_response(status: int, length: int, content_type: str) -> str | None:
    """What a response to a path probe means, or None if it means nothing.

    A 404 is the common case and carries no information. A 401/403 is reported
    because it confirms the path exists but is protected.
    """
    if status == 200 and length > 0:
        return "accessible"
    if status in (401, 403):
        return "protected"
    if status in (301, 302, 307, 308):
        return "redirected"
    if status == 500:
        return "server-error"
    return None
