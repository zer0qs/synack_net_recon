"""Offline correlation of detected versions against an operator-supplied CVE feed.

Why this module is shaped the way it is:

* **It invents nothing.** Every CVE id, score, date and description comes out of
  a feed file the operator put on disk. A fabricated CVE in a penetration-test
  report is worse than no CVE at all, so there is no built-in vulnerability
  table here and nothing to fall back on when a feed is absent.
* **It makes no requests.** Reading the feed file is the only I/O in the whole
  :mod:`netrecon.analyze` package. netrecon does not download feeds, query an
  API, or phone a vulnerability service; see :func:`feed_help`.
* **It never claims exploitability.** A match means "the version string this host
  advertised falls inside a range the feed records for this CVE". Distributions
  backport fixes without touching banners, products get patched in place, and a
  CPE range is a coarse instrument. Every finding this module emits says so in
  its summary and tells the reader to confirm the build.
* **Not configured is not an error.** With no feed, correlation is skipped. That
  is the default and the quiet path.

A feed with a few hundred thousand entries must stay usable, so entries are
indexed by the ``(vendor, product)`` pair taken from their CPE at load time and
looked up by product, never scanned.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netrecon.analyze import techstack
from netrecon.analyze.base import Finding
from netrecon.analyze.techstack import Technology

_LOG = logging.getLogger(__name__)

#: Stop one broken feed from filling the log and the checkpoint.
MAX_REPORTED_WARNINGS = 50

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: NVD severity bands, used only when the feed gives a score but no label.
_SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)

SEVERITY_NAMES: tuple[str, ...] = ("critical", "high", "medium", "low", "none", "unknown")


class MissingFeed(Exception):
    """No usable CVE feed: absent, unreadable, or not a feed netrecon knows."""


def feed_help() -> str:
    """How an operator gets a feed. netrecon never fetches one itself."""
    return (
        "netrecon does no vulnerability lookups of its own: it correlates only "
        "against a feed file you place on disk, and it never contacts a CVE "
        "service. Obtain an NVD JSON feed (schema 1.1 or 2.0) from "
        "nvd.nist.gov yourself, or hand-write a netrecon feed "
        '({"entries": [{"cve": ..., "cpe": ..., "cvss": ..., "summary": ...}]}), '
        "then point netrecon at that local path. With no feed configured, "
        "correlation is skipped and nothing is reported."
    )


# -- version comparison --------------------------------------------------

#: Words that mark a pre-release, which sorts *below* the plain version.
_PRERELEASE: dict[str, int] = {
    "dev": -6,
    "snapshot": -5,
    "alpha": -4,
    "a": -4,
    "beta": -3,
    "b": -3,
    "milestone": -3,
    "m": -3,
    "rc": -2,
    "pre": -2,
    "preview": -2,
}

#: Padding element for comparing versions of unequal length: ``1.18`` and
#: ``1.18.0`` must compare equal, while ``1.18.0-ubuntu`` must compare greater.
_NEUTRAL: tuple[int, int, str] = (1, 0, "")


def version_key(text: str | None) -> tuple[tuple[int, int, str], ...]:
    """Split a version into comparable tokens.

    Handles the shapes that actually turn up in banners and feeds: ``1.2.3``,
    ``1.2``, ``8.9p1``, ``1.18.0-ubuntu``, ``2.4.41-4ubuntu3``, ``1.0-beta2``.
    Numeric runs compare numerically; a trailing word such as ``p1`` or
    ``ubuntu`` sorts above a bare number (it is a later build), while a
    pre-release word sorts below it.
    """
    if text is None:
        return ()
    tokens: list[tuple[int, int, str]] = []
    for chunk in re.findall(r"\d+|[A-Za-z]+", str(text).strip().lower()):
        if chunk.isdigit():
            tokens.append((1, int(chunk), ""))
        elif chunk in _PRERELEASE:
            tokens.append((0, _PRERELEASE[chunk], chunk))
        else:
            tokens.append((2, 0, chunk))
    return tuple(tokens)


def compare_versions(left: str | None, right: str | None) -> int:
    """-1, 0 or 1. Unknown components are padded, so ``1.18 == 1.18.0``."""
    a = version_key(left)
    b = version_key(right)
    length = max(len(a), len(b))
    a += (_NEUTRAL,) * (length - len(a))
    b += (_NEUTRAL,) * (length - len(b))
    return (a > b) - (a < b)


def severity_band(score: float | None) -> str | None:
    """NVD-style label for a score, or None when there is no score."""
    if score is None:
        return None
    if score <= 0:
        return "none"
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def finding_severity(score: float | None) -> str:
    """Map a CVSS base score onto a netrecon finding severity.

    An unscored match stays "low": netrecon will not promote something the feed
    could not even rate.
    """
    if score is None:
        return "low"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# -- records -------------------------------------------------------------


@dataclass(frozen=True)
class CveMatch:
    """One feed entry whose affected range covers one detected version."""

    cve_id: str
    cvss_score: float | None
    #: critical / high / medium / low / none, as the feed reported or implied it.
    cvss_severity: str | None
    published: str | None
    summary: str
    #: The feed's CPE the detected technology was matched against.
    matched_cpe: str
    technology: str
    version: str | None
    #: The feed file this came from. Never a URL: netrecon fetches nothing.
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "published": self.published,
            "summary": self.summary,
            "matched_cpe": self.matched_cpe,
            "technology": self.technology,
            "version": self.version,
            "source": self.source,
            "verified": False,
        }


@dataclass(frozen=True)
class FeedEntry:
    """One ``(CVE, affected CPE range)`` pair, normalised out of any feed format."""

    cve_id: str
    cpe: str
    vendor: str
    product: str
    #: The CPE's own version component; "*" when the entry uses a range instead.
    cpe_version: str = "*"
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    published: str | None = None
    summary: str = ""

    @property
    def has_range(self) -> bool:
        return any(
            bound is not None
            for bound in (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        )

    def covers(self, version: str | None) -> bool:
        """Whether *version* falls in this entry's affected range.

        A version netrecon does not know never matches, and neither does an
        entry with no constraint at all (a bare ``*`` CPE): "every version of
        nginx ever" is not a finding, it is noise that would bury the real ones.
        """
        if self.has_range:
            if not version:
                return False
            if self.version_start_including is not None:
                if compare_versions(version, self.version_start_including) < 0:
                    return False
            if self.version_start_excluding is not None:
                if compare_versions(version, self.version_start_excluding) <= 0:
                    return False
            if self.version_end_including is not None:
                if compare_versions(version, self.version_end_including) > 0:
                    return False
            if self.version_end_excluding is not None:
                if compare_versions(version, self.version_end_excluding) >= 0:
                    return False
            return True

        if self.cpe_version in {"*", "-", ""} or not version:
            return False
        return compare_versions(version, self.cpe_version) == 0


# -- feed loading --------------------------------------------------------


def _product_token(value: str | None) -> str:
    """Normalise a product/vendor word for indexing and lookup."""
    if not value:
        return ""
    text = re.sub(r"\\(.)", r"\1", str(value)).strip().lower()
    return re.sub(r"[\s\-]+", "_", text)


def _first(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _as_score(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= score <= 10.0:
        return None
    return round(score, 1)


def _as_text(value: Any, limit: int = 1200) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit]


def _english(descriptions: Any) -> str:
    """Pick the English description out of an NVD description list."""
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
                return _as_text(item.get("value"))
        for item in descriptions:
            if isinstance(item, dict) and item.get("value"):
                return _as_text(item.get("value"))
    return _as_text(descriptions if isinstance(descriptions, str) else None)


def _metrics_20(metrics: Any) -> tuple[float | None, str | None]:
    """Best available CVSS from an NVD 2.0 ``metrics`` object."""
    if not isinstance(metrics, dict):
        return (None, None)
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData") if isinstance(entry.get("cvssData"), dict) else {}
            score = _as_score(data.get("baseScore"))
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            if score is not None:
                label = str(severity).lower() if severity else severity_band(score)
                return (score, label)
    return (None, None)


def _metrics_11(impact: Any) -> tuple[float | None, str | None]:
    """Best available CVSS from an NVD 1.1 ``impact`` object."""
    if not isinstance(impact, dict):
        return (None, None)
    v3 = impact.get("baseMetricV3")
    if isinstance(v3, dict):
        data = v3.get("cvssV3") if isinstance(v3.get("cvssV3"), dict) else {}
        score = _as_score(data.get("baseScore"))
        if score is not None:
            severity = data.get("baseSeverity")
            return (score, str(severity).lower() if severity else severity_band(score))
    v2 = impact.get("baseMetricV2")
    if isinstance(v2, dict):
        data = v2.get("cvssV2") if isinstance(v2.get("cvssV2"), dict) else {}
        score = _as_score(data.get("baseScore"))
        if score is not None:
            severity = v2.get("severity")
            return (score, str(severity).lower() if severity else severity_band(score))
    return (None, None)


def _iter_nodes(nodes: Any) -> list[dict[str, Any]]:
    """Flatten an NVD configuration node tree."""
    flat: list[dict[str, Any]] = []
    stack = list(nodes) if isinstance(nodes, list) else []
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        flat.append(node)
        children = node.get("children")
        if isinstance(children, list):
            stack.extend(children)
    return flat


def _entry_from_cpe_match(
    cve_id: str,
    match: Any,
    *,
    score: float | None,
    severity: str | None,
    published: str | None,
    summary: str,
) -> FeedEntry | None:
    if not isinstance(match, dict):
        return None
    if match.get("vulnerable") is False:
        return None
    criteria = _first(match, "criteria", "cpe23Uri", "cpe23uri", "cpe", "cpeMatchString")
    cpe = techstack.normalise_cpe(str(criteria)) if criteria else None
    if not cpe:
        return None
    part, vendor, product, version = techstack.cpe_fields(cpe)
    product_token = _product_token(product)
    if not product_token or product_token == "*":  # noqa: S105 - CPE product, not a secret
        return None
    return FeedEntry(
        cve_id=cve_id,
        cpe=cpe,
        vendor=_product_token(vendor),
        product=product_token,
        cpe_version=re.sub(r"\\(.)", r"\1", version or "*"),
        version_start_including=_version_bound(match, "versionStartIncluding"),
        version_start_excluding=_version_bound(match, "versionStartExcluding"),
        version_end_including=_version_bound(match, "versionEndIncluding"),
        version_end_excluding=_version_bound(match, "versionEndExcluding"),
        cvss_score=score,
        cvss_severity=severity or severity_band(score),
        published=published,
        summary=summary,
    )


def _version_bound(data: dict[str, Any], camel: str) -> str | None:
    """Read a version bound written either camelCase or snake_case."""
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", camel).lower()
    value = _first(data, camel, snake)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_nvd_20(items: list[Any], warnings: list[str]) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    for index, item in enumerate(items):
        try:
            cve = item.get("cve") if isinstance(item, dict) else None
            if not isinstance(cve, dict):
                raise ValueError("no 'cve' object")
            cve_id = _cve_id(cve.get("id"))
            score, severity = _metrics_20(cve.get("metrics"))
            summary = _english(cve.get("descriptions"))
            published = _as_text(cve.get("published"), 64) or None
            configurations = cve.get("configurations")
            if not isinstance(configurations, list):
                configurations = []
            for configuration in configurations:
                if not isinstance(configuration, dict):
                    continue
                for node in _iter_nodes(configuration.get("nodes")):
                    for cpe_match in node.get("cpeMatch") or []:
                        entry = _entry_from_cpe_match(
                            cve_id,
                            cpe_match,
                            score=score,
                            severity=severity,
                            published=published,
                            summary=summary,
                        )
                        if entry:
                            entries.append(entry)
        except Exception as exc:  # noqa: BLE001 - one bad record must not kill the feed
            warnings.append(f"NVD 2.0 record #{index}: {exc}")
    return entries


def _parse_nvd_11(items: list[Any], warnings: list[str]) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    for index, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise ValueError("record is not an object")
            cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
            meta = cve.get("CVE_data_meta") if isinstance(cve.get("CVE_data_meta"), dict) else {}
            cve_id = _cve_id(meta.get("ID") or item.get("id"))
            score, severity = _metrics_11(item.get("impact"))
            description = cve.get("description") if isinstance(cve.get("description"), dict) else {}
            summary = _english(description.get("description_data"))
            published = _as_text(item.get("publishedDate"), 64) or None
            configurations = item.get("configurations")
            nodes = configurations.get("nodes") if isinstance(configurations, dict) else None
            for node in _iter_nodes(nodes):
                for cpe_match in node.get("cpe_match") or node.get("cpeMatch") or []:
                    entry = _entry_from_cpe_match(
                        cve_id,
                        cpe_match,
                        score=score,
                        severity=severity,
                        published=published,
                        summary=summary,
                    )
                    if entry:
                        entries.append(entry)
        except Exception as exc:  # noqa: BLE001 - see _parse_nvd_20
            warnings.append(f"NVD 1.1 record #{index}: {exc}")
    return entries


def _parse_netrecon(items: list[Any], warnings: list[str]) -> list[FeedEntry]:
    """The hand-writable format: one flat entry per CVE/CPE pair."""
    entries: list[FeedEntry] = []
    for index, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise ValueError("entry is not an object")
            cve_id = _cve_id(_first(item, "cve", "cve_id", "id"))
            criteria = _first(item, "cpe", "cpe23Uri", "criteria")
            cpe = techstack.normalise_cpe(str(criteria)) if criteria else None
            if not cpe:
                raise ValueError(f"unusable cpe {criteria!r}")
            _part, vendor, product, version = techstack.cpe_fields(cpe)
            product_token = _product_token(product)
            if not product_token or product_token == "*":  # noqa: S105 - CPE product, not a secret
                raise ValueError(f"cpe names no product: {criteria!r}")
            score = _as_score(_first(item, "cvss", "cvss_score", "score", "baseScore"))
            severity = _first(item, "severity", "cvss_severity")
            entries.append(
                FeedEntry(
                    cve_id=cve_id,
                    cpe=cpe,
                    vendor=_product_token(vendor),
                    product=product_token,
                    cpe_version=re.sub(r"\\(.)", r"\1", version or "*"),
                    version_start_including=_version_bound(item, "versionStartIncluding"),
                    version_start_excluding=_version_bound(item, "versionStartExcluding"),
                    version_end_including=_version_bound(item, "versionEndIncluding"),
                    version_end_excluding=_version_bound(item, "versionEndExcluding"),
                    cvss_score=score,
                    cvss_severity=(str(severity).lower() if severity else severity_band(score)),
                    published=_as_text(_first(item, "published", "published_date"), 64) or None,
                    summary=_as_text(_first(item, "summary", "description")),
                )
            )
        except Exception as exc:  # noqa: BLE001 - see _parse_nvd_20
            warnings.append(f"netrecon entry #{index}: {exc}")
    return entries


def _cve_id(value: Any) -> str:
    text = _as_text(value, 32).upper()
    if not _CVE_ID.match(text):
        raise ValueError(f"not a CVE id: {value!r}")
    return text


class CveFeed:
    """An indexed, read-only view of one local CVE feed file."""

    def __init__(
        self,
        entries: list[FeedEntry] | tuple[FeedEntry, ...],
        *,
        source: str,
        feed_format: str = "unknown",
        warnings: list[str] | None = None,
        skipped: int = 0,
    ) -> None:
        self.source = source
        self.feed_format = feed_format
        self.warnings: list[str] = list(warnings or [])
        self.skipped = skipped
        self._entries: tuple[FeedEntry, ...] = tuple(entries)

        # Indexed on load so a 200k-entry feed is a dict lookup per technology,
        # never a scan. The (vendor, product) index is what the CPE actually
        # keys on; the product index is the lookup path, because feeds and
        # banners disagree about vendors far more often than about products
        # (nginx ships as "igor_sysoev", "nginx" and "f5" across feeds).
        self._by_key: dict[tuple[str, str], list[FeedEntry]] = {}
        self._by_product: dict[str, list[FeedEntry]] = {}
        for entry in self._entries:
            self._by_key.setdefault((entry.vendor, entry.product), []).append(entry)
            self._by_product.setdefault(entry.product, []).append(entry)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"CveFeed({self.feed_format}, {len(self._entries)} entries, {self.source})"

    @property
    def entries(self) -> tuple[FeedEntry, ...]:
        return self._entries

    @property
    def products(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_product))

    def entries_for(self, vendor: str | None, product: str | None) -> tuple[FeedEntry, ...]:
        """Entries for one exact ``(vendor, product)`` CPE pair."""
        key = (_product_token(vendor), _product_token(product))
        return tuple(self._by_key.get(key, ()))

    @classmethod
    def load(cls, path: str | Path) -> CveFeed:
        """Read and index a local feed file. The only I/O in this package."""
        feed_path = Path(path)
        if not feed_path.is_file():
            raise MissingFeed(f"CVE feed not found: {feed_path}. {feed_help()}")
        try:
            raw = feed_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise MissingFeed(f"CVE feed {feed_path} could not be read: {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MissingFeed(f"CVE feed {feed_path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise MissingFeed(
                f"CVE feed {feed_path} must be a JSON object with "
                "'vulnerabilities', 'CVE_Items' or 'entries'."
            )

        warnings: list[str] = []
        if isinstance(data.get("vulnerabilities"), list):
            feed_format = "nvd-2.0"
            entries = _parse_nvd_20(data["vulnerabilities"], warnings)
        elif isinstance(data.get("CVE_Items"), list):
            feed_format = "nvd-1.1"
            entries = _parse_nvd_11(data["CVE_Items"], warnings)
        elif isinstance(data.get("entries"), list):
            feed_format = "netrecon"
            entries = _parse_netrecon(data["entries"], warnings)
        else:
            raise MissingFeed(
                f"CVE feed {feed_path} is not a shape netrecon understands "
                "(expected NVD JSON 2.0 'vulnerabilities', NVD JSON 1.1 "
                "'CVE_Items', or netrecon 'entries')."
            )

        skipped = len(warnings)
        if skipped > MAX_REPORTED_WARNINGS:
            warnings = warnings[:MAX_REPORTED_WARNINGS]
            warnings.append(f"... and {skipped - MAX_REPORTED_WARNINGS} further malformed entries")
        if skipped:
            _LOG.warning(
                "CVE feed %s: skipped %d malformed entry/entries; first: %s",
                feed_path,
                skipped,
                warnings[0],
            )

        return cls(
            entries,
            source=str(feed_path),
            feed_format=feed_format,
            warnings=warnings,
            skipped=skipped,
        )

    # -- matching --------------------------------------------------------

    def match(self, tech: Technology) -> list[CveMatch]:
        """Feed entries whose affected range covers *tech*'s detected version."""
        if tech is None or not getattr(tech, "name", None):
            return []
        version = (tech.version or "").strip() or None
        matches: list[CveMatch] = []
        seen: set[tuple[str, str]] = set()
        for product in _tech_products(tech):
            for entry in self._by_product.get(product, ()):
                identity = (entry.cve_id, entry.cpe)
                if identity in seen or not entry.covers(version):
                    continue
                seen.add(identity)
                matches.append(
                    CveMatch(
                        cve_id=entry.cve_id,
                        cvss_score=entry.cvss_score,
                        cvss_severity=entry.cvss_severity or severity_band(entry.cvss_score),
                        published=entry.published,
                        summary=entry.summary,
                        matched_cpe=entry.cpe,
                        technology=tech.name,
                        version=version,
                        source=self.source,
                    )
                )
        return sort_matches(matches)


def _tech_products(tech: Technology) -> list[str]:
    """CPE product tokens worth looking up for one technology."""
    tokens: list[str] = []

    def add(value: str | None) -> None:
        token = _product_token(value)
        if token and token not in tokens:
            tokens.append(token)

    if tech.cpe:
        _part, _vendor, product, _version = techstack.cpe_fields(tech.cpe)
        add(product)
    # The table knows that "Apache httpd" is CPE product "http_server".
    built = techstack.build_cpe(None, tech.name, None)
    if built:
        _part, _vendor, product, _version = techstack.cpe_fields(built)
        add(product)
    add(tech.name)
    # Feeds drop the ".js" that display names keep ("Moment.js" -> "moment").
    stripped = re.sub(r"\.js$", "", tech.name.strip(), flags=re.IGNORECASE)
    if stripped and stripped.lower() != tech.name.strip().lower():
        add(stripped)
    return tokens


def load_feed(path: str | Path | None) -> CveFeed | None:
    """Load a feed when one is configured; None when none is. Never an error."""
    if path is None or not str(path).strip():
        return None
    return CveFeed.load(path)


def sort_matches(matches: list[CveMatch]) -> list[CveMatch]:
    """Highest CVSS first, then by CVE id; unscored matches last."""
    return sorted(
        matches,
        key=lambda m: (
            0 if m.cvss_score is not None else 1,
            -(m.cvss_score or 0.0),
            m.cve_id,
            m.technology.lower(),
        ),
    )


def correlate(technologies: list[Technology], feed: CveFeed | None) -> list[CveMatch]:
    """Match every detected technology against the feed. No feed, no matches."""
    if feed is None:
        return []
    matches: list[CveMatch] = []
    seen: set[tuple[str, str, str]] = set()
    for tech in technologies or []:
        for match in feed.match(tech):
            identity = (match.cve_id, match.technology.lower(), match.matched_cpe)
            if identity in seen:
                continue
            seen.add(identity)
            matches.append(match)
    return sort_matches(matches)


def summarise(matches: list[CveMatch]) -> dict[str, Any]:
    """Counts by severity, the highest score seen, and the total."""
    counts = {name: 0 for name in SEVERITY_NAMES}
    highest: float | None = None
    for match in matches or []:
        label = (match.cvss_severity or severity_band(match.cvss_score) or "unknown").lower()
        counts[label if label in counts else "unknown"] += 1
        if match.cvss_score is not None and (highest is None or match.cvss_score > highest):
            highest = match.cvss_score
    return {
        "total": len(matches or []),
        "by_severity": {name: count for name, count in counts.items() if count},
        "highest_score": highest,
        "highest_severity": severity_band(highest),
        "correlation_only": True,
    }


def findings_from_matches(
    matches: list[CveMatch], technology: Technology | str | None = None
) -> list[Finding]:
    """Turn feed matches into findings that cannot be mistaken for verified bugs.

    When *technology* is given, only matches against that technology are used,
    so a caller holding one service's stack can emit findings per technology.
    """
    if isinstance(technology, Technology):
        wanted = technology.name
        subject = technology.label
    elif technology:
        wanted = str(technology)
        subject = str(technology)
    else:
        wanted = None
        subject = None

    findings: list[Finding] = []
    for match in sort_matches(matches or []):
        if wanted and match.technology.strip().lower() != wanted.strip().lower():
            continue
        observed = subject or (
            f"{match.technology} {match.version}" if match.version else match.technology
        )
        score_text = (
            f"CVSS {match.cvss_score} ({match.cvss_severity})"
            if match.cvss_score is not None
            else "no CVSS score in the feed"
        )
        findings.append(
            Finding(
                key="cve.known-vulnerability",
                title=f"{match.cve_id} is recorded against {observed}",
                severity=finding_severity(match.cvss_score),
                summary=(
                    f"Version-to-CVE correlation only: the version netrecon observed "
                    f"({observed}) falls inside the affected range the local feed records "
                    f"for {match.cve_id} ({score_text}). netrecon did not test this host "
                    f"for the issue and cannot say it is vulnerable - backported vendor "
                    f"patches routinely leave the advertised version unchanged, and a CPE "
                    f"range is coarser than a build. Treat this as a lead to verify, not a "
                    f"confirmed exploitable condition."
                ),
                evidence=(
                    f"{match.cve_id} <- feed CPE {match.matched_cpe}; observed {observed}"
                    + (f". {match.summary}" if match.summary else "")
                ),
                recommendation=(
                    "Confirm the exact build and patch level on the host (package version, "
                    "vendor changelog, backported fixes) before reporting this, then "
                    "establish whether the affected component is reachable and exploitable "
                    "in this engagement's context."
                ),
                source=match.source,
                data=match.to_dict(),
            )
        )
    return findings
