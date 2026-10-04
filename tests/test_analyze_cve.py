"""Tests for offline CVE correlation.

The CVE ids, scores and descriptions in this file are **synthetic fixtures**:
CVE-2099-* ids that cannot exist, written into tmp_path so each test loads a feed
it fully controls. netrecon itself ships no CVE data and makes no requests, so
these fixtures are the only CVE data anywhere in the test suite - and they never
reach a report.

The behaviour that matters here is conservatism: boundaries respected, a
constraint-free ``*`` CPE ignored rather than matched, a broken entry skipped
rather than fatal, and every finding labelled as unverified correlation.
"""

from __future__ import annotations

import json

import pytest

from netrecon.analyze.cve import (
    CveFeed,
    CveMatch,
    MissingFeed,
    compare_versions,
    correlate,
    feed_help,
    finding_severity,
    findings_from_matches,
    load_feed,
    severity_band,
    summarise,
    version_key,
)
from netrecon.analyze.techstack import Technology, build_cpe

NGINX_CPE = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"


def tech(name: str = "nginx", version: str | None = "1.18.0") -> Technology:
    return Technology(
        name=name,
        version=version,
        categories=("web-server",),
        confidence="certain",
        source="nmap-sV",
        evidence=f"{name} {version}",
        cpe=build_cpe(None, name, version),
    )


def write_feed(tmp_path, name: str, payload: dict) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


# -- fixtures in each supported format -----------------------------------


def netrecon_feed(tmp_path) -> str:
    return write_feed(
        tmp_path,
        "netrecon-feed.json",
        {
            "entries": [
                {
                    "cve": "CVE-2099-0001",
                    "cpe": NGINX_CPE,
                    "version_start_including": "1.16.0",
                    "version_end_excluding": "1.20.1",
                    "cvss": 7.5,
                    "severity": "high",
                    "summary": "Synthetic range entry for tests.",
                    "published": "2099-01-01T00:00Z",
                },
                {
                    "cve": "CVE-2099-0002",
                    "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                    "cvss": 9.8,
                    "summary": "Synthetic exact-version entry.",
                },
                {
                    "cve": "CVE-2099-0003",
                    "cpe": NGINX_CPE,
                    "cvss": 5.0,
                    "summary": "No constraint at all - must never match.",
                },
            ]
        },
    )


def nvd_20_feed(tmp_path) -> str:
    return write_feed(
        tmp_path,
        "nvd-2.0.json",
        {
            "resultsPerPage": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-1001",
                        "published": "2099-02-03T00:00:00.000",
                        "descriptions": [
                            {"lang": "es", "value": "entrada sintetica"},
                            {"lang": "en", "value": "Synthetic NVD 2.0 entry."},
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "operator": "OR",
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": NGINX_CPE,
                                                "versionStartIncluding": "1.17.0",
                                                "versionEndIncluding": "1.18.0",
                                            },
                                            {
                                                "vulnerable": False,
                                                "criteria": (
                                                    "cpe:2.3:a:nginx:nginx:1.19.0:*:*:*:*:*:*:*"
                                                ),
                                            },
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2099-1002",
                        "descriptions": [{"lang": "en", "value": "Nested configuration entry."}],
                        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.3}}]},
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "operator": "AND",
                                        "cpeMatch": [],
                                        "children": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "vulnerable": True,
                                                        "criteria": (
                                                            "cpe:2.3:a:jquery:jquery:3.6.0"
                                                            ":*:*:*:*:*:*:*"
                                                        ),
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                },
                {"not": "a vulnerability record"},
            ],
        },
    )


def nvd_11_feed(tmp_path) -> str:
    return write_feed(
        tmp_path,
        "nvd-1.1.json",
        {
            "CVE_data_type": "CVE",
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2099-2001"},
                        "description": {
                            "description_data": [{"lang": "en", "value": "Synthetic 1.1 entry."}]
                        },
                    },
                    "configurations": {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpe_match": [
                                    {
                                        "vulnerable": True,
                                        "cpe23Uri": NGINX_CPE,
                                        "versionEndExcluding": "1.20.0",
                                    }
                                ],
                            }
                        ]
                    },
                    "impact": {
                        "baseMetricV3": {"cvssV3": {"baseScore": 8.2, "baseSeverity": "HIGH"}}
                    },
                    "publishedDate": "2099-03-04T00:00Z",
                },
                {"cve": {"CVE_data_meta": {}}, "configurations": {}},
            ],
        },
    )


# -- loading -------------------------------------------------------------


def test_netrecon_format_loads(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert feed.feed_format == "netrecon"
    assert len(feed) == 3
    assert feed.products == ("nginx",)


def test_nvd_20_format_loads(tmp_path):
    feed = CveFeed.load(nvd_20_feed(tmp_path))
    assert feed.feed_format == "nvd-2.0"
    # The non-vulnerable cpeMatch is dropped; the nested child node is kept.
    assert len(feed) == 2
    assert set(feed.products) == {"nginx", "jquery"}
    assert feed.skipped == 1


def test_nvd_11_format_loads(tmp_path):
    feed = CveFeed.load(nvd_11_feed(tmp_path))
    assert feed.feed_format == "nvd-1.1"
    assert len(feed) == 1
    entry = feed.entries[0]
    assert entry.cve_id == "CVE-2099-2001"
    assert entry.cvss_score == 8.2
    assert entry.cvss_severity == "high"
    assert entry.version_end_excluding == "1.20.0"


def test_entries_are_indexed_by_vendor_and_product(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert len(feed.entries_for("nginx", "nginx")) == 3
    assert feed.entries_for("apache", "http_server") == ()


def test_missing_feed_file_raises(tmp_path):
    with pytest.raises(MissingFeed) as excinfo:
        CveFeed.load(tmp_path / "does-not-exist.json")
    assert "not found" in str(excinfo.value)


def test_corrupt_feed_file_raises_missing_feed(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json at all", encoding="utf-8")
    with pytest.raises(MissingFeed):
        CveFeed.load(path)


def test_unrecognised_feed_shape_raises_missing_feed(tmp_path):
    path = write_feed(tmp_path, "weird.json", {"something": "else"})
    with pytest.raises(MissingFeed):
        CveFeed.load(path)


def test_malformed_entries_are_skipped_not_fatal(tmp_path):
    path = write_feed(
        tmp_path,
        "mixed.json",
        {
            "entries": [
                {"cve": "not-a-cve-id", "cpe": NGINX_CPE, "version_end_excluding": "2.0"},
                {"cve": "CVE-2099-0009", "cpe": "garbage", "cvss": 1.0},
                ["not", "an", "object"],
                {
                    "cve": "CVE-2099-0010",
                    "cpe": NGINX_CPE,
                    "version_end_excluding": "1.20.0",
                    "cvss": 6.1,
                },
            ]
        },
    )
    feed = CveFeed.load(path)
    assert len(feed) == 1
    assert feed.skipped == 3
    assert len(feed.warnings) == 3
    assert [m.cve_id for m in feed.match(tech())] == ["CVE-2099-0010"]


def test_no_feed_configured_is_not_an_error():
    assert load_feed(None) is None
    assert load_feed("   ") is None
    assert correlate([tech()], None) == []


def test_feed_help_points_at_a_local_file_and_no_lookup():
    text = feed_help()
    assert "nvd.nist.gov" in text
    assert "local path" in text
    assert "never contacts" in text


# -- version handling ----------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2.3", "1.2.3", 0),
        ("1.2", "1.2.0", 0),
        ("1.2.3", "1.2.4", -1),
        ("1.10.0", "1.9.0", 1),
        ("8.9p1", "8.9", 1),
        ("8.9p1", "8.9p2", -1),
        ("1.18.0-ubuntu", "1.18.0", 1),
        ("1.18.0-ubuntu", "1.19.0", -1),
        ("1.0-beta", "1.0", -1),
        ("2.4.41-4ubuntu3", "2.4.41", 1),
    ],
)
def test_compare_versions(left, right, expected):
    assert compare_versions(left, right) == expected


def test_version_key_of_nothing_is_empty():
    assert version_key(None) == ()
    assert version_key("unknown") != ()


def test_start_including_boundary_is_inclusive(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert "CVE-2099-0001" in {m.cve_id for m in feed.match(tech(version="1.16.0"))}
    assert "CVE-2099-0001" not in {m.cve_id for m in feed.match(tech(version="1.15.12"))}


def test_end_excluding_boundary_is_exclusive(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert "CVE-2099-0001" in {m.cve_id for m in feed.match(tech(version="1.20.0"))}
    assert "CVE-2099-0001" not in {m.cve_id for m in feed.match(tech(version="1.20.1"))}


def test_end_including_boundary_is_inclusive(tmp_path):
    feed = CveFeed.load(nvd_20_feed(tmp_path))
    assert [m.cve_id for m in feed.match(tech(version="1.18.0"))] == ["CVE-2099-1001"]
    assert feed.match(tech(version="1.18.1")) == []


def test_start_excluding_boundary_is_exclusive(tmp_path):
    path = write_feed(
        tmp_path,
        "start-excluding.json",
        {
            "entries": [
                {
                    "cve": "CVE-2099-3001",
                    "cpe": NGINX_CPE,
                    "versionStartExcluding": "1.18.0",
                    "versionEndIncluding": "1.20.0",
                    "cvss": 7.0,
                }
            ]
        },
    )
    feed = CveFeed.load(path)
    assert feed.match(tech(version="1.18.0")) == []
    assert len(feed.match(tech(version="1.18.1"))) == 1


def test_exact_version_cpe_matches_only_that_version(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert "CVE-2099-0002" in {m.cve_id for m in feed.match(tech(version="1.18.0"))}
    assert "CVE-2099-0002" not in {m.cve_id for m in feed.match(tech(version="1.19.0"))}


def test_star_version_with_no_range_never_matches(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    matched = {m.cve_id for m in feed.match(tech(version="1.18.0"))}
    assert "CVE-2099-0003" not in matched


def test_unknown_version_never_matches_a_range(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert feed.match(tech(version=None)) == []


def test_a_different_product_does_not_match(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    assert feed.match(tech(name="Apache httpd", version="1.18.0")) == []


def test_display_name_is_mapped_onto_the_feed_product(tmp_path):
    feed = CveFeed.load(nvd_20_feed(tmp_path))
    matched = feed.match(tech(name="jQuery", version="3.6.0"))
    assert [m.cve_id for m in matched] == ["CVE-2099-1002"]
    assert matched[0].technology == "jQuery"
    assert matched[0].source.endswith("nvd-2.0.json")


# -- correlation and reporting -------------------------------------------


def test_correlate_sorts_by_cvss_then_id(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    matches = correlate([tech(version="1.18.0")], feed)
    assert [m.cve_id for m in matches] == ["CVE-2099-0002", "CVE-2099-0001"]
    assert [m.cvss_score for m in matches] == [9.8, 7.5]
    assert matches[0].cvss_severity == "critical"
    assert matches[0].version == "1.18.0"


def test_correlate_across_two_technologies(tmp_path):
    feed = CveFeed.load(nvd_20_feed(tmp_path))
    matches = correlate([tech(version="1.18.0"), tech(name="jQuery", version="3.6.0")], feed)
    assert [m.cve_id for m in matches] == ["CVE-2099-1001", "CVE-2099-1002"]


def test_summarise_counts_and_highest_score(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    summary = summarise(correlate([tech()], feed))
    assert summary["total"] == 2
    assert summary["by_severity"] == {"critical": 1, "high": 1}
    assert summary["highest_score"] == 9.8
    assert summary["highest_severity"] == "critical"
    assert summary["correlation_only"] is True


def test_summarise_of_nothing():
    assert summarise([]) == {
        "total": 0,
        "by_severity": {},
        "highest_score": None,
        "highest_severity": None,
        "correlation_only": True,
    }


@pytest.mark.parametrize(
    ("score", "expected"),
    [(9.8, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"),
     (4.0, "medium"), (3.9, "low"), (0.0, "low"), (None, "low")],
)
def test_finding_severity_mapping(score, expected):
    assert finding_severity(score) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [(9.8, "critical"), (7.5, "high"), (5.0, "medium"), (0.5, "low"), (0.0, "none"), (None, None)],
)
def test_severity_band(score, expected):
    assert severity_band(score) == expected


def test_findings_are_labelled_as_unverified_correlation(tmp_path):
    feed = CveFeed.load(netrecon_feed(tmp_path))
    subject = tech(version="1.18.0")
    findings = findings_from_matches(correlate([subject], feed), subject)
    assert [f.key for f in findings] == ["cve.known-vulnerability"] * 2
    assert [f.severity for f in findings] == ["critical", "high"]

    top = findings[0]
    assert "correlation only" in top.summary.lower()
    assert "did not test this host" in top.summary
    assert "cannot say it is vulnerable" in top.summary
    assert "confirm the exact build and patch level" in top.recommendation.lower()
    assert top.source.endswith("netrecon-feed.json")
    assert top.data["cve_id"] == "CVE-2099-0002"
    assert top.data["verified"] is False
    assert "CVE-2099-0002" in top.evidence


def test_findings_can_be_filtered_to_one_technology(tmp_path):
    feed = CveFeed.load(nvd_20_feed(tmp_path))
    matches = correlate([tech(version="1.18.0"), tech(name="jQuery", version="3.6.0")], feed)
    only_jquery = findings_from_matches(matches, "jQuery")
    assert [f.data["cve_id"] for f in only_jquery] == ["CVE-2099-1002"]
    assert len(findings_from_matches(matches)) == 2


def test_findings_from_nothing_is_empty():
    assert findings_from_matches([], tech()) == []


def test_match_to_dict_is_json_ready():
    match = CveMatch(
        cve_id="CVE-2099-0001",
        cvss_score=7.5,
        cvss_severity="high",
        published="2099-01-01",
        summary="Synthetic.",
        matched_cpe=NGINX_CPE,
        technology="nginx",
        version="1.18.0",
        source="/tmp/feed.json",
    )
    assert json.loads(json.dumps(match.to_dict()))["cve_id"] == "CVE-2099-0001"
    assert match.to_dict()["verified"] is False


def test_lookup_is_indexed_so_a_large_feed_stays_cheap(tmp_path):
    """A feed of many products must not be scanned per technology."""
    entries = [
        {
            "cve": f"CVE-2099-{4000 + index}",
            "cpe": f"cpe:2.3:a:vendor{index}:product{index}:*:*:*:*:*:*:*:*",
            "version_end_excluding": "9.9",
            "cvss": 5.0,
        }
        for index in range(2000)
    ]
    entries.append(
        {
            "cve": "CVE-2099-9999",
            "cpe": NGINX_CPE,
            "version_end_excluding": "1.20.0",
            "cvss": 7.5,
        }
    )
    feed = CveFeed.load(write_feed(tmp_path, "big.json", {"entries": entries}))
    assert len(feed) == 2001
    # One product bucket is consulted, not 2001 entries.
    assert len(feed.entries_for("nginx", "nginx")) == 1
    assert [m.cve_id for m in feed.match(tech())] == ["CVE-2099-9999"]
