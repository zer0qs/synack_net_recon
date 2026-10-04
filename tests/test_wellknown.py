"""Tests for the curated path list used by web recon.

The important property is a negative one: this list must stay a short, curated
set of commonly exposed files, not grow into a directory brute-force wordlist.
The size assertion below is deliberate - if someone pastes in a 10k wordlist,
this test fails and the conversation happens before the scan does.
"""

from __future__ import annotations

import pytest

from netrecon.core.config import HIDDEN_PATHS_HARD_MAX
from netrecon.stages.wellknown import (
    HIGH_VALUE_PREFIXES,
    WELL_KNOWN_PATHS,
    classify_response,
    curated_paths,
    paths_from_robots,
    paths_from_sitemap,
)

# -- the list itself -----------------------------------------------------


def test_the_curated_list_stays_curated():
    """A short list is a handful of 404s; a wordlist is a different activity."""
    assert len(WELL_KNOWN_PATHS) <= HIDDEN_PATHS_HARD_MAX


def test_every_entry_has_a_path_and_a_reason():
    for path, reason in WELL_KNOWN_PATHS:
        assert path.startswith("/"), path
        assert reason and len(reason) > 10, path


def test_paths_are_unique():
    paths = [path for path, _ in WELL_KNOWN_PATHS]
    assert len(paths) == len(set(paths))


def test_no_entry_carries_a_query_string_or_payload():
    """Every entry must be a plain GET of a file, with nothing appended."""
    for path, _ in WELL_KNOWN_PATHS:
        assert "?" not in path, path
        assert "&" not in path, path
        assert ";" not in path, path


def test_high_value_paths_are_flagged():
    candidates = {c.path: c for c in curated_paths(len(WELL_KNOWN_PATHS))}
    assert candidates["/.git/HEAD"].high_value is True
    assert candidates["/.env"].high_value is True
    assert candidates["/feed"].high_value is False


def test_curated_paths_respects_the_limit():
    assert len(curated_paths(10)) == 10
    assert curated_paths(0) == []


def test_the_limit_keeps_the_most_valuable_paths_first():
    """A reduced limit must still check the things most worth checking."""
    first_ten = {c.path for c in curated_paths(10)}
    assert any(p.startswith("/.git") for p in first_ten)


def test_high_value_prefixes_all_appear_in_the_list():
    paths = [path for path, _ in WELL_KNOWN_PATHS]
    for prefix in HIGH_VALUE_PREFIXES:
        assert any(p.startswith(prefix) for p in paths), prefix


def test_curated_candidates_are_marked_as_such():
    assert all(c.origin == "curated" for c in curated_paths(5))


# -- site-published paths ------------------------------------------------


def test_robots_disallow_entries_become_candidates():
    body = """
    User-agent: *
    Disallow: /admin
    Disallow: /api/internal
    Allow: /public
    """
    paths = {c.path for c in paths_from_robots(body)}
    assert paths == {"/admin", "/api/internal", "/public"}


def test_robots_candidates_are_marked_as_published_not_guessed():
    assert paths_from_robots("Disallow: /admin")[0].origin == "robots"


def test_robots_wildcards_are_skipped():
    assert paths_from_robots("Disallow: /tmp/*") == []


def test_robots_relative_entries_are_skipped():
    assert paths_from_robots("Disallow: admin") == []


def test_robots_handles_empty_and_malformed_input():
    assert paths_from_robots("") == []
    assert paths_from_robots("not a robots file at all") == []


def test_robots_deduplicates():
    assert len(paths_from_robots("Disallow: /a\nDisallow: /a\nDisallow: /a")) == 1


def test_robots_respects_its_limit():
    body = "\n".join(f"Disallow: /p{i}" for i in range(200))
    assert len(paths_from_robots(body, limit=5)) == 5


def test_sitemap_locations_become_candidates():
    body = """<?xml version="1.0"?><urlset>
      <url><loc>http://10.0.0.1:8080/about</loc></url>
      <url><loc>http://10.0.0.1:8080/pricing</loc></url>
    </urlset>"""
    paths = {c.path for c in paths_from_sitemap(body, "10.0.0.1:8080")}
    assert paths == {"/about", "/pricing"}


def test_sitemap_entries_for_other_hosts_are_dropped():
    """A sitemap can list any host; only this in-scope endpoint is authorised."""
    body = """<urlset>
      <url><loc>http://10.0.0.1:8080/mine</loc></url>
      <url><loc>https://someone-else.example.com/theirs</loc></url>
    </urlset>"""
    paths = {c.path for c in paths_from_sitemap(body, "10.0.0.1:8080")}
    assert paths == {"/mine"}


def test_sitemap_relative_locations_are_kept():
    body = "<urlset><url><loc>/relative/page</loc></url></urlset>"
    assert [c.path for c in paths_from_sitemap(body, "10.0.0.1:8080")] == ["/relative/page"]


def test_sitemap_handles_malformed_input():
    assert paths_from_sitemap("", "10.0.0.1:80") == []
    assert paths_from_sitemap("<urlset><url><loc></loc>", "10.0.0.1:80") == []


# -- response classification --------------------------------------------


@pytest.mark.parametrize(
    ("status", "length", "expected"),
    [
        (200, 120, "accessible"),
        (200, 0, None),
        (401, 50, "protected"),
        (403, 50, "protected"),
        (301, 0, "redirected"),
        (302, 0, "redirected"),
        (500, 100, "server-error"),
        (404, 300, None),
        (410, 10, None),
    ],
)
def test_response_classification(status, length, expected):
    assert classify_response(status, length, "text/html") == expected


def test_a_404_is_the_common_case_and_carries_no_information():
    assert classify_response(404, 1500, "text/html") is None
