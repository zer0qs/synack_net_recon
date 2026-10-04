"""Stability of configuration loading and report rendering.

Two classes of bug this file exists to catch:

* **A guardrail that stops guarding.** Every limit in this tool exists because
  exceeding it does damage to someone else's network. A config value of the
  wrong type, at a boundary, or absent must never end up silently disabling a
  cap. The tests below push every knob to its edges and assert the clamp still
  holds.
* **A report that cannot be produced.** The report is the deliverable. After a
  long scan, a renderer that raises on a surprising value — an enormous
  banner, a null where a string was expected, a host that reported nothing —
  has destroyed the run's output. Every field here is fed something hostile or
  degenerate, and the requirement is that the page still renders.
"""

from __future__ import annotations

import json
import math

import pytest
import yaml

from netrecon.core.config import (
    CONCURRENCY_HARD_MAX,
    HIDDEN_PATHS_HARD_MAX,
    MASSCAN_RATE_HARD_MAX,
    NUCLEI_RATE_HARD_MAX,
    WEBRECON_RATE_HARD_MAX,
    WEBRECON_RESPONSE_BYTES_HARD_MAX,
    Config,
    ConfigError,
)
from netrecon.report.build import Artifacts, aggregate, render_markdown
from netrecon.report.categories import group_by_category
from netrecon.report.html import render_html

# -- configuration -------------------------------------------------------

#: Every clamped limit: (config path, hard maximum).
CLAMPED_LIMITS: list[tuple[tuple[str, str], int]] = [
    (("limits", "masscan_rate"), MASSCAN_RATE_HARD_MAX),
    (("limits", "nuclei_rate"), NUCLEI_RATE_HARD_MAX),
    (("limits", "concurrency"), CONCURRENCY_HARD_MAX),
    (("webrecon", "rate_per_second"), WEBRECON_RATE_HARD_MAX),
    (("webrecon", "max_response_bytes"), WEBRECON_RESPONSE_BYTES_HARD_MAX),
    (("webrecon", "max_hidden_paths"), HIDDEN_PATHS_HARD_MAX),
]


@pytest.mark.parametrize(
    ("path", "maximum"), CLAMPED_LIMITS, ids=[f"{s}.{k}" for (s, k), _ in CLAMPED_LIMITS]
)
@pytest.mark.parametrize("factor", [1.5, 10, 1000, 10**6], ids=["x1.5", "x10", "x1k", "x1M"])
def test_every_clamped_limit_holds_at_any_magnitude(path, maximum, factor):
    """A typo of any size must land on the cap, never above it."""
    section, key = path
    config = Config.from_dict({section: {key: int(maximum * factor)}})
    assert getattr(getattr(config, section), key) <= maximum
    assert any("clamped" in warning for warning in config.warnings)


@pytest.mark.parametrize(("path", "maximum"), CLAMPED_LIMITS, ids=[f"{s}.{k}" for (s, k), _ in CLAMPED_LIMITS])
def test_a_value_exactly_at_the_maximum_is_kept(path, maximum):
    section, key = path
    config = Config.from_dict({section: {key: maximum}})
    assert getattr(getattr(config, section), key) == maximum


@pytest.mark.parametrize(("path", "maximum"), CLAMPED_LIMITS, ids=[f"{s}.{k}" for (s, k), _ in CLAMPED_LIMITS])
def test_a_value_one_below_the_maximum_is_kept(path, maximum):
    section, key = path
    config = Config.from_dict({section: {key: maximum - 1}})
    assert getattr(getattr(config, section), key) == maximum - 1


@pytest.mark.parametrize(
    "value",
    [0, -1, -(10**9)],
    ids=["zero", "negative", "very-negative"],
)
@pytest.mark.parametrize(
    ("section", "key"),
    [
        ("limits", "masscan_rate"),
        ("limits", "nuclei_rate"),
        ("limits", "concurrency"),
        ("limits", "host_timeout_seconds"),
        ("limits", "stage_timeout_seconds"),
        ("webrecon", "max_endpoints"),
        ("webrecon", "max_scripts_per_endpoint"),
        ("webrecon", "rate_per_second"),
        ("webrecon", "request_timeout_seconds"),
        ("webrecon", "concurrency"),
        ("scope", "max_hosts"),
        ("servicerecon", "probe_timeout_seconds"),
    ],
)
def test_non_positive_limits_are_rejected_not_silently_accepted(section, key, value):
    """A rate of zero would mean 'no limit' to some tools. Refuse it."""
    with pytest.raises(ConfigError):
        Config.from_dict({section: {key: value}})


@pytest.mark.parametrize(
    "value",
    [float("inf"), float("nan"), 10**30],
    ids=["inf", "nan", "huge-int"],
)
def test_pathological_numbers_do_not_disable_a_cap(value):
    """inf and nan must not survive into an argv as a rate limit."""
    if isinstance(value, float) and math.isnan(value):
        # NaN compares false against everything, so a naive `> MAX` check
        # would let it through. Either it is rejected or it is clamped;
        # what it must never be is passed on unchanged.
        try:
            config = Config.from_dict({"webrecon": {"rate_per_second": value}})
        except ConfigError:
            return
        assert not math.isnan(config.webrecon.rate_per_second)
        return

    try:
        config = Config.from_dict({"webrecon": {"rate_per_second": value}})
    except (ConfigError, OverflowError, ValueError):
        return
    assert config.webrecon.rate_per_second <= WEBRECON_RATE_HARD_MAX


@pytest.mark.parametrize(
    "value",
    ["1000", True, None, [], {}, "many"],
    ids=["str", "bool", "none", "list", "dict", "word"],
)
def test_wrong_types_for_a_rate_do_not_crash_opaquely(value):
    """Whatever happens, it must be a ConfigError the operator can read."""
    try:
        config = Config.from_dict({"limits": {"masscan_rate": value}})
    except ConfigError:
        return
    except Exception as exc:  # noqa: BLE001 - that is the finding
        pytest.fail(f"expected ConfigError, got {type(exc).__name__}: {exc}")
    # If it was coerced rather than rejected, the clamp must still apply.
    assert config.limits.masscan_rate <= MASSCAN_RATE_HARD_MAX


@pytest.mark.parametrize(
    "ports",
    [
        "1-65535",
        "1",
        "65535",
        "80,443",
        "1-1,2-2",
        " 80 , 443 ",
        "80,\n443",
        "8000-8010,8080-8090",
    ],
    ids=["all", "low", "high", "pair", "degenerate-ranges", "spaces", "newline", "ranges"],
)
def test_valid_port_specs_survive_normalisation(ports):
    config = Config.from_dict({"ports": {"sweep": ports}})
    assert " " not in config.ports.sweep
    assert "\n" not in config.ports.sweep


@pytest.mark.parametrize(
    "ports",
    [
        "", "0", "65536", "99999", "-1", "80-", "-80", "80--90", "443-80",
        "80,,443", "80;443", "80 443", "http", "80/tcp", "0-0", "1-65536",
    ],
)
def test_invalid_port_specs_are_rejected(ports):
    """A malformed port spec reaching an argv is a scan of the wrong thing."""
    with pytest.raises(ConfigError):
        Config.from_dict({"ports": {"sweep": ports}})


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "../etc", "a/b", "./x", "/absolute", ".hidden"],
)
def test_dangerous_run_names_are_rejected(name):
    """run_name becomes a directory component; traversal must not be possible."""
    with pytest.raises(ConfigError):
        Config.from_dict({"run_name": name})


@pytest.mark.parametrize("name", ["a", "run-1", "acme_2024", "ACME.11", "x" * 200])
def test_ordinary_run_names_are_accepted(name):
    assert Config.from_dict({"run_name": name}).run_name == name


@pytest.mark.parametrize(
    "document",
    ["", "\n", "# only a comment\n", "---\n"],
    ids=["empty", "newline", "comment", "doc-marker"],
)
def test_an_effectively_empty_config_file_yields_defaults(tmp_path, document):
    path = tmp_path / "c.yaml"
    path.write_text(document, encoding="utf-8")
    assert Config.load(path).limits.masscan_rate == Config().limits.masscan_rate


@pytest.mark.parametrize(
    "document",
    ["- a\n- b\n", "just a string\n", "42\n", "true\n"],
    ids=["list", "scalar-str", "scalar-int", "scalar-bool"],
)
def test_a_config_that_is_not_a_mapping_is_rejected(tmp_path, document):
    path = tmp_path / "c.yaml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ConfigError, match="mapping"):
        Config.load(path)


def test_invalid_yaml_is_rejected_with_a_readable_error(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("limits:\n  masscan_rate: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="could not parse"):
        Config.load(path)


def test_a_missing_config_file_is_rejected():
    with pytest.raises(ConfigError, match="not found"):
        Config.load("/nonexistent/netrecon.yaml")


@pytest.mark.parametrize(
    "payload",
    [
        {"unknown_top": 1},
        {"limits": {"unknown_key": 1}},
        {"webrecon": {"raet_per_second": 5}},
        {"stages": {"webrcon": True}},
    ],
    ids=["top-level", "limits", "webrecon-typo", "stages-typo"],
)
def test_unknown_keys_are_rejected_so_a_typo_cannot_disable_a_guardrail(payload):
    with pytest.raises(ConfigError, match="unknown"):
        Config.from_dict(payload)


def test_a_section_set_to_null_falls_back_to_defaults(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("limits:\nwebrecon:\n", encoding="utf-8")
    config = Config.load(path)
    assert config.limits.masscan_rate == Config().limits.masscan_rate


@pytest.mark.parametrize("section", ["limits", "webrecon", "stages", "ports", "scope"])
def test_a_section_that_is_not_a_mapping_is_rejected(section):
    with pytest.raises(ConfigError, match="mapping"):
        Config.from_dict({section: ["not", "a", "mapping"]})


def test_validate_is_idempotent():
    """The CLI validates after applying overrides; clamping must not compound."""
    config = Config.from_dict({"limits": {"masscan_rate": 10**6}})
    first = config.limits.masscan_rate
    for _ in range(5):
        config.validate()
    assert config.limits.masscan_rate == first


def test_the_shipped_config_round_trips_through_to_dict():
    config = Config.load("configs/default.yaml")
    rebuilt = Config.from_dict({k: v for k, v in config.to_dict().items() if k != "warnings"})
    assert rebuilt.to_dict() == config.to_dict()


def test_to_dict_is_json_and_yaml_serialisable():
    """It goes into state.json and is read back on resume."""
    payload = Config.load("configs/default.yaml").to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert yaml.safe_load(yaml.safe_dump(payload)) == payload


# -- report rendering ----------------------------------------------------

HOSTILE_STRINGS = [
    "<script>alert(1)</script>",
    "</pre><img src=x onerror=alert(1)>",
    "' onmouseover='alert(1)",
    '" autofocus onfocus="alert(1)',
    "javascript:alert(1)",
    "\x00\x01\x02 control chars",
    "line\nbreak\rand\ttabs",
    "‮RTL override",
    "😀 emoji and ünïcödé",
    "a" * 5000,
    "|pipes|in|a|table|",
    "`backticks` and **markdown**",
    "{{template}} and ${interpolation}",
]


def _artifacts(**overrides) -> Artifacts:
    base = {
        "live_hosts": ["10.0.0.1"],
        "in_scope": frozenset({"10.0.0.1"}),
        "run": {"name": "t", "started_at": "2024-05-20T10:00:00Z"},
        "scope": {"total_hosts": 1, "source": "scope.txt"},
        "limits": {"sweep_rate_pps": 1000},
        "stages": {},
    }
    base.update(overrides)
    return Artifacts(**base)


def _render_both(artifacts: Artifacts) -> tuple[str, str]:
    result = aggregate(artifacts)
    markdown = render_markdown(result.payload, result.hosts, result.categories)
    html = render_html(result.payload, result.hosts, result.categories, artifacts.webrecon)
    return markdown, html


@pytest.mark.parametrize("hostile", HOSTILE_STRINGS, ids=range(len(HOSTILE_STRINGS)))
def test_a_hostile_service_banner_renders_without_executing(hostile):
    """Banners come from the scanned host. They are never trusted markup."""
    markdown, html = _render_both(
        _artifacts(
            sweep={"hosts": {"10.0.0.1": [{"port": 80, "protocol": "tcp"}]}},
            services={
                "hosts": [
                    {
                        "address": "10.0.0.1",
                        "ports": [
                            {
                                "port": 80,
                                "protocol": "tcp",
                                "state": "open",
                                "service": {"name": "http", "label": hostile},
                            }
                        ],
                    }
                ]
            },
        )
    )
    assert markdown
    assert html.startswith("<!doctype html>")
    if "<" in hostile:
        assert hostile not in html, "raw markup from a scanned host reached the page"
    if "|" in hostile:
        assert "|pipes|in|a|table|" not in markdown, "an unescaped pipe breaks the table"


@pytest.mark.parametrize("hostile", HOSTILE_STRINGS, ids=range(len(HOSTILE_STRINGS)))
def test_a_hostile_page_title_renders_without_executing(hostile):
    markdown, html = _render_both(
        _artifacts(
            webrecon={
                "results": [
                    {
                        "ip": "10.0.0.1",
                        "port": 80,
                        "base_url": "http://10.0.0.1:80",
                        "root": {"status": 200, "title": hostile},
                        "totals": {},
                    }
                ]
            }
        )
    )
    assert markdown
    if "<" in hostile:
        assert hostile not in html


@pytest.mark.parametrize("hostile", HOSTILE_STRINGS[:8], ids=range(8))
def test_a_hostile_hostname_cannot_break_an_html_attribute(hostile):
    _, html = _render_both(
        _artifacts(
            sweep={"hosts": {"10.0.0.1": [{"port": 80, "protocol": "tcp"}]}},
            services={
                "hosts": [
                    {
                        "address": "10.0.0.1",
                        "hostnames": [hostile],
                        "ports": [
                            {"port": 80, "protocol": "tcp", "state": "open",
                             "service": {"name": "http"}}
                        ],
                    }
                ]
            },
        )
    )
    assert "onmouseover='alert(1)" not in html
    assert 'onfocus="alert(1)' not in html


@pytest.mark.parametrize(
    "degenerate",
    [
        {},
        {"hosts": None},
        {"hosts": {}},
        {"hosts": []},
        {"hosts": {"10.0.0.1": None}},
        {"hosts": {"10.0.0.1": "not a list"}},
        {"hosts": {"10.0.0.1": [None, 1, "x", {}]}},
        {"hosts": {"10.0.0.1": [{"port": None}]}},
        {"hosts": {"10.0.0.1": [{"port": "80"}]}},
        {"hosts": {"": [{"port": 80}]}},
    ],
    ids=range(10),
)
def test_a_degenerate_sweep_checkpoint_still_renders(degenerate):
    markdown, html = _render_both(_artifacts(sweep=degenerate))
    assert markdown
    assert html.rstrip().endswith("</html>")


@pytest.mark.parametrize(
    "degenerate",
    [
        {},
        {"hosts": None},
        {"hosts": [None]},
        {"hosts": [{"address": None}]},
        {"hosts": [{"address": "10.0.0.1", "ports": None}]},
        {"hosts": [{"address": "10.0.0.1", "ports": [None]}]},
        {"hosts": [{"address": "10.0.0.1", "os_matches": [{}]}]},
        {"hosts": [{"address": "10.0.0.1", "host_scripts": None}]},
    ],
    ids=range(8),
)
def test_a_degenerate_services_checkpoint_still_renders(degenerate):
    markdown, html = _render_both(_artifacts(services=degenerate))
    assert markdown
    assert html.rstrip().endswith("</html>")


@pytest.mark.parametrize(
    "degenerate",
    [
        {},
        {"results": None},
        {"results": [None]},
        {"results": [{}]},
        {"results": [{"ip": "10.0.0.1"}]},
        {"results": [{"ip": "10.0.0.1", "root": None, "totals": None}]},
        {"results": [{"ip": "10.0.0.1", "javascript": None}]},
        {"results": [{"ip": "10.0.0.1", "hidden_paths": None}]},
        {"results": [{"ip": "10.0.0.1", "api_endpoints": None}]},
        {"results": [{"ip": "10.0.0.1", "cve_matches": "not a list"}]},
    ],
    ids=range(10),
)
def test_a_degenerate_webrecon_checkpoint_still_renders(degenerate):
    markdown, html = _render_both(_artifacts(webrecon=degenerate))
    assert markdown
    assert html.rstrip().endswith("</html>")


@pytest.mark.parametrize(
    "degenerate",
    [
        {},
        {"results": None},
        {"results": [None]},
        {"results": [{"ip": "10.0.0.1", "findings": None}]},
        {"results": [{"ip": "10.0.0.1", "findings": [None]}]},
        {"results": [{"ip": "10.0.0.1", "findings": [{}]}]},
        {"results": [{"ip": "10.0.0.1", "findings": [{"severity": "made-up"}]}]},
    ],
    ids=range(7),
)
def test_a_degenerate_service_findings_checkpoint_still_renders(degenerate):
    result = aggregate(_artifacts(service_findings=degenerate))
    html = render_html(result.payload, result.hosts, result.categories, {}, degenerate)
    assert html.rstrip().endswith("</html>")


def test_an_artifact_from_a_newer_version_is_tolerated():
    """Unknown keys must be ignored, not rejected: runs outlive versions."""
    markdown, html = _render_both(
        _artifacts(
            sweep={
                "hosts": {"10.0.0.1": [{"port": 80, "protocol": "tcp", "future_key": 1}]},
                "unknown_top_level": {"a": 1},
            },
            webrecon={"results": [], "something_new": [1, 2, 3]},
        )
    )
    assert markdown
    assert html


def test_a_large_run_renders_in_reasonable_time():
    """500 hosts with 20 ports each: the report must still be produced."""
    import time

    hosts = {
        f"10.0.{block}.{host}": [
            {"port": 8000 + index, "protocol": "tcp"} for index in range(20)
        ]
        for block in range(2)
        for host in range(1, 251)
    }
    artifacts = _artifacts(
        live_hosts=sorted(hosts),
        in_scope=frozenset(hosts),
        sweep={"hosts": hosts},
        scope={"total_hosts": len(hosts), "source": "scope.txt"},
    )
    started = time.monotonic()
    markdown, html = _render_both(artifacts)
    elapsed = time.monotonic() - started

    assert elapsed < 30, f"rendering 500 hosts took {elapsed:.1f}s"
    assert markdown.count("### ") >= 500
    assert len(html) > 100_000


def test_a_host_that_reported_absolutely_nothing_still_appears():
    result = aggregate(_artifacts(live_hosts=["10.0.0.1"]))
    assert result.payload["hosts"][0]["ip"] == "10.0.0.1"
    markdown = render_markdown(result.payload, result.hosts, result.categories)
    assert "10.0.0.1" in markdown


def test_an_empty_run_renders_both_formats():
    markdown, html = _render_both(Artifacts())
    assert "No hosts responded" in markdown
    assert html.rstrip().endswith("</html>")


def test_rendering_is_deterministic():
    artifacts = _artifacts(
        sweep={
            "hosts": {
                "10.0.0.1": [{"port": 443, "protocol": "tcp"},
                             {"port": 80, "protocol": "tcp"}]
            }
        }
    )
    first_md, first_html = _render_both(artifacts)
    second_md, second_html = _render_both(artifacts)
    # Only the generated-at stamp may differ.
    assert first_md.replace("\n", "")[:200] == second_md.replace("\n", "")[:200]
    assert len(first_html) == len(second_html)


@pytest.mark.parametrize("count", [0, 1, 2, 50], ids=["none", "one", "two", "many"])
def test_category_grouping_is_stable_for_any_host_count(count):
    hosts = {
        f"10.0.0.{index + 1}": [{"port": 80, "protocol": "tcp"}] for index in range(count)
    }
    result = aggregate(
        _artifacts(sweep={"hosts": hosts}, in_scope=frozenset(hosts), live_hosts=[])
    )
    categories = group_by_category(result.hosts)
    assert all(category.entries for category in categories), "no empty category may appear"
    if count:
        assert categories[0].key == "web"
