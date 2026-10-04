"""Stability tests for the parsers and the JavaScript/stack analysers.

Everything these functions are fed is attacker-influenced. An nmap XML file
records what a scanned host *said*; a masscan line records what a host *replied*;
the analysers in :mod:`netrecon.analyze` run over minified JavaScript served by
the target. So the class of bug this file exists to catch is not "wrong answer",
it is **the operator's own run dying or stalling because the target sent
something odd**:

* an uncaught exception (``OSError`` from a path-shaped blob, ``UnicodeEncodeError``
  from a lone surrogate, ``ValueError`` from a 5000-digit port) - a denial of
  service against the engagement;
* a regex with catastrophic backtracking - worse than a crash, because the run
  hangs with no error and the operator waits;
* an unbounded result - one minified megabyte swamping the report;
* a *fabricated* finding - a host, port, endpoint or hostname in the report that
  was never in the input. In a penetration-test report that is the worst
  outcome of the four.

The contract under test is therefore: **return what you can, drop what you
cannot parse, never raise anything but the module's own declared error, finish
inside a finite time budget, and never report what you did not read.**

Timing assertions use a budget far above any honest cost (:data:`BUDGET_SECONDS`).
A case that exceeds it is a bug to fix in the analyser, never a budget to raise.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from netrecon.analyze import apistructure, jsdata, techstack
from netrecon.analyze.cve import CveFeed, MissingFeed, Technology, correlate
from netrecon.parse.masscan import (
    PORT_RANGE,
    parse_masscan_json,
    parse_masscan_list,
    parse_naabu_json,
)
from netrecon.parse.nmap import NmapParseError, parse_nmap_xml

#: Generous on purpose. Every honest input below finishes in well under a
#: second; five seconds only catches a regex that has gone exponential.
BUDGET_SECONDS = 5.0


# -- the corpus ----------------------------------------------------------


def _deep_json(depth: int = 200) -> str:
    return "{" * depth + '"a":1' + "}" * depth


def _deep_xml(depth: int = 200) -> str:
    return "<nmaprun>" + "<a>" * depth + "leaf" + "</a>" * depth + "</nmaprun>"


#: Malformed, truncated, mistyped and hostile-encoding inputs. Built as a dict
#: so each case gets a readable test id.
MALFORMED: dict[str, str] = {
    "empty": "",
    "whitespace_only": "   \n\t\r ",
    "null_byte": "\x00",
    "null_byte_embedded": '{"ip":"1.1.1.1\x00","ports":[]}',
    "lone_surrogate": "\ud800",
    "lone_surrogate_in_xml": '<nmaprun><host><address addr="\ud800"/></host></nmaprun>',
    "invalid_utf8_replacement": "���",
    "utf8_bom_only": "﻿",
    "utf8_bom_then_xml": "﻿<nmaprun><host/></nmaprun>",
    "utf8_bom_then_json": '﻿{"ip":"10.0.0.1","ports":[]}',
    "crlf_endings": "open tcp 80 10.0.0.1\r\nopen tcp 443 10.0.0.2\r\n",
    "lone_cr_endings": "open tcp 80 10.0.0.1\ropen tcp 443 10.0.0.2\r",
    "truncated_mid_token": "<nmapru",
    "truncated_mid_element": '<nmaprun><host><address addr="10.0.0.1"',
    "truncated_mid_string": '<nmaprun args="nmap -sV 10.0',
    "truncated_mid_object": '[{"ip":"10.0.0.1","ports":[{"port":80,',
    "truncated_mid_key": '{"ip":"10.0.0.1","por',
    "valid_prefix_then_garbage": "<nmaprun/>\x01\x02\xff garbage )(*&",
    "valid_json_then_garbage": '[{"ip":"10.0.0.1","ports":[]}]@@@@ not json',
    "xml_given_to_json_parser": '<?xml version="1.0"?><nmaprun><host/></nmaprun>',
    "json_given_to_xml_parser": '{"ip":"10.0.0.1","ports":[{"port":80}]}',
    "deep_json_objects": _deep_json(),
    "deep_json_arrays": "[" * 200 + "]" * 200,
    "deep_xml_elements": _deep_xml(),
    "array_where_object_expected": '[[1,2,3],["a"]]',
    "object_where_array_expected": '{"ip":"10.0.0.1","ports":{"port":80}}',
    "scalar_at_top_level": "42",
    "string_at_top_level": '"just a string"',
    "entity_declaration": (
        '<?xml version="1.0"?>'
        '<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>'
    ),
    "external_dtd": (
        '<?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "http://127.0.0.1:1/evil.dtd">'
        "<nmaprun><host/></nmaprun>"
    ),
    "one_megabyte_single_line": "A" * 1_000_000,
    "long_path_shaped_line": "/" + "n" * 600,
}


def _entity_bomb() -> str:
    """A billion-laughs expansion, which must be refused rather than expanded."""
    levels = "".join(
        f'<!ENTITY e{i} "{(f"&e{i - 1};" * 10) if i else "a" * 10}">' for i in range(8)
    )
    return f'<!DOCTYPE nmaprun [{levels}]><nmaprun args="&e7;"/>'


#: Inputs built to stress one regex family each. The name says which.
PATHOLOGICAL: dict[str, str] = {
    "dotted_run_40kb": "a." * 20_000,  # hostname / dotted-call-chain patterns
    "long_label_run": ("a" * 62 + ".") * 500,
    "hyphen_digit_run_100kb": "1-" * 50_000,  # email local-part pattern
    "at_signs_100kb": "@" * 100_000,
    "dots_100kb": "." * 100_000,
    "digits_100kb": "0" * 100_000,  # card / phone / national-id patterns
    "digit_space_run": "1 " * 50_000,
    "quotes_100kb": '"' * 100_000,
    "single_quotes_100kb": "'" * 100_000,
    "backticks_40kb": "`" * 40_000,
    "backslashes_100kb": "\\" * 100_000,
    "dollar_brace_100kb": "${" * 50_000,
    "nested_template_literals": "`${" * 5_000,
    "key_colon_no_close": "{" + "key:" * 20_000,
    "fifty_thousand_commas": "," * 50_000,
    "unbalanced_open_braces": "{" * 20_000,
    "unbalanced_open_brackets": "[" * 20_000,
    "unbalanced_open_parens": "(" * 20_000,
    "one_char_100kb": "x" * 100_000,
    "unterminated_get_calls": "x.get(" * 5_000,
    "unterminated_fetch_options": "fetch('/a',{" * 2_000,
    "unterminated_axios_strings": "axios.get('/a" * 5_000,
    "api_path_repeated": "/api/" * 20_000,
    "comment_keyword_storm": ("/*" + "TODO" * 100) * 500,
    "assignment_storm": 'key="' * 20_000,
    "bearer_storm": "authorization:'Bearer " * 5_000,
}


# -- the functions under test --------------------------------------------

#: Exceptions each entry point is *allowed* to raise. Anything else is a bug.
#: Only the two functions that document a failure mode are listed; every other
#: analyser must return a partial result instead of raising.
DECLARED_ERRORS: dict[str, tuple[type[BaseException], ...]] = {
    "parse_nmap_xml": (NmapParseError,),
    "CveFeed.load": (MissingFeed,),
}


def _feed_loader(tmp_path: Path) -> Callable[[str], CveFeed]:
    counter = iter(range(10_000))

    def load(text: str) -> CveFeed:
        target = tmp_path / f"feed-{next(counter)}.json"
        # errors="surrogatepass" so a lone surrogate reaches the loader as the
        # byte sequence a real file would hold, rather than failing the write.
        target.write_bytes(text.encode("utf-8", errors="surrogatepass"))
        return CveFeed.load(target)

    return load


def string_entry_points(tmp_path: Path) -> dict[str, Callable[[str], Any]]:
    """Every entry point under test, normalised to ``str -> result``."""
    return {
        "parse_nmap_xml": parse_nmap_xml,
        "parse_masscan_json": parse_masscan_json,
        "parse_masscan_list": parse_masscan_list,
        "parse_naabu_json": parse_naabu_json,
        "analyse_javascript": lambda text: jsdata.analyse_javascript(text, "app.js"),
        "extract_call_sites": lambda text: apistructure.extract_call_sites(text, "app.js"),
        "detect_from_html": techstack.detect_from_html,
        "detect_from_headers": lambda text: techstack.detect_from_headers(
            {"server": text, "x-powered-by": text, "set-cookie": text}
        ),
        "CveFeed.load": _feed_loader(tmp_path),
    }


ENTRY_POINT_NAMES = tuple(string_entry_points(Path("/nonexistent")))


def call(name: str, func: Callable[[str], Any], text: str) -> Any:
    """Invoke one entry point, allowing only its declared error."""
    try:
        return func(text)
    except DECLARED_ERRORS.get(name, ()) as exc:
        return exc


# -- "no fabricated finding" ---------------------------------------------


def _grounded(value: str, text: str) -> bool:
    """Whether a reported string was actually read out of *text*.

    Comparison is case-insensitive because hostnames are lowercased on the way
    out, and a normalised URL may carry ``{name}`` where the source wrote
    ``${name}``, so a value containing a brace is exempted.
    """
    if "{" in value or "}" in value:
        return True
    return value.lower() in text.lower()


def assert_not_fabricated(name: str, result: Any, text: str) -> None:
    """Every concrete value in *result* must trace back to *text*."""
    if isinstance(result, BaseException):
        return
    if name == "parse_nmap_xml":
        for host in result.hosts:
            assert _grounded(host.address, text), host.address
            for port in host.ports:
                assert port.port in PORT_RANGE, port.port
                assert str(port.port) in text, port.port
        return
    if name in {"parse_masscan_json", "parse_masscan_list", "parse_naabu_json"}:
        for entry in result:
            assert _grounded(entry.ip, text), entry.ip
            assert entry.port in PORT_RANGE, entry.port
            assert str(entry.port) in text, entry.port
        return
    if name == "analyse_javascript":
        for endpoint in result.endpoints:
            assert _grounded(endpoint.value, text), endpoint.value
        for host in result.hosts:
            assert _grounded(host, text), host
        for match in result.infrastructure:
            assert _grounded(match.value, text), match.value
        return
    if name == "extract_call_sites":
        for site in result:
            assert _grounded(site.path, text), site.path
        return
    if name in {"detect_from_html", "detect_from_headers"}:
        for tech in result:
            if tech.version:
                assert tech.version in text, tech.version
        return
    if name == "CveFeed.load":
        # The feed invents nothing: every CVE id it indexed was in the file.
        for entry in result.entries:
            assert entry.cve_id.lower() in text.lower(), entry.cve_id


# -- 1. malformed and truncated input ------------------------------------


@pytest.mark.parametrize("case", sorted(MALFORMED), ids=sorted(MALFORMED))
@pytest.mark.parametrize("name", ENTRY_POINT_NAMES)
def test_malformed_string_input_is_survived(name: str, case: str, tmp_path: Path) -> None:
    text = MALFORMED[case]
    func = string_entry_points(tmp_path)[name]
    started = time.monotonic()
    result = call(name, func, text)
    elapsed = time.monotonic() - started
    assert elapsed < BUDGET_SECONDS, f"{name}({case}) took {elapsed:.2f}s"
    assert_not_fabricated(name, result, text)


@pytest.mark.parametrize("case", sorted(MALFORMED), ids=sorted(MALFORMED))
@pytest.mark.parametrize(
    "name",
    ["parse_nmap_xml", "parse_masscan_json", "parse_masscan_list", "parse_naabu_json"],
)
def test_malformed_file_input_is_survived(name: str, case: str, tmp_path: Path) -> None:
    """The same corpus reaching the parsers as a file on disk, not a string."""
    text = MALFORMED[case]
    target = tmp_path / "scan.out"
    target.write_bytes(text.encode("utf-8", errors="surrogatepass"))
    result = call(name, string_entry_points(tmp_path)[name], str(target))
    # Reading the file back cannot be compared against the surrogate-escaped
    # original, so only the parsers' own invariants are checked here.
    if not isinstance(result, BaseException) and name != "parse_nmap_xml":
        assert all(entry.port in PORT_RANGE for entry in result)


def test_empty_file_is_not_an_error_for_the_masscan_parsers(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert parse_masscan_json(empty) == []
    assert parse_masscan_list(empty) == []
    assert parse_naabu_json(empty) == []


def test_missing_file_is_not_an_error_for_the_masscan_parsers(tmp_path: Path) -> None:
    absent = tmp_path / "never-written.json"
    assert parse_masscan_json(absent) == []
    assert parse_masscan_list(absent) == []
    assert parse_naabu_json(absent) == []


def test_a_long_single_line_is_not_mistaken_for_a_filename(tmp_path: Path) -> None:
    """A path component over 255 bytes makes ``is_file()`` raise ENAMETOOLONG.

    Tool output arrives as a string, so one long line of scanner garbage used
    to abort the whole run with an uncaught OSError.
    """
    blob = "/" + "z" * 400
    assert parse_masscan_json(blob) == []
    assert parse_masscan_list(blob) == []
    assert parse_naabu_json(blob) == []
    with pytest.raises(NmapParseError):
        parse_nmap_xml(blob)


def test_a_bom_prefixed_xml_body_is_parsed_not_treated_as_a_path() -> None:
    report = parse_nmap_xml('﻿<nmaprun version="7.94"><host/></nmaprun>')
    assert report.version == "7.94"


def test_a_lone_surrogate_in_xml_is_a_parse_error_not_a_unicode_crash() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml('<nmaprun><host><address addr="\ud800" addrtype="ipv4"/></host></nmaprun>')


def test_external_entities_are_not_resolved(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("SUPER-SECRET-FILE-CONTENT")
    xml = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file://{secret}">]>'
        '<nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>'
    )
    try:
        report = parse_nmap_xml(xml)
    except NmapParseError as exc:
        assert "SUPER-SECRET" not in str(exc)
    else:  # pragma: no cover - only reached if a future parser resolves entities
        assert "SUPER-SECRET" not in json.dumps(report.to_dict())


def test_an_entity_expansion_bomb_is_refused_quickly() -> None:
    started = time.monotonic()
    try:
        report = parse_nmap_xml(_entity_bomb())
    except NmapParseError:
        pass
    else:
        assert len(report.args or "") < 1_000_000
    assert time.monotonic() - started < BUDGET_SECONDS


# -- 2. pathological input: timing ---------------------------------------


@pytest.mark.parametrize("case", sorted(PATHOLOGICAL), ids=sorted(PATHOLOGICAL))
@pytest.mark.parametrize(
    "name",
    [
        "analyse_javascript",
        "extract_call_sites",
        "detect_from_html",
        "parse_masscan_list",
        "parse_naabu_json",
    ],
)
def test_pathological_input_completes_inside_the_budget(
    name: str, case: str, tmp_path: Path
) -> None:
    """A regex that goes exponential here hangs the operator's run."""
    text = PATHOLOGICAL[case]
    func = string_entry_points(tmp_path)[name]
    started = time.monotonic()
    result = call(name, func, text)
    elapsed = time.monotonic() - started
    assert elapsed < BUDGET_SECONDS, f"{name}({case}) took {elapsed:.2f}s - fix the pattern"
    assert_not_fabricated(name, result, text)


@pytest.mark.parametrize(
    ("label", "extractor"),
    [
        ("endpoints", jsdata.extract_endpoints),
        ("secrets", jsdata.extract_secrets),
        ("pii", jsdata.extract_pii),
        ("infrastructure", jsdata.extract_infrastructure),
        ("source_maps", jsdata.extract_source_maps),
        ("comments", jsdata.extract_comments),
    ],
)
@pytest.mark.parametrize(
    "case",
    ["dotted_run_40kb", "hyphen_digit_run_100kb", "digits_100kb", "quotes_100kb", "dots_100kb"],
)
def test_each_extractor_is_individually_bounded(
    label: str, extractor: Callable[[str], Any], case: str
) -> None:
    """Per-extractor timing, so a slow pattern is attributable."""
    started = time.monotonic()
    extractor(PATHOLOGICAL[case])
    elapsed = time.monotonic() - started
    assert elapsed < BUDGET_SECONDS, f"{label} on {case} took {elapsed:.2f}s"


def test_a_one_megabyte_minified_body_is_analysed_inside_the_budget() -> None:
    # A realistic shape: no newlines, lots of quoted paths and braces.
    body = 'fetch("/api/v1/item/0",{method:"POST",body:{id:0}});' * 20_000
    assert "\n" not in body
    started = time.monotonic()
    jsdata.analyse_javascript(body, "bundle.js")
    apistructure.extract_call_sites(body, "bundle.js")
    elapsed = time.monotonic() - started
    assert elapsed < BUDGET_SECONDS, f"1 MB bundle took {elapsed:.2f}s"


# -- 2b. pathological input: the caps must actually bind -----------------


def test_max_endpoints_binds() -> None:
    body = "".join(f'fetch("/api/v1/a{i}",{{method:"POST"}});' for i in range(1_200))
    body += "".join(f'u="/api/v2/b{i}";' for i in range(1_200))
    assert len(jsdata.extract_endpoints(body)) == jsdata.MAX_ENDPOINTS


def test_max_matches_per_kind_binds_for_secrets() -> None:
    body = " ".join("AKIA" + f"{i:016X}" for i in range(300))
    secrets = jsdata.extract_secrets(body, "app.js")
    assert len(secrets) == jsdata.MAX_MATCHES_PER_KIND
    assert {s.kind for s in secrets} == {"aws_access_key_id"}


def test_max_matches_per_kind_binds_for_pii() -> None:
    body = " ".join(f"user{i}@corp{i}.vn" for i in range(300))
    pii = jsdata.extract_pii(body, "app.js")
    assert len(pii) == jsdata.MAX_MATCHES_PER_KIND


def test_max_hosts_binds() -> None:
    body = " ".join(f"host{i}.internal" for i in range(500))
    matches, hosts = jsdata.extract_infrastructure(body, "app.js")
    assert len(hosts) == jsdata.MAX_HOSTS
    assert len(matches) <= jsdata.MAX_MATCHES_PER_KIND * 3


def test_max_call_sites_binds() -> None:
    body = "".join(f'fetch("/api/{i}");' for i in range(3_000))
    sites = apistructure.extract_call_sites(body, "app.js")
    assert len(sites) == apistructure.MAX_CALL_SITES


def test_api_max_endpoints_binds() -> None:
    body = "".join(f'fetch("/api/{i}");' for i in range(3_000))
    endpoints = apistructure.group_endpoints(apistructure.extract_call_sites(body))
    assert len(endpoints) <= apistructure.MAX_ENDPOINTS


def test_comment_limit_binds() -> None:
    body = "".join(f"/* TODO thing {i} */" for i in range(200))
    assert len(jsdata.extract_comments(body, limit=30)) <= 30


def test_the_total_scan_budget_bounds_a_body_full_of_unbalanced_brackets() -> None:
    """Each unbalanced bracket costs a full scan window; thousands must not."""
    body = "fetch('/a',{" * 2_000
    started = time.monotonic()
    apistructure.extract_call_sites(body, "app.js")
    assert time.monotonic() - started < BUDGET_SECONDS


# -- 3. semantic robustness: nmap ----------------------------------------


def _nmaprun(inner: str) -> str:
    return f"<nmaprun version='7.94'>{inner}</nmaprun>"


NMAP_SEMANTIC: dict[str, str] = {
    "host_without_ports_element": _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><status state='up'/></host>"
    ),
    "port_without_state": _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/>"
        "<ports><port portid='80'/></ports></host>"
    ),
    "service_without_name": _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><ports><port portid='80'>"
        "<state state='open'/><service product='thing'/></port></ports></host>"
    ),
    "duplicate_hosts": _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><status state='up'/></host>"
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><status state='down'/></host>"
    ),
    "duplicate_ports": _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><ports>"
        "<port portid='80'><state state='open'/></port>"
        "<port portid='80'><state state='closed'/></port></ports></host>"
    ),
    "unknown_addrtype": _nmaprun("<host><address addr='whatever' addrtype='quantum'/></host>"),
    "mac_address_only": _nmaprun(
        "<host><address addr='00:11:22:33:44:55' addrtype='mac' vendor='VMware'/></host>"
    ),
    "elapsed_not_a_number": _nmaprun("<runstats><finished elapsed='soon' exit='success'/></runstats>"),
    "elapsed_infinity": _nmaprun("<runstats><finished elapsed='inf'/></runstats>"),
    "elapsed_nan": _nmaprun("<runstats><finished elapsed='nan'/></runstats>"),
    "no_hosts_at_all": _nmaprun(""),
    "host_with_no_address": _nmaprun("<host><status state='up'/></host>"),
}


@pytest.mark.parametrize("case", sorted(NMAP_SEMANTIC), ids=sorted(NMAP_SEMANTIC))
def test_nmap_semantic_oddities_are_survived(case: str) -> None:
    xml = NMAP_SEMANTIC[case]
    report = parse_nmap_xml(xml)
    # The report must round-trip through JSON: a NaN or an Infinity here would
    # silently produce a summary.json no other tool can read.
    assert json.loads(json.dumps(report.to_dict(), allow_nan=False))
    assert_not_fabricated("parse_nmap_xml", report, xml)


@pytest.mark.parametrize("portid", ["-1", "0", "65535", "65536", "70000", "99999999", "abc", ""])
def test_out_of_range_nmap_ports_are_never_reported(portid: str) -> None:
    xml = _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><ports>"
        f"<port portid='{portid}'><state state='open'/></port></ports></host>"
    )
    ports = [p.port for p in parse_nmap_xml(xml).hosts[0].ports]
    assert all(port in PORT_RANGE for port in ports), ports
    if portid in {"0", "65535"}:
        assert ports == [int(portid)]
    else:
        assert ports == []


def test_an_absurd_port_number_does_not_raise_on_integer_conversion() -> None:
    # int() refuses a string of more than 4300 digits outright.
    xml = _nmaprun(
        "<host><address addr='10.0.0.1' addrtype='ipv4'/><ports>"
        f"<port portid='{'9' * 5000}'><state state='open'/></port></ports></host>"
    )
    assert parse_nmap_xml(xml).hosts[0].ports == []
    assert parse_masscan_list(f"open tcp {'9' * 5000} 10.0.0.1\n") == []


def test_a_duplicate_nmap_host_is_kept_verbatim_not_merged_into_a_guess() -> None:
    report = parse_nmap_xml(NMAP_SEMANTIC["duplicate_hosts"])
    assert report.addresses() == ["10.0.0.1", "10.0.0.1"]
    assert {host.status for host in report.hosts} == {"up", "down"}


# -- 3. semantic robustness: masscan / naabu -----------------------------


MASSCAN_SEMANTIC: dict[str, str] = {
    "ports_is_a_string": '{"ip":"10.0.0.1","ports":"80"}',
    "ports_is_an_int": '{"ip":"10.0.0.1","ports":80}',
    "ports_is_null": '{"ip":"10.0.0.1","ports":null}',
    "port_is_a_float": '{"ip":"10.0.0.1","ports":[{"port":80.0,"status":"open"}]}',
    "port_is_a_bool": '{"ip":"10.0.0.1","ports":[{"port":true,"status":"open"}]}',
    "port_is_a_string": '{"ip":"10.0.0.1","ports":[{"port":"80","status":"open"}]}',
    "status_missing": '{"ip":"10.0.0.1","ports":[{"port":80}]}',
    "status_is_closed": '{"ip":"10.0.0.1","ports":[{"port":80,"status":"closed"}]}',
    "status_is_a_number": '{"ip":"10.0.0.1","ports":[{"port":80,"status":1}]}',
    "trailing_finished_record": (
        '{"ip":"10.0.0.1","ports":[{"port":80,"status":"open"}]},\n{"finished":1}'
    ),
    "ip_missing": '{"ports":[{"port":80,"status":"open"}]}',
    "ip_is_a_number": '{"ip":16843009,"ports":[{"port":80,"status":"open"}]}',
    "out_of_range_port": '{"ip":"10.0.0.1","ports":[{"port":70000,"status":"open"}]}',
    "negative_port": '{"ip":"10.0.0.1","ports":[{"port":-80,"status":"open"}]}',
    "ttl_not_an_int": '{"ip":"10.0.0.1","ports":[{"port":80,"status":"open","ttl":"x"}]}',
    "duplicate_records": (
        '{"ip":"10.0.0.1","ports":[{"port":80,"status":"open"}]},\n'
        '{"ip":"10.0.0.1","ports":[{"port":80,"status":"open"}]}'
    ),
}


@pytest.mark.parametrize("case", sorted(MASSCAN_SEMANTIC), ids=sorted(MASSCAN_SEMANTIC))
def test_masscan_semantic_oddities_are_survived(case: str) -> None:
    text = MASSCAN_SEMANTIC[case]
    for name, parser in (
        ("parse_masscan_json", parse_masscan_json),
        ("parse_naabu_json", parse_naabu_json),
    ):
        result = parser(text)
        assert_not_fabricated(name, result, text)


def test_the_trailing_finished_record_does_not_become_a_host() -> None:
    ports = parse_masscan_json(MASSCAN_SEMANTIC["trailing_finished_record"])
    assert [(p.ip, p.port) for p in ports] == [("10.0.0.1", 80)]


def test_out_of_range_masscan_ports_are_never_reported() -> None:
    assert parse_masscan_json(MASSCAN_SEMANTIC["out_of_range_port"]) == []
    assert parse_masscan_json(MASSCAN_SEMANTIC["negative_port"]) == []
    assert parse_naabu_json('{"ip":"10.0.0.1","port":70000}') == []


def test_duplicate_masscan_records_collapse_to_one() -> None:
    assert len(parse_masscan_json(MASSCAN_SEMANTIC["duplicate_records"])) == 1


# -- 3. semantic robustness: CVE feed ------------------------------------


def _write_feed(tmp_path: Path, name: str, payload: Any) -> Path:
    target = tmp_path / f"{name}.json"
    target.write_text(payload if isinstance(payload, str) else json.dumps(payload))
    return target


NGINX_CPE = "cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*"
NGINX_RANGE_CPE = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"

FEED_SEMANTIC: dict[str, Any] = {
    "entry_missing_every_optional_field": {
        "entries": [{"cve": "CVE-2021-1234", "cpe": NGINX_CPE}]
    },
    "range_with_start_after_end": {
        "entries": [
            {
                "cve": "CVE-2021-1234",
                "cpe": NGINX_RANGE_CPE,
                "versionStartIncluding": "9.0",
                "versionEndExcluding": "1.0",
            }
        ]
    },
    "non_numeric_cvss": {
        "entries": [{"cve": "CVE-2021-1234", "cpe": NGINX_CPE, "cvss": "very bad"}]
    },
    "out_of_band_cvss": {"entries": [{"cve": "CVE-2021-1234", "cpe": NGINX_CPE, "cvss": 99}]},
    "cpe_with_too_few_fields": {"entries": [{"cve": "CVE-2021-1234", "cpe": "cpe:2.3:a:nginx"}]},
    "cpe_with_too_many_fields": {
        "entries": [{"cve": "CVE-2021-1234", "cpe": "cpe:2.3:" + "a:" * 40}]
    },
    "cpe_is_not_a_cpe": {"entries": [{"cve": "CVE-2021-1234", "cpe": "nginx 1.0"}]},
    "cve_id_malformed": {"entries": [{"cve": "NOT-A-CVE", "cpe": NGINX_CPE}]},
    "entry_is_a_list": {"entries": [["CVE-2021-1234", NGINX_CPE]]},
    "entry_is_a_string": {"entries": ["CVE-2021-1234"]},
    "entry_is_null": {"entries": [None]},
    "nvd20_vulnerabilities_of_scalars": {"vulnerabilities": ["x", None, 1]},
    "nvd11_items_of_scalars": {"CVE_Items": ["x", None, 1]},
    "nvd20_nodes_cycle_shaped": {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-1234",
                    "configurations": [{"nodes": [{"children": [{"cpeMatch": []}]}]}],
                }
            }
        ]
    },
}


@pytest.mark.parametrize("case", sorted(FEED_SEMANTIC), ids=sorted(FEED_SEMANTIC))
def test_cve_feed_semantic_oddities_are_survived(case: str, tmp_path: Path) -> None:
    payload = FEED_SEMANTIC[case]
    path = _write_feed(tmp_path, case, payload)
    feed = CveFeed.load(path)
    text = path.read_text()
    assert_not_fabricated("CveFeed.load", feed, text)
    assert len(feed) == len(feed.entries)
    assert len(feed.warnings) <= 51  # MAX_REPORTED_WARNINGS plus the summary line


def test_an_impossible_version_range_matches_nothing(tmp_path: Path) -> None:
    """start > end must yield no match, not a match for every version."""
    feed = CveFeed.load(
        _write_feed(tmp_path, "inverted", FEED_SEMANTIC["range_with_start_after_end"])
    )
    for version in ("0.1", "1.0", "5.0", "9.0", "99.0", None):
        tech = Technology("nginx", version, ("web-server",), "certain", "test", "banner")
        assert feed.match(tech) == []


def test_a_bare_wildcard_cpe_is_not_a_finding_for_every_version(tmp_path: Path) -> None:
    feed = CveFeed.load(
        _write_feed(
            tmp_path,
            "wildcard",
            {"entries": [{"cve": "CVE-2021-1234", "cpe": NGINX_RANGE_CPE}]},
        )
    )
    tech = Technology("nginx", "1.2.3", ("web-server",), "certain", "test", "banner")
    assert feed.match(tech) == []


def test_a_non_numeric_cvss_is_dropped_not_guessed(tmp_path: Path) -> None:
    feed = CveFeed.load(_write_feed(tmp_path, "cvss", FEED_SEMANTIC["non_numeric_cvss"]))
    assert all(entry.cvss_score is None for entry in feed.entries)


def test_a_ten_thousand_entry_feed_loads_and_looks_up_fast(tmp_path: Path) -> None:
    entries = [
        {
            "cve": f"CVE-2021-{10_000 + i}",
            "cpe": f"cpe:2.3:a:v{i % 50}:p{i % 50}:1.{i % 20}:*:*:*:*:*:*:*",
            "cvss": 5.0,
        }
        for i in range(10_000)
    ]
    path = _write_feed(tmp_path, "big", {"entries": entries})
    started = time.monotonic()
    feed = CveFeed.load(path)
    load_elapsed = time.monotonic() - started
    assert len(feed) == 10_000
    assert load_elapsed < BUDGET_SECONDS, f"load took {load_elapsed:.2f}s"

    technologies = [
        Technology(f"p{i}", f"1.{i % 20}", (), "certain", "test", "banner") for i in range(50)
    ]
    started = time.monotonic()
    for _ in range(20):
        correlate(technologies, feed)
    lookup_elapsed = time.monotonic() - started
    # Indexed by product, so this must not scan the feed.
    assert lookup_elapsed < BUDGET_SECONDS, f"1000 lookups took {lookup_elapsed:.2f}s"


# -- 3. semantic robustness: oversized JavaScript values -----------------


@pytest.mark.parametrize("length", [160, 1_000, 10_000])
def test_an_oversized_secret_value_never_reaches_the_report_unmasked(length: int) -> None:
    """Whether or not an absurd value is matched, it must not be reprinted.

    The patterns bound a value at 160 characters, so a 10 000-character one is
    deliberately dropped - but if it is matched, neither the value nor its
    context window may carry it.
    """
    value = ("Zq7Wx9Lm2Pd4Rt6Yv8Bn" * 500)[:length]
    body = f'const apiKey = "{value}"; authDomain: "a.example.vn";'
    started = time.monotonic()
    secrets = jsdata.extract_secrets(body, "app.js")
    assert time.monotonic() - started < BUDGET_SECONDS
    if length == 160:
        assert secrets, "a value inside the pattern bound should still be reported"
    for match in secrets:
        assert value not in match.value
        assert value not in (match.context or "")
        assert len(match.value) < 200
        assert len(match.context or "") <= jsdata.CONTEXT_CHARS * 2


def test_the_same_secret_a_thousand_times_is_reported_once() -> None:
    value = "AKIA" + "ZZ7QQQ3MMMNNN42X"
    body = (f'k="{value}";' * 1_000)
    started = time.monotonic()
    secrets = jsdata.extract_secrets(body, "app.js")
    assert time.monotonic() - started < BUDGET_SECONDS
    aws = [match for match in secrets if match.kind == "aws_access_key_id"]
    assert len(aws) == 1
    assert all(value not in match.value for match in secrets)


def test_a_five_thousand_character_path_is_not_reported_as_an_endpoint() -> None:
    body = 'fetch("/api/' + "s" * 5_000 + '");'
    started = time.monotonic()
    endpoints = jsdata.extract_endpoints(body, "app.js")
    sites = apistructure.extract_call_sites(body, "app.js")
    assert time.monotonic() - started < BUDGET_SECONDS
    assert all(len(endpoint.value) <= 250 for endpoint in endpoints)
    assert all(len(site.url) <= apistructure.MAX_URL_CHARS for site in sites)


# -- 4. determinism and idempotence --------------------------------------


def _comparable(result: Any) -> Any:
    """A hashable, order-preserving view of any result for equality checks."""
    if isinstance(result, BaseException):
        return (type(result).__name__,)
    if isinstance(result, CveFeed):
        return tuple(sorted(repr(entry) for entry in result.entries))
    if hasattr(result, "to_dict"):
        return json.dumps(result.to_dict(), sort_keys=True, default=str)
    if isinstance(result, Iterable) and not isinstance(result, str):
        return json.dumps(
            [item.to_dict() if hasattr(item, "to_dict") else str(item) for item in result],
            sort_keys=True,
            default=str,
        )
    return repr(result)


DETERMINISM_CORPUS: tuple[str, ...] = (
    "empty",
    "truncated_mid_object",
    "json_given_to_xml_parser",
    "xml_given_to_json_parser",
    "deep_json_objects",
    "utf8_bom_then_xml",
    "valid_prefix_then_garbage",
)


@pytest.mark.parametrize("case", DETERMINISM_CORPUS)
@pytest.mark.parametrize("name", ENTRY_POINT_NAMES)
def test_running_an_analysis_twice_gives_an_identical_result(
    name: str, case: str, tmp_path: Path
) -> None:
    func = string_entry_points(tmp_path)[name]
    text = MALFORMED[case]
    assert _comparable(call(name, func, text)) == _comparable(call(name, func, text))


REALISTIC_A = (
    'fetch("/api/v1/orders?include=items",{method:"POST",body:{id:1,qty:2}});'
    'const apiKey="Zq7Wx9Lm2Pd4Rt6Yv8Bn";authDomain:"a.example.vn";'
    "// TODO remove staging host jenkins.corp.internal\n"
    "contact: ops@acme.vn 10.1.2.3"
)
REALISTIC_B = (
    'axios.get("/api/v2/users/${userId}",{params:{page:1}});'
    'xhr.open("PUT","/internal/admin/flush");'
    "//# sourceMappingURL=app.js.map\n"
    "db: postgres://u:p@db.staging.internal:5432/app"
)


@pytest.mark.parametrize("name", ["analyse_javascript", "extract_call_sites", "detect_from_html"])
def test_analysis_order_does_not_change_the_result(name: str, tmp_path: Path) -> None:
    """These functions are pure, so no module-level state may leak between calls."""
    func = string_entry_points(tmp_path)[name]
    a_first = (_comparable(func(REALISTIC_A)), _comparable(func(REALISTIC_B)))
    b_first = (_comparable(func(REALISTIC_B)), _comparable(func(REALISTIC_A)))
    assert a_first == (b_first[1], b_first[0])


@pytest.mark.parametrize(
    "module", [jsdata, apistructure], ids=["jsdata", "apistructure"]
)
def test_no_module_level_mutable_state_is_touched_by_an_analysis(module: Any) -> None:
    mutable = {
        name: repr(value)
        for name, value in vars(module).items()
        if isinstance(value, (list, dict, set))
    }
    jsdata.analyse_javascript(REALISTIC_A, "a.js")
    apistructure.extract_call_sites(REALISTIC_B, "b.js")
    after = {
        name: repr(value)
        for name, value in vars(module).items()
        if isinstance(value, (list, dict, set))
    }
    assert mutable == after


@pytest.mark.parametrize(
    "accessor",
    [
        "sorted(h for h in jsdata.analyse_javascript(BODY).hosts)",
        "[e.value for e in jsdata.analyse_javascript(BODY).endpoints]",
        "[s.path for s in apistructure.extract_call_sites(BODY)]",
        "jsdata.extract_source_maps(BODY)",
    ],
)
def test_results_do_not_depend_on_hash_seed(accessor: str) -> None:
    """Sets and dicts are used internally; the output order must not show it."""
    program = (
        "import json\n"
        "from netrecon.analyze import jsdata, apistructure\n"
        f"BODY = {REALISTIC_A + REALISTIC_B!r}\n"
        f"print(json.dumps({accessor}))\n"
    )
    outputs = set()
    for seed in ("0", "1", "12345"):
        completed = subprocess.run(  # noqa: S603 - fixed argv, this interpreter
            [sys.executable, "-c", program],
            check=True,
            capture_output=True,
            text=True,
            env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)},
        )
        outputs.add(completed.stdout)
    assert len(outputs) == 1, outputs


ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    ("label", "call_twice"),
    [
        ("sorted hosts", lambda: jsdata.analyse_javascript(REALISTIC_A + REALISTIC_B).hosts),
        ("source maps", lambda: jsdata.extract_source_maps(REALISTIC_B)),
        (
            "parameter wordlist",
            lambda: apistructure.parameter_wordlist(
                apistructure.build_parameter_index(
                    apistructure.group_endpoints(
                        apistructure.extract_call_sites(REALISTIC_A + REALISTIC_B)
                    )
                )
            ),
        ),
    ],
)
def test_sorted_outputs_are_actually_sorted(label: str, call_twice: Callable[[], list]) -> None:
    values = call_twice()
    if label == "sorted hosts":
        assert values == sorted(values), label
    assert values == call_twice(), label


# -- 5. unicode and encoding ---------------------------------------------


RTL_OVERRIDE = "‮"
ZERO_WIDTH_JOINER = "‍"
HOMOGLYPH_A = "а"  # Cyrillic a
PUNYCODE_HOST = "xn--80ak6aa92e.com"

UNICODE_BODIES: dict[str, str] = {
    "rtl_override": f'fetch("/api/{RTL_OVERRIDE}gnp.exe");',
    "zero_width_joiner": f'const api{ZERO_WIDTH_JOINER}Key = "Zq7Wx9Lm2Pd4Rt6Yv8Bn";',
    "homoglyph_host": f"host: {HOMOGLYPH_A}cme.vn",
    "emoji": 'fetch("/api/\U0001f600/items");',
    "punycode_host": f'fetch("https://{PUNYCODE_HOST}/api/v1/x");',
    "non_ascii_email": "contact: nguyễn.văn.a@công-ty.vn",
    "non_ascii_hostname": "host: máy-chủ.nội-bộ.vn",
    "mixed": (
        f"{RTL_OVERRIDE}{ZERO_WIDTH_JOINER}\U0001f600 {PUNYCODE_HOST} "
        f"{HOMOGLYPH_A}dmin.staging.internal nguyễn@acme.vn"
    ),
    "combining_marks": "é" * 5_000,
    "astral_plane": "\U0001f600" * 20_000,
}


@pytest.mark.parametrize("case", sorted(UNICODE_BODIES), ids=sorted(UNICODE_BODIES))
@pytest.mark.parametrize(
    "name", ["analyse_javascript", "extract_call_sites", "detect_from_html", "detect_from_headers"]
)
def test_unicode_bodies_are_survived(name: str, case: str, tmp_path: Path) -> None:
    text = UNICODE_BODIES[case]
    func = string_entry_points(tmp_path)[name]
    started = time.monotonic()
    result = call(name, func, text)
    assert time.monotonic() - started < BUDGET_SECONDS
    assert_not_fabricated(name, result, text)


@pytest.mark.parametrize(
    "value",
    [
        "\U0001f600" * 20,
        "é" * 20,
        "nguyễn.văn.a@công-ty.vn",
        "é" * 10,
        RTL_OVERRIDE + "secret-value-here",
        "абв" * 10,
    ],
)
def test_masking_never_reveals_a_multibyte_value(value: str) -> None:
    """Masking slices by character, so a multi-byte value must not survive."""
    masked = jsdata.mask_value(value)
    assert value not in masked
    # The head and tail are bounded in *characters*, not bytes.
    assert len(masked) < len(value) + 32


@pytest.mark.parametrize(
    "address",
    ["nguyễn.văn.a@công-ty.vn", "аdmin@acme.vn", "a@b.vn", "é@é.vn"],
)
def test_email_masking_never_reveals_a_multibyte_local_part(address: str) -> None:
    masked = jsdata.mask_email(address)
    local, _, domain = address.partition("@")
    assert address not in masked
    if len(local) > 2:
        assert local not in masked
    assert domain in masked  # the domain is the part worth keeping


@pytest.mark.parametrize("value", ["٠١٢٣٤٥٦٧٨٩", "1234-5678-9012-3456", "１２３４５６７８"])
def test_digit_masking_never_reveals_a_multibyte_value(value: str) -> None:
    masked = jsdata.mask_digits(value)
    assert value not in masked


def test_a_punycode_host_is_reported_as_written() -> None:
    _matches, hosts = jsdata.extract_infrastructure(UNICODE_BODIES["punycode_host"], "app.js")
    assert PUNYCODE_HOST in hosts
