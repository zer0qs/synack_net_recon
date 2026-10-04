"""Tests for report aggregation as a pure function.

`aggregate()` takes plain data and returns plain data: no file access, no
network, no RunContext. That is what makes the cross-stage reasoning in the
report testable at all — every test here builds an `Artifacts` by hand and
asserts on the payload, with no fixture directory and no scan.
"""

from __future__ import annotations

import pytest

from netrecon.report.build import Artifacts, aggregate

IN_SCOPE = "10.10.10.5"
ALSO_IN_SCOPE = "10.10.10.6"
OUT_OF_SCOPE = "192.168.99.99"
SCOPE = frozenset({IN_SCOPE, ALSO_IN_SCOPE})


def _artifacts(**overrides) -> Artifacts:
    base = {
        "live_hosts": [IN_SCOPE],
        "in_scope": SCOPE,
        "run": {"name": "t", "started_at": "2024-05-20T10:00:00Z"},
        "scope": {"total_hosts": 2, "source": "scope.txt"},
        "limits": {"sweep_rate_pps": 1000},
        "stages": {},
    }
    base.update(overrides)
    return Artifacts(**base)


def _sweep(hosts):
    return {"backend": "masscan", "hosts": hosts}


# -- purity --------------------------------------------------------------


def test_aggregate_touches_no_files_and_no_network(monkeypatch):
    """The whole point of the split: assert it rather than assume it."""
    import builtins
    import socket
    import subprocess

    def explode(*_args, **_kwargs):
        raise AssertionError("aggregate() must not perform I/O")

    monkeypatch.setattr(builtins, "open", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(subprocess, "run", explode)

    result = aggregate(
        _artifacts(sweep=_sweep({IN_SCOPE: [{"port": 80, "protocol": "tcp"}]}))
    )
    assert result.payload["totals"]["open_ports"] == 1


def test_aggregate_is_deterministic():
    artifacts = _artifacts(sweep=_sweep({IN_SCOPE: [{"port": 443, "protocol": "tcp"}]}))
    first = aggregate(artifacts).payload
    second = aggregate(artifacts).payload
    first.pop("generated_at")
    second.pop("generated_at")
    assert first == second


def test_aggregate_does_not_mutate_its_input():
    sweep = _sweep({IN_SCOPE: [{"port": 80, "protocol": "tcp"}]})
    artifacts = _artifacts(sweep=sweep)
    aggregate(artifacts)
    assert sweep == {"backend": "masscan", "hosts": {IN_SCOPE: [{"port": 80, "protocol": "tcp"}]}}


def test_empty_artifacts_produce_an_empty_but_valid_payload():
    payload = aggregate(Artifacts()).payload
    assert payload["totals"]["hosts_reported"] == 0
    assert payload["hosts"] == []
    assert payload["categories"] == []


# -- merging across stages ----------------------------------------------


def test_sweep_ports_become_host_rows():
    payload = aggregate(
        _artifacts(sweep=_sweep({IN_SCOPE: [{"port": 22, "protocol": "tcp"}]}))
    ).payload
    host = payload["hosts"][0]
    assert host["ip"] == IN_SCOPE
    assert host["open_ports"][0]["port"] == 22


def test_service_data_enriches_the_matching_sweep_port():
    payload = aggregate(
        _artifacts(
            sweep=_sweep({IN_SCOPE: [{"port": 80, "protocol": "tcp"}]}),
            services={
                "services_identified": 1,
                "hosts": [
                    {
                        "address": IN_SCOPE,
                        "hostnames": ["web01"],
                        "ports": [
                            {
                                "port": 80,
                                "protocol": "tcp",
                                "state": "open",
                                "service": {"name": "http", "label": "nginx 1.18.0"},
                            }
                        ],
                    }
                ],
            },
        )
    ).payload
    host = payload["hosts"][0]
    assert host["hostnames"] == ["web01"]
    assert len(host["open_ports"]) == 1, "the port must be enriched, not duplicated"
    assert host["open_ports"][0]["service"] == "http"
    assert host["open_ports"][0]["version"] == "nginx 1.18.0"


def test_a_service_port_absent_from_the_sweep_is_still_added():
    payload = aggregate(
        _artifacts(
            sweep=_sweep({IN_SCOPE: []}),
            services={
                "hosts": [
                    {
                        "address": IN_SCOPE,
                        "ports": [
                            {"port": 8443, "protocol": "tcp", "state": "open",
                             "service": {"name": "https"}}
                        ],
                    }
                ]
            },
        )
    ).payload
    assert [p["port"] for p in payload["hosts"][0]["open_ports"]] == [8443]


def test_closed_service_ports_are_ignored():
    payload = aggregate(
        _artifacts(
            services={
                "hosts": [
                    {
                        "address": IN_SCOPE,
                        "ports": [
                            {"port": 443, "protocol": "tcp", "state": "closed",
                             "service": {"name": "https"}}
                        ],
                    }
                ]
            }
        )
    ).payload
    assert payload["hosts"][0]["open_ports"] == []


def test_live_hosts_with_no_ports_still_get_a_row():
    payload = aggregate(_artifacts(live_hosts=[IN_SCOPE, ALSO_IN_SCOPE])).payload
    assert {h["ip"] for h in payload["hosts"]} == {IN_SCOPE, ALSO_IN_SCOPE}
    assert all(h["open_port_count"] == 0 for h in payload["hosts"])


def test_hosts_are_sorted_numerically():
    payload = aggregate(
        _artifacts(live_hosts=["10.10.10.20", "10.10.10.3", "10.10.10.100"],
                   in_scope=frozenset({"10.10.10.20", "10.10.10.3", "10.10.10.100"}))
    ).payload
    assert [h["ip"] for h in payload["hosts"]] == ["10.10.10.3", "10.10.10.20", "10.10.10.100"]


# -- scope re-filtering --------------------------------------------------


def test_out_of_scope_webrecon_results_are_dropped():
    """A hand-edited webrecon.json must not be able to add a host."""
    payload = aggregate(
        _artifacts(
            webrecon={
                "results": [
                    {"ip": OUT_OF_SCOPE, "base_url": "http://evil", "totals": {}, "root": {}},
                    {"ip": IN_SCOPE, "base_url": "http://ok", "totals": {}, "root": {}},
                ]
            }
        )
    ).payload
    assert {h["ip"] for h in payload["hosts"]} == {IN_SCOPE}


def test_out_of_scope_service_findings_are_dropped():
    payload = aggregate(
        _artifacts(
            service_findings={
                "findings": 2,
                "results": [
                    {
                        "analyzer": "tls",
                        "ip": OUT_OF_SCOPE,
                        "port": 443,
                        "findings": [{"key": "k", "severity": "high", "title": "T",
                                      "summary": "s"}],
                    },
                    {
                        "analyzer": "tls",
                        "ip": IN_SCOPE,
                        "port": 443,
                        "findings": [{"key": "k", "severity": "high", "title": "T",
                                      "summary": "s"}],
                    },
                ],
            }
        )
    ).payload
    assert {h["ip"] for h in payload["hosts"]} == {IN_SCOPE}


def test_an_empty_scope_set_disables_filtering_rather_than_dropping_everything():
    """`netrecon report` on a run without a scope snapshot must still work."""
    payload = aggregate(
        Artifacts(
            in_scope=frozenset(),
            webrecon={"results": [{"ip": IN_SCOPE, "totals": {}, "root": {}}]},
        )
    ).payload
    assert payload["hosts"][0]["ip"] == IN_SCOPE


# -- derived notes -------------------------------------------------------


def test_notable_service_ports_produce_a_note():
    payload = aggregate(
        _artifacts(sweep=_sweep({IN_SCOPE: [{"port": 3306, "protocol": "tcp"}]}))
    ).payload
    assert any("MySQL" in note for note in payload["hosts"][0]["notes"])


def test_high_severity_analyzer_findings_become_notes():
    payload = aggregate(
        _artifacts(
            service_findings={
                "findings": 1,
                "results": [
                    {
                        "analyzer": "tls",
                        "ip": IN_SCOPE,
                        "port": 443,
                        "protocol": "tcp",
                        "findings": [
                            {"key": "tls.expired", "severity": "high",
                             "title": "Certificate has expired", "summary": "s"}
                        ],
                    }
                ],
            }
        )
    ).payload
    assert any("Certificate has expired" in n for n in payload["hosts"][0]["notes"])


def test_info_findings_do_not_become_notes():
    payload = aggregate(
        _artifacts(
            service_findings={
                "results": [
                    {
                        "analyzer": "http",
                        "ip": IN_SCOPE,
                        "port": 80,
                        "protocol": "tcp",
                        "findings": [
                            {"key": "http.technology", "severity": "info",
                             "title": "Technology stack", "summary": "s"}
                        ],
                    }
                ]
            }
        )
    ).payload
    assert not any("Technology stack" in n for n in payload["hosts"][0]["notes"])


def test_pii_in_front_end_assets_produces_a_handling_note():
    payload = aggregate(
        _artifacts(
            webrecon={
                "results": [
                    {
                        "ip": IN_SCOPE,
                        "port": 80,
                        "base_url": "http://x",
                        "root": {},
                        "totals": {"pii_candidates": 3},
                        "javascript": {"pii_summary": {"email": 3}},
                    }
                ]
            }
        )
    ).payload
    notes = " ".join(payload["hosts"][0]["notes"])
    assert "personal-data candidate" in notes
    assert "handle the run directory as personal data" in notes


# -- totals and grouping -------------------------------------------------


def test_totals_count_what_the_report_shows():
    payload = aggregate(
        _artifacts(
            live_hosts=[IN_SCOPE, ALSO_IN_SCOPE],
            sweep=_sweep(
                {
                    IN_SCOPE: [{"port": 80, "protocol": "tcp"},
                               {"port": 443, "protocol": "tcp"}],
                    ALSO_IN_SCOPE: [{"port": 22, "protocol": "tcp"}],
                }
            ),
        )
    ).payload
    totals = payload["totals"]
    assert totals["live_hosts"] == 2
    assert totals["hosts_reported"] == 2
    assert totals["hosts_with_open_ports"] == 2
    assert totals["open_ports"] == 3


def test_categories_are_derived_from_the_merged_hosts():
    result = aggregate(
        _artifacts(
            sweep=_sweep(
                {IN_SCOPE: [{"port": 80, "protocol": "tcp"},
                            {"port": 3306, "protocol": "tcp"}]}
            )
        )
    )
    assert [c.key for c in result.categories] == ["web", "database"]
    assert result.payload["totals"]["service_categories"] == 2


def test_web_block_carries_through_for_the_renderers():
    payload = aggregate(
        _artifacts(
            webrecon={
                "technologies": ["nginx 1.18.0"],
                "hosts_referenced": ["internal.acme.corp"],
                "high_value_paths": ["http://x/.git/HEAD"],
                "results": [],
            }
        )
    ).payload
    assert payload["web"]["technologies"] == ["nginx 1.18.0"]
    assert payload["web"]["hosts_referenced"] == ["internal.acme.corp"]
    assert payload["web"]["high_value_paths"] == ["http://x/.git/HEAD"]


def test_nuclei_findings_attach_to_their_host():
    payload = aggregate(
        _artifacts(
            nuclei_findings=[
                {
                    "template-id": "tech-detect",
                    "info": {"name": "Tech", "severity": "info"},
                    "host": f"{IN_SCOPE}:80",
                    "matched-at": f"{IN_SCOPE}:80",
                }
            ]
        )
    ).payload
    assert payload["hosts"][0]["nuclei_findings"][0]["template"] == "tech-detect"
    assert payload["totals"]["nuclei_findings"] == 1


def test_malformed_artifact_shapes_do_not_raise():
    """Checkpoints can be truncated; aggregation must survive that."""
    payload = aggregate(
        _artifacts(
            sweep={"hosts": {IN_SCOPE: [None, "junk", {"port": 80, "protocol": "tcp"}]}},
            services={"hosts": [{"no_address": True}, None]},
            webrecon={"results": [{"no_ip": True}]},
            service_findings={"results": [{"ip": None, "findings": []}]},
        )
    ).payload
    assert payload["totals"]["open_ports"] == 1


@pytest.mark.parametrize("missing", ["sweep", "services", "webrecon", "service_findings"])
def test_any_single_artifact_may_be_absent(missing):
    kwargs = {
        "sweep": _sweep({IN_SCOPE: [{"port": 80, "protocol": "tcp"}]}),
        "services": {"hosts": []},
        "webrecon": {"results": []},
        "service_findings": {"results": []},
    }
    kwargs.pop(missing)
    assert aggregate(_artifacts(**kwargs)).payload["totals"]["hosts_reported"] >= 1
