"""Tests for the per-service analysis stage.

The stage's defining property is that it is **offline**: it re-reads what the
earlier stages wrote and sends nothing. The first test in this file asserts
exactly that, by replacing the subprocess and socket entry points with things
that explode if touched.
"""

from __future__ import annotations

import json

import pytest

from netrecon.analyze.base import Finding, ServiceEvidence, dedupe_findings, severity_counts
from netrecon.analyze.registry import (
    ANALYZER_NAMES,
    UnknownAnalyzer,
    build_analyzers,
    validate_names,
)
from netrecon.core.config import Config, ConfigError
from netrecon.core.jsonio import write_json
from netrecon.stages import servicerecon
from netrecon.stages.base import StageSkipped

IN_SCOPE = "10.10.10.5"
OUT_OF_SCOPE = "192.168.99.99"


def _seed(ctx, *, services=None, sweep=None, scripts=None):
    if services is not None:
        write_json(ctx.paths.services, {"hosts": services})
    if sweep is not None:
        write_json(ctx.paths.open_ports, {"hosts": sweep})
    if scripts is not None:
        write_json(ctx.paths.root / "scripts.json", {"hosts": scripts})


def _service_host(ip=IN_SCOPE, port=22, name="ssh", **service):
    return {
        "address": ip,
        "hostnames": [],
        "ports": [
            {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": {"name": name, **service},
            }
        ],
    }


# -- the offline guarantee ----------------------------------------------


def test_the_stage_opens_no_sockets_and_runs_no_subprocess(make_context, monkeypatch):
    """This is the whole point of the stage; assert it rather than assume it."""
    import socket
    import subprocess

    def explode(*_args, **_kwargs):
        raise AssertionError("servicerecon must not touch the network")

    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(socket.socket, "connect", explode)
    monkeypatch.setattr(subprocess, "run", explode)
    monkeypatch.setattr(subprocess, "Popen", explode)

    ctx = make_context()
    ctx.config.servicerecon.allow_tls_probe = False
    _seed(
        ctx,
        services=[
            {
                "address": IN_SCOPE,
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "ssh", "product": "OpenSSH", "version": "7.4"},
                        "scripts": {"ssh-hostkey": "1024 aa:bb (DSA)"},
                    }
                ],
            }
        ],
    )
    result = servicerecon.run(ctx)
    assert result.counts["services_analysed"] == 1


# -- evidence assembly ---------------------------------------------------


def test_evidence_comes_from_service_data(make_context):
    ctx = make_context()
    _seed(ctx, services=[_service_host(product="OpenSSH", version="8.9p1")])
    evidence = servicerecon.load_evidence(ctx)
    assert len(evidence) == 1
    assert evidence[0].service == "ssh"
    assert evidence[0].product == "OpenSSH"
    assert evidence[0].banner.startswith("OpenSSH 8.9p1")


def test_sweep_fills_in_ports_that_never_reached_version_detection(make_context):
    ctx = make_context()
    _seed(ctx, sweep={IN_SCOPE: [{"port": 3306, "protocol": "tcp"}]})
    evidence = servicerecon.load_evidence(ctx)
    assert [(e.port, e.service) for e in evidence] == [(3306, None)]


def test_service_data_wins_over_sweep_for_the_same_port(make_context):
    ctx = make_context()
    _seed(
        ctx,
        services=[_service_host(port=3306, name="mysql")],
        sweep={IN_SCOPE: [{"port": 3306, "protocol": "tcp"}]},
    )
    evidence = servicerecon.load_evidence(ctx)
    assert len(evidence) == 1
    assert evidence[0].service == "mysql"


def test_nse_output_is_merged_onto_the_right_port(make_context):
    ctx = make_context()
    _seed(
        ctx,
        services=[_service_host(port=443, name="https")],
        scripts=[
            {
                "address": IN_SCOPE,
                "host_scripts": {"smb2-time": "date: 2024-05-20"},
                "ports": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "scripts": {"ssl-cert": "Subject: commonName=acme.vn"},
                    }
                ],
            }
        ],
    )
    evidence = servicerecon.load_evidence(ctx)[0]
    assert "ssl-cert" in evidence.scripts
    assert "smb2-time" in evidence.host_scripts
    assert evidence.script("ssl-cert").startswith("Subject:")


def test_out_of_scope_hosts_are_dropped_from_evidence(make_context):
    ctx = make_context()
    _seed(
        ctx,
        services=[_service_host(ip=OUT_OF_SCOPE), _service_host(ip=IN_SCOPE)],
    )
    assert [e.ip for e in servicerecon.load_evidence(ctx)] == [IN_SCOPE]


def test_closed_ports_are_not_evidence(make_context):
    ctx = make_context()
    write_json(
        ctx.paths.services,
        {
            "hosts": [
                {
                    "address": IN_SCOPE,
                    "ports": [
                        {"port": 22, "protocol": "tcp", "state": "closed",
                         "service": {"name": "ssh"}}
                    ],
                }
            ]
        },
    )
    assert servicerecon.load_evidence(ctx) == []


def test_stage_skips_when_there_is_nothing_to_analyse(make_context):
    with pytest.raises(StageSkipped, match="no open ports"):
        servicerecon.run(make_context())


# -- running analyzers ---------------------------------------------------


def test_findings_are_written_and_counted(make_context):
    ctx = make_context()
    ctx.config.servicerecon.allow_tls_probe = False
    _seed(
        ctx,
        services=[
            {
                "address": IN_SCOPE,
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "ssh", "product": "OpenSSH", "version": "6.6"},
                        "scripts": {
                            # Real ssh2-enum-algos layout: "name (count)", then
                            # one indented algorithm per line.
                            "ssh2-enum-algos": (
                                "  kex_algorithms (2)\n"
                                "      diffie-hellman-group1-sha1\n"
                                "      curve25519-sha256\n"
                                "  encryption_algorithms (2)\n"
                                "      3des-cbc\n"
                                "      aes256-ctr\n"
                            )
                        },
                    }
                ],
            }
        ],
    )
    result = servicerecon.run(ctx)
    payload = json.loads(ctx.paths.service_findings.read_text())

    assert result.counts["findings"] >= 1
    assert payload["services_analysed"] == 1
    keys = {f["key"] for r in payload["results"] for f in r["findings"]}
    assert "ssh.weak-kex" in keys
    assert "ssh.weak-cipher" in keys


def test_output_records_that_no_packets_were_sent(make_context):
    ctx = make_context()
    _seed(ctx, services=[_service_host()])
    servicerecon.run(ctx)
    payload = json.loads(ctx.paths.service_findings.read_text())
    assert "offline analysis" in payload["method"]


def test_a_failing_analyzer_does_not_stop_the_stage(make_context, monkeypatch):
    class Exploding:
        name = "boom"
        needs_probe = False

        def applies_to(self, evidence):
            return True

        def analyse(self, evidence):
            raise RuntimeError("analyzer bug")

    class Working:
        name = "fine"
        needs_probe = False

        def applies_to(self, evidence):
            return True

        def analyse(self, evidence):
            return [Finding("x.ok", "Something", "info", "A summary.")]

    monkeypatch.setattr(servicerecon, "build_analyzers", lambda _names: [Exploding(), Working()])
    ctx = make_context()
    _seed(ctx, services=[_service_host()])
    result = servicerecon.run(ctx)

    payload = json.loads(ctx.paths.service_findings.read_text())
    assert result.counts["findings"] == 1
    assert len(payload["errors"]) == 1
    assert "analyzer bug" in payload["errors"][0]


def test_tls_probe_is_not_offered_when_disabled(make_context, monkeypatch):
    seen: dict[str, object] = {}

    class Probing:
        name = "tls"
        needs_probe = True

        def applies_to(self, evidence):
            return True

        def analyse(self, evidence, probe=None):
            seen["probe"] = probe
            return []

    monkeypatch.setattr(servicerecon, "build_analyzers", lambda _names: [Probing()])
    ctx = make_context()
    ctx.config.servicerecon.allow_tls_probe = False
    _seed(ctx, services=[_service_host(port=443, name="https")])
    servicerecon.run(ctx)
    assert seen["probe"] is None


def test_dry_run_never_offers_a_probe(make_context, monkeypatch):
    seen: dict[str, object] = {}

    class Probing:
        name = "tls"
        needs_probe = True

        def applies_to(self, evidence):
            return True

        def analyse(self, evidence, probe=None):
            seen["probe"] = probe
            return []

    monkeypatch.setattr(servicerecon, "build_analyzers", lambda _names: [Probing()])
    ctx = make_context(dry_run=True)
    _seed(ctx, services=[_service_host(port=443, name="https")])
    servicerecon.run(ctx)
    assert seen["probe"] is None


# -- regrouping for the report ------------------------------------------


def test_findings_by_host_groups_and_annotates():
    payload = {
        "results": [
            {
                "analyzer": "tls",
                "ip": IN_SCOPE,
                "port": 443,
                "protocol": "tcp",
                "findings": [{"key": "tls.expired", "severity": "high", "title": "T"}],
            },
            {
                "analyzer": "ssh",
                "ip": IN_SCOPE,
                "port": 22,
                "protocol": "tcp",
                "findings": [{"key": "ssh.weak-kex", "severity": "medium", "title": "K"}],
            },
        ]
    }
    grouped = servicerecon.findings_by_host(payload)
    assert set(grouped) == {IN_SCOPE}
    assert {f["analyzer"] for f in grouped[IN_SCOPE]} == {"tls", "ssh"}
    assert all("port" in f for f in grouped[IN_SCOPE])


def test_top_findings_sorts_by_severity():
    payload = {
        "results": [
            {
                "analyzer": "a",
                "ip": "10.0.0.2",
                "port": 1,
                "findings": [
                    {"key": "k1", "severity": "info", "title": "i"},
                    {"key": "k2", "severity": "critical", "title": "c"},
                    {"key": "k3", "severity": "medium", "title": "m"},
                ],
            }
        ]
    }
    top = servicerecon.top_findings(payload)
    assert [f["severity"] for f in top] == ["critical", "medium", "info"]


def test_top_findings_respects_the_limit():
    payload = {
        "results": [
            {
                "analyzer": "a",
                "ip": "10.0.0.1",
                "port": 1,
                "findings": [
                    {"key": f"k{i}", "severity": "info", "title": "t"} for i in range(50)
                ],
            }
        ]
    }
    assert len(servicerecon.top_findings(payload, limit=5)) == 5


# -- registry ------------------------------------------------------------


def test_every_registered_analyzer_loads():
    analyzers = build_analyzers(None)
    assert [a.name for a in analyzers] == list(ANALYZER_NAMES)


def test_analyzers_honour_the_interface():
    for analyzer in build_analyzers(None):
        assert isinstance(analyzer.name, str) and analyzer.name
        assert isinstance(getattr(analyzer, "needs_probe", False), bool)
        assert callable(analyzer.applies_to)
        assert callable(analyzer.analyse)


def test_only_tls_may_open_a_connection():
    """Exactly one analyzer is allowed to touch the network; keep it that way."""
    probing = [a.name for a in build_analyzers(None) if getattr(a, "needs_probe", False)]
    assert probing == ["tls"]


def test_a_subset_can_be_selected_and_keeps_report_order():
    assert [a.name for a in build_analyzers(["ssh", "tls"])] == ["tls", "ssh"]


def test_unknown_analyzer_is_rejected():
    with pytest.raises(UnknownAnalyzer, match="unknown analyzer"):
        build_analyzers(["definitely-not-real"])


def test_validate_names_normalises_and_deduplicates():
    assert validate_names([" TLS ", "ssh", "tls"]) == ["tls", "ssh"]


def test_empty_selection_is_rejected():
    with pytest.raises(UnknownAnalyzer):
        validate_names([])


def test_config_rejects_an_unknown_analyzer():
    with pytest.raises(ConfigError, match="unknown analyzer"):
        Config.from_dict({"servicerecon": {"analyzers": ["nope"]}})


def test_config_accepts_a_valid_subset():
    config = Config.from_dict({"servicerecon": {"analyzers": ["TLS", "smb"]}})
    assert config.servicerecon.analyzers == ["tls", "smb"]


def test_stage_is_off_by_default():
    assert Config().stages.servicerecon is False


# -- base helpers --------------------------------------------------------


def test_finding_rejects_an_unknown_severity():
    with pytest.raises(ValueError, match="severity"):
        Finding("k", "T", "catastrophic", "s")


def test_dedupe_keeps_the_first_of_each_key_and_evidence():
    findings = [
        Finding("k", "T", "low", "s", evidence="e"),
        Finding("k", "T", "low", "s", evidence="e"),
        Finding("k", "T", "low", "s", evidence="other"),
    ]
    assert len(dedupe_findings(findings)) == 2


def test_severity_counts_omits_empty_bands():
    counts = severity_counts([Finding("k", "T", "high", "s")])
    assert counts == {"high": 1}


def test_evidence_script_lookup_prefers_an_exact_id():
    evidence = ServiceEvidence(
        ip=IN_SCOPE,
        port=443,
        scripts={"ssl-cert": "exact", "ssl-cert-intaddr": "prefix"},
    )
    assert evidence.script("ssl-cert") == "exact"


def test_evidence_script_falls_back_to_host_scripts():
    evidence = ServiceEvidence(ip=IN_SCOPE, port=445, host_scripts={"smb-os-discovery": "x"})
    assert evidence.script("smb-os-discovery") == "x"
    assert evidence.has_script("smb-os-discovery") is True
    assert evidence.script("nothing-here") is None
