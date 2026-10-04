"""HTML rendering for the run report.

The output is a single self-contained file: inline CSS and a few lines of inline
JavaScript for the tab switching and filter box, and **no external resources**.
A report that fetched a stylesheet or font would phone home from whatever
machine it is opened on, which is not acceptable for engagement output that may
be read on a client's network or attached to a deliverable.

Every value interpolated into the document goes through :func:`esc`. Report data
includes strings that came from scanned hosts - page titles, HTTP headers,
JavaScript fragments - so all of it is treated as untrusted and escaped.
"""

from __future__ import annotations

from html import escape
from typing import Any

from netrecon.report.categories import Category

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _dict_entries(value: Any) -> list[dict[str, Any]]:
    """Only the mapping entries of *value*, or nothing."""
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def esc(value: Any) -> str:
    """HTML-escape any value, including quotes. ``None`` renders as a dash."""
    if value is None:
        return "&mdash;"
    return escape(str(value), quote=True)


STYLE = """
:root {
  --bg: #f7f8fa; --panel: #ffffff; --border: #d8dce3; --text: #1b1f27;
  --muted: #5b6372; --accent: #1f5f9e; --accent-soft: #e8f0f8;
  --crit: #8c1d18; --high: #b3451f; --med: #8a6500; --low: #3a6186; --info: #4a5260;
  --ok: #1f6b3a; --code-bg: #f1f3f6;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14171c; --panel: #1b1f26; --border: #2e343e; --text: #e6e9ee;
    --muted: #9aa3b2; --accent: #74b2e8; --accent-soft: #1e2a36;
    --crit: #f08b84; --high: #f0a978; --med: #ddc06a; --low: #8fb8dd; --info: #a7b0bf;
    --ok: #7fc99a; --code-bg: #232931;
  }
}
:root[data-theme="dark"] {
  --bg: #14171c; --panel: #1b1f26; --border: #2e343e; --text: #e6e9ee;
  --muted: #9aa3b2; --accent: #74b2e8; --accent-soft: #1e2a36;
  --crit: #f08b84; --high: #f0a978; --med: #ddc06a; --low: #8fb8dd; --info: #a7b0bf;
  --ok: #7fc99a; --code-bg: #232931;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px 16px 72px; }
header.page { border-bottom: 2px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }
header.page h1 { margin: 0 0 4px; font-size: 25px; letter-spacing: -0.01em; }
.sub { color: var(--muted); font-size: 13.5px; }
.notice {
  background: var(--accent-soft); border-left: 4px solid var(--accent);
  padding: 11px 14px; margin: 16px 0; border-radius: 0 5px 5px 0; font-size: 13.5px;
}
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 18px 0; }
.stat { background: var(--panel); border: 1px solid var(--border); border-radius: 7px; padding: 11px 13px; }
.stat .n { font-size: 23px; font-weight: 650; font-variant-numeric: tabular-nums; }
.stat .k { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .055em; }
nav.tabs { display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid var(--border); margin: 22px 0 0; }
nav.tabs button {
  background: none; border: 1px solid transparent; border-bottom: none; color: var(--muted);
  padding: 9px 15px; font-size: 14px; font-weight: 550; cursor: pointer;
  border-radius: 6px 6px 0 0; font-family: inherit;
}
nav.tabs button:hover { color: var(--text); }
nav.tabs button[aria-selected="true"] {
  background: var(--panel); border-color: var(--border); color: var(--accent);
  margin-bottom: -1px; padding-bottom: 10px;
}
.panel[hidden] { display: none; }
section.card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 18px; margin: 16px 0;
}
section.card > h3 { margin: 0 0 3px; font-size: 17px; }
section.card > h3 .port-n { color: var(--muted); font-weight: 450; font-size: 14px; }
h2.section { font-size: 19px; margin: 26px 0 2px; }
h4 { margin: 16px 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
a { color: var(--accent); }
a:hover { text-decoration: none; }
/* Cards scroll their own overflow so the page never scrolls sideways. */
section.card { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13.5px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .045em; font-weight: 600; }
tbody tr:last-child td { border-bottom: none; }
td.num, th.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
code, .mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px;
  background: var(--code-bg); padding: 1px 5px; border-radius: 4px;
  overflow-wrap: anywhere;
}
td.mono, td code { overflow-wrap: anywhere; }
pre {
  background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 10px 12px; overflow-x: auto; font-size: 12.5px; margin: 8px 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre-wrap; word-break: break-word;
}
ul.notes { margin: 6px 0; padding-left: 20px; }
ul.notes li { margin: 3px 0; }
.tag {
  display: inline-block; padding: 1.5px 8px; border-radius: 11px; font-size: 11.5px;
  border: 1px solid var(--border); color: var(--muted); margin: 2px 4px 2px 0; white-space: nowrap;
}
.tag.web { border-color: var(--accent); color: var(--accent); }
.sev { font-weight: 600; text-transform: uppercase; font-size: 11.5px; letter-spacing: .03em; }
.sev-critical { color: var(--crit); } .sev-high { color: var(--high); }
.sev-medium { color: var(--med); } .sev-low { color: var(--low); }
.sev-info, .sev-unknown { color: var(--info); }
.muted { color: var(--muted); }
.ok { color: var(--ok); }
.empty { color: var(--muted); font-style: italic; padding: 10px 0; }
details { margin: 7px 0; }
summary { cursor: pointer; font-size: 13.5px; font-weight: 550; padding: 3px 0; }
summary:hover { color: var(--accent); }
input.filter {
  width: 100%; max-width: 380px; padding: 8px 11px; margin: 14px 0 4px;
  border: 1px solid var(--border); border-radius: 6px; background: var(--panel);
  color: var(--text); font: inherit; font-size: 13.5px;
}
.toc { display: flex; flex-wrap: wrap; gap: 5px; margin: 10px 0 2px; }
.toc a {
  font-size: 12.5px; color: var(--accent); text-decoration: none;
  border: 1px solid var(--border); border-radius: 5px; padding: 3px 9px;
}
.toc a:hover { background: var(--accent-soft); }
footer.page { margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--border);
  color: var(--muted); font-size: 12.5px; }
@media (max-width: 640px) {
  .wrap { padding: 16px 16px 56px; }
  table { font-size: 12.5px; } th, td { padding: 6px 6px; }
  header.page h1 { font-size: 21px; }
  .grid { grid-template-columns: repeat(auto-fit, minmax(118px, 1fr)); }
  nav.tabs button { padding: 8px 11px; font-size: 13px; }
}
"""

SCRIPT = """
(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll('nav.tabs button'));
  function show(id) {
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-target') === id;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      var panel = document.getElementById(t.getAttribute('data-target'));
      if (panel) { panel.hidden = !on; }
    });
    try { location.hash = id; } catch (e) { /* ignore */ }
  }
  tabs.forEach(function (t) {
    t.addEventListener('click', function () { show(t.getAttribute('data-target')); });
  });
  var initial = (location.hash || '').replace('#', '');
  show(tabs.some(function (t) { return t.getAttribute('data-target') === initial; })
    ? initial : (tabs[0] && tabs[0].getAttribute('data-target')));

  Array.prototype.forEach.call(document.querySelectorAll('input.filter'), function (box) {
    box.addEventListener('input', function () {
      var q = box.value.toLowerCase();
      var scope = document.getElementById(box.getAttribute('data-scope'));
      if (!scope) { return; }
      Array.prototype.forEach.call(scope.querySelectorAll('[data-search]'), function (el) {
        el.hidden = q !== '' && el.getAttribute('data-search').indexOf(q) === -1;
      });
    });
  });
})();
"""


def render_html(
    payload: dict[str, Any],
    hosts: list[Any],
    categories: list[Category],
    webrecon: dict[str, Any] | None = None,
    service_findings: dict[str, Any] | None = None,
) -> str:
    """Render the complete report as one self-contained HTML document."""
    # Same defensive reads as the markdown renderer: see the note there.
    run = payload.get("run") or {}
    totals = payload.get("totals") or {}
    title = f"netrecon report - {run.get('name')}"

    tabs: list[tuple[str, str]] = [
        ("tab-overview", "Overview"),
        ("tab-hosts", f"By host ({len(hosts)})"),
        ("tab-categories", f"By service ({len(categories)})"),
    ]
    # Both checkpoints are read back from disk and may hold anything; keep only
    # the mapping entries so a truncated file degrades instead of raising.
    findings_results = _dict_entries((service_findings or {}).get("results"))
    finding_total = sum(len(_dict_entries(r.get("findings"))) for r in findings_results)
    if finding_total:
        tabs.insert(1, ("tab-findings", f"Findings ({finding_total})"))
    web_results = _dict_entries((webrecon or {}).get("results"))
    if web_results:
        tabs.append(("tab-web", f"Web recon ({len(web_results)})"))

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{esc(title)}</title>",
        f"<style>{STYLE}</style>",
        "</head><body><div class='wrap'>",
        "<header class='page'>",
        "<h1>netrecon report</h1>",
        f"<div class='sub'>Run <code>{esc(run.get('name'))}</code> &middot; started "
        f"{esc(run.get('started_at'))} &middot; report generated "
        f"{esc(payload.get('generated_at'))} (UTC)</div>",
        "</header>",
        "<div class='notice'><strong>Authorised engagement output.</strong> Everything "
        "below is an observation about an exposed service, not a verified "
        "vulnerability. netrecon performs no authentication testing, brute forcing or "
        "exploitation; all findings need manual triage.</div>",
        _render_stats(totals),
        "<nav class='tabs' role='tablist'>",
    ]
    for target, label in tabs:
        parts.append(
            f"<button type='button' role='tab' data-target='{esc(target)}' "
            f"aria-selected='false'>{esc(label)}</button>"
        )
    parts.append("</nav>")

    parts.append(f"<div class='panel' id='tab-overview' hidden>{_render_overview(payload)}</div>")
    if finding_total:
        parts.append(
            "<div class='panel' id='tab-findings' hidden>"
            + _render_findings(service_findings or {})
            + "</div>"
        )
    parts.append(f"<div class='panel' id='tab-hosts' hidden>{_render_hosts(hosts)}</div>")
    parts.append(
        f"<div class='panel' id='tab-categories' hidden>{_render_categories(categories)}</div>"
    )
    if web_results:
        parts.append(f"<div class='panel' id='tab-web' hidden>{_render_web(webrecon or {})}</div>")

    parts += [
        "<footer class='page'>",
        f"Generated by netrecon {esc(run.get('netrecon_version'))} &middot; "
        f"raw tool output under <code>nmap/</code> and <code>raw/</code> &middot; "
        f"machine-readable data in <code>summary.json</code>",
        "</footer>",
        "</div>",
        f"<script>{SCRIPT}</script>",
        "</body></html>",
    ]
    return "\n".join(parts)


def _render_stats(totals: dict[str, Any]) -> str:
    cells = [
        ("In-scope addresses", totals.get("in_scope_hosts", 0)),
        ("Live hosts", totals.get("live_hosts", 0)),
        ("Hosts with open ports", totals.get("hosts_with_open_ports", 0)),
        ("Open ports", totals.get("open_ports", 0)),
        ("Services identified", totals.get("services_identified", 0)),
        ("Notable observations", totals.get("notable_observations", 0)),
    ]
    if totals.get("web_endpoints"):
        cells.append(("Web endpoints", totals.get("web_endpoints")))
    if totals.get("js_secret_candidates"):
        cells.append(("JS secret candidates", totals.get("js_secret_candidates")))
    if totals.get("service_findings"):
        cells.append(("Service findings", totals.get("service_findings")))
    if totals.get("js_pii_candidates"):
        cells.append(("PII candidates", totals.get("js_pii_candidates")))
    if totals.get("paths_accessible"):
        cells.append(("Paths accessible", totals.get("paths_accessible")))
    if totals.get("technologies"):
        cells.append(("Technologies", totals.get("technologies")))
    if totals.get("cve_matches"):
        cells.append(("CVE correlations", totals.get("cve_matches")))
    if totals.get("nuclei_findings"):
        cells.append(("nuclei findings", totals.get("nuclei_findings")))

    out = ["<div class='grid'>"]
    for key, value in cells:
        out.append(
            f"<div class='stat'><div class='n'>{esc(value)}</div>"
            f"<div class='k'>{esc(key)}</div></div>"
        )
    out.append("</div>")
    return "".join(out)


def _render_overview(payload: dict[str, Any]) -> str:
    run = payload.get("run") or {}
    scope = payload.get("scope") or {}
    limits = payload.get("limits") or {}

    rows = [
        ("Run name", run.get("name")),
        ("Output directory", run.get("directory")),
        ("Scope file", scope.get("source")),
        ("In-scope hosts", f"{scope.get('total_hosts')} "
                           f"(IPv4 {scope.get('ipv4_hosts')}, IPv6 {scope.get('ipv6_hosts')})"),
        ("Address range", f"{scope.get('first')} .. {scope.get('last')}"),
        ("Scope entries", f"{scope.get('entries')} accepted, "
                          f"{scope.get('rejected_lines')} rejected"),
        ("Raw sockets", "yes" if run.get("raw_sockets") else "no (connect-scan fallback)"),
        ("Sweep backend", payload.get("sweep_backend") or "n/a"),
        ("Sweep rate cap", f"{limits.get('sweep_rate_pps')} pps"),
        ("nuclei rate cap", f"{limits.get('nuclei_rate_rps')} rps"),
        ("Concurrency", limits.get("concurrency")),
        ("nmap timing", f"-T{limits.get('nmap_timing')}"),
        ("Active stage (nuclei)", "enabled" if run.get("active_stage_enabled") else "disabled"),
        ("Web recon stage", "enabled" if run.get("web_stage_enabled") else "disabled"),
    ]
    if limits.get("webrecon_rate_rps"):
        rows.append(("Web recon rate cap", f"{limits['webrecon_rate_rps']} rps (GET only)"))

    out = ["<h2 class='section'>Run parameters</h2>", "<section class='card'><table><tbody>"]
    for key, value in rows:
        out.append(f"<tr><th style='width:34%'>{esc(key)}</th><td>{esc(value)}</td></tr>")
    out.append("</tbody></table></section>")

    out.append("<h2 class='section'>Stage timings</h2>")
    out.append(
        "<section class='card'><table><thead><tr><th>Stage</th><th>Status</th>"
        "<th class='num'>Duration (s)</th><th>Backend</th><th>Detail</th></tr></thead><tbody>"
    )
    for name, stage in (payload.get("stages") or {}).items():
        if name == "report":
            continue
        status = stage.get("status") or ""
        css = " class='ok'" if status == "completed" else " class='muted'"
        out.append(
            f"<tr><td><code>{esc(name)}</code></td><td{css}>{esc(status)}</td>"
            f"<td class='num'>{esc(stage.get('duration_seconds'))}</td>"
            f"<td>{esc(stage.get('backend'))}</td><td>{esc(stage.get('detail'))}</td></tr>"
        )
    out.append("</tbody></table></section>")
    out.append(_render_parameter_index(payload))
    return "".join(out)


def _render_parameter_index(payload: dict[str, Any]) -> str:
    """Every parameter the front-end sends, widest acceptance first."""
    parameters = (payload.get("web") or {}).get("parameters") or []
    if not parameters:
        return ""
    out = [
        f"<h2 class='section'>Parameter index ({len(parameters)})</h2>",
        "<section class='card'><div class='sub'>Names the front-end sends, ordered by "
        "how many endpoints accept each one. A plain wordlist is written to "
        "<code>parameters.txt</code>.</div>",
        "<table><thead><tr><th>Parameter</th><th>Kinds</th>"
        "<th class='num'>Endpoints</th><th class='num'>Occurrences</th>"
        "</tr></thead><tbody>",
    ]
    for parameter in parameters[:200]:
        out.append(
            f"<tr><td class='mono'>{esc(parameter.get('name'))}</td>"
            f"<td>{esc(', '.join(parameter.get('kinds') or []))}</td>"
            f"<td class='num'>{esc(parameter.get('endpoint_count'))}</td>"
            f"<td class='num'>{esc(parameter.get('occurrences'))}</td></tr>"
        )
    out.append("</tbody></table></section>")
    return "".join(out)


def _render_findings(payload: dict[str, Any]) -> str:
    """The cross-host findings view: everything the analyzers concluded."""
    results = _dict_entries(payload.get("results"))
    flat: list[dict[str, Any]] = []
    for result in results:
        for finding in _dict_entries(result.get("findings")):
            flat.append({**finding, **{
                "ip": result.get("ip"),
                "port": result.get("port"),
                "protocol": result.get("protocol"),
                "analyzer": result.get("analyzer"),
            }})
    if not flat:
        return "<p class='empty'>No service findings.</p>"

    flat.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity") or "info").lower(), 9),
            str(f.get("ip") or ""),
            f.get("port") or 0,
        )
    )
    by_severity = payload.get("by_severity") or {}

    out = [
        "<h2 class='section'>Service findings</h2>",
        "<div class='notice'>Derived offline from the <code>nmap -sV</code> and NSE "
        "output already collected - this analysis sent no packets. Severity is an "
        "<strong>exposure</strong> judgement, not an exploitability rating: it means "
        "\"an assessor should look at this\", never \"this host is exploitable\".</div>",
        "<div class='grid'>",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        if by_severity.get(severity):
            out.append(
                f"<div class='stat'><div class='n sev-{esc(severity)}'>"
                f"{esc(by_severity[severity])}</div>"
                f"<div class='k'>{esc(severity)}</div></div>"
            )
    out.append("</div>")

    out.append(
        "<input class='filter' type='search' data-scope='findings-list' "
        "placeholder='Filter by host, title, analyzer&hellip;' "
        "aria-label='Filter findings'>"
    )
    out.append("<div id='findings-list'><section class='card'>")
    out.append(
        "<table><thead><tr><th>Severity</th><th>Host</th><th class='num'>Port</th>"
        "<th>Finding</th><th>Analyzer</th></tr></thead><tbody>"
    )
    for finding in flat:
        severity = str(finding.get("severity") or "info").lower()
        haystack = " ".join(
            str(finding.get(k) or "")
            for k in ("ip", "title", "analyzer", "summary", "key")
        ).lower()
        out.append(
            f"<tr data-search=\"{esc(haystack)}\">"
            f"<td><span class='sev sev-{esc(severity)}'>{esc(severity)}</span></td>"
            f"<td><a href='#host-{esc(_slug(finding.get('ip')))}'>{esc(finding.get('ip'))}</a></td>"
            f"<td class='num'>{esc(finding.get('port'))}</td>"
            f"<td><strong>{esc(finding.get('title'))}</strong><br>"
            f"<span class='muted'>{esc(finding.get('summary'))}</span>"
        )
        if finding.get("evidence"):
            out.append(f"<details><summary>evidence</summary><pre>{esc(str(finding['evidence'])[:3000])}</pre></details>")
        if finding.get("recommendation"):
            out.append(f"<div class='sub'>&rarr; {esc(finding['recommendation'])}</div>")
        out.append(f"</td><td><code>{esc(finding.get('analyzer'))}</code></td></tr>")
    out.append("</tbody></table></section></div>")

    errors = payload.get("errors") or []
    if errors:
        out.append(
            f"<section class='card'><h3>Analyzer errors ({len(errors)})</h3><pre>"
            + esc("\n".join(errors))
            + "</pre></section>"
        )
    return "".join(out)


def _render_hosts(hosts: list[Any]) -> str:
    if not hosts:
        return "<p class='empty'>No hosts responded within the authorised scope.</p>"

    out = [
        "<h2 class='section'>Hosts</h2>",
        "<input class='filter' type='search' data-scope='hosts-list' "
        "placeholder='Filter by IP, hostname, service or port&hellip;' "
        "aria-label='Filter hosts'>",
        "<div class='toc'>",
    ]
    for host in hosts:
        out.append(f"<a href='#host-{esc(_slug(host.ip))}'>{esc(host.ip)}</a>")
    out.append("</div><div id='hosts-list'>")

    for host in hosts:
        haystack = " ".join(
            [host.ip, " ".join(host.hostnames)]
            + [
                f"{p.get('port')} {p.get('service') or ''} {p.get('version') or ''}"
                for p in host.open_ports
            ]
        ).lower()
        title = esc(host.ip)
        if host.hostnames:
            title += f" <span class='port-n'>({esc(', '.join(host.hostnames))})</span>"

        out.append(
            f"<section class='card' id='host-{esc(_slug(host.ip))}' "
            f"data-search=\"{esc(haystack)}\">"
        )
        out.append(f"<h3>{title}</h3>")

        meta: list[str] = [f"{len(host.open_ports)} open port(s)"]
        if host.os_guess:
            meta.append(f"OS: {host.os_guess}")
        if host.mac:
            meta.append(f"MAC: {host.mac}")
        out.append(f"<div class='sub'>{_dotted(meta)}</div>")

        if host.open_ports:
            out.append(
                "<table><thead><tr><th class='num'>Port</th><th>Proto</th>"
                "<th>Service</th><th>Version / banner</th></tr></thead><tbody>"
            )
            for port in host.open_ports:
                out.append(
                    f"<tr><td class='num'>{esc(port.get('port'))}</td>"
                    f"<td>{esc(port.get('protocol'))}</td>"
                    f"<td>{esc(port.get('service'))}</td>"
                    f"<td>{esc(port.get('version'))}</td></tr>"
                )
            out.append("</tbody></table>")
        else:
            out.append("<p class='empty'>No open ports in the scanned port set.</p>")

        script_rows = [
            (port, name, output)
            for port in host.open_ports
            for name, output in (port.get("scripts") or {}).items()
        ]
        if script_rows:
            out.append(f"<details><summary>NSE script output ({len(script_rows)})</summary>")
            for port, name, output in script_rows:
                out.append(
                    f"<h4><code>{esc(port.get('port'))}/{esc(port.get('protocol'))}</code> "
                    f"{esc(name)}</h4><pre>{esc((output or '').strip()[:4000])}</pre>"
                )
            out.append("</details>")

        if host.nuclei_findings:
            out.append("<h4>nuclei findings</h4><ul class='notes'>")
            for finding in sorted(
                host.nuclei_findings,
                key=lambda f: SEVERITY_ORDER.get(str(f.get("severity") or "unknown").lower(), 9),
            ):
                severity = str(finding.get("severity") or "unknown").lower()
                out.append(
                    f"<li><span class='sev sev-{esc(severity)}'>{esc(severity)}</span> "
                    f"{esc(finding.get('name') or finding.get('template'))} "
                    f"<code>{esc(finding.get('matched'))}</code></li>"
                )
            out.append("</ul>")

        if getattr(host, "service_findings", None):
            out.append(f"<h4>Service findings ({len(host.service_findings)})</h4>")
            out.append("<table><thead><tr><th>Severity</th><th class='num'>Port</th>"
                       "<th>Finding</th></tr></thead><tbody>")
            for finding in host.service_findings:
                severity = str(finding.get("severity") or "info").lower()
                out.append(
                    f"<tr><td><span class='sev sev-{esc(severity)}'>{esc(severity)}</span></td>"
                    f"<td class='num'>{esc(finding.get('port'))}</td>"
                    f"<td><strong>{esc(finding.get('title'))}</strong><br>"
                    f"<span class='muted'>{esc(finding.get('summary'))}</span></td></tr>"
                )
            out.append("</tbody></table>")

        if host.notes:
            out.append("<h4>Notable</h4><ul class='notes'>")
            for note in host.notes:
                out.append(f"<li>{_render_note(note)}</li>")
            out.append("</ul>")

        out.append("</section>")

    out.append("</div>")
    return "".join(out)


def _render_categories(categories: list[Category]) -> str:
    if not categories:
        return "<p class='empty'>No services to categorise.</p>"

    out = ["<h2 class='section'>Services by category</h2>", "<div class='toc'>"]
    for category in categories:
        out.append(
            f"<a href='#cat-{esc(category.key)}'>{esc(category.label)} "
            f"({len(category.entries)})</a>"
        )
    out.append("</div>")

    for category in categories:
        out.append(f"<section class='card' id='cat-{esc(category.key)}'>")
        out.append(
            f"<h3>{esc(category.label)} "
            f"<span class='port-n'>&mdash; {len(category.entries)} port(s) on "
            f"{category.host_count} host(s)</span></h3>"
        )
        out.append(f"<div class='sub'>{esc(category.description)}</div>")
        out.append(
            "<table><thead><tr><th>Host</th><th class='num'>Port</th><th>Proto</th>"
            "<th>Service</th><th>Version / banner</th></tr></thead><tbody>"
        )
        for entry in category.entries:
            label = esc(entry.ip)
            if entry.hostnames:
                label += f" <span class='muted'>({esc(', '.join(entry.hostnames))})</span>"
            out.append(
                f"<tr><td><a href='#host-{esc(_slug(entry.ip))}'>{label}</a></td>"
                f"<td class='num'>{esc(entry.port)}</td><td>{esc(entry.protocol)}</td>"
                f"<td>{esc(entry.service)}</td><td>{esc(entry.version)}</td></tr>"
            )
        out.append("</tbody></table>")

        notes = [note for entry in category.entries for note in entry.notes]
        if notes:
            out.append("<h4>Notable in this category</h4><ul class='notes'>")
            for note in dict.fromkeys(notes):
                out.append(f"<li>{_render_note(note)}</li>")
            out.append("</ul>")
        out.append("</section>")
    return "".join(out)


def _render_web(webrecon: dict[str, Any]) -> str:
    results = _dict_entries(webrecon.get("results"))
    limits = webrecon.get("limits") or {}

    out = [
        "<h2 class='section'>Web reconnaissance</h2>",
        _render_web_method_notice(limits),
        "<input class='filter' type='search' data-scope='web-list' "
        "placeholder='Filter by host, title, technology or path&hellip;' "
        "aria-label='Filter web endpoints'>",
        "<div id='web-list'>",
    ]

    for result in results:
        root = result.get("root") or {}
        totals = result.get("totals") or {}
        base = result.get("base_url") or f"{result.get('ip')}:{result.get('port')}"
        haystack = " ".join(
            [
                str(result.get("ip") or ""),
                str(result.get("port") or ""),
                str(root.get("title") or ""),
                " ".join(root.get("technologies") or []),
            ]
        ).lower()

        out.append(f"<section class='card' data-search=\"{esc(haystack)}\">")
        out.append(f"<h3><code>{esc(base)}</code></h3>")

        if result.get("error"):
            out.append(f"<p class='empty'>Not reachable: {esc(result['error'])}</p></section>")
            continue

        status = root.get("status")
        bits = [f"HTTP {status} {root.get('reason') or ''}".strip()]
        if root.get("title"):
            bits.append(f"title: {root['title']}")
        if root.get("redirect_to"):
            bits.append(f"redirects to {root['redirect_to']} (not followed)")
        out.append(f"<div class='sub'>{esc(' | '.join(bits))}</div>")

        technologies = _dict_entries(result.get("technologies"))
        if technologies:
            out.append(f"<h4>Technology stack ({len(technologies)})</h4><div>")
            for tech in technologies:
                label = tech.get("name", "")
                if tech.get("version"):
                    label = f"{label} {tech['version']}"
                title = f"{tech.get('source', '')} / {tech.get('confidence', '')}"
                out.append(
                    f"<span class='tag web' title='{esc(title)}'>{esc(label)}</span>"
                )
            out.append("</div>")
        elif root.get("technologies"):
            out.append("<h4>Technology hints</h4><div>")
            for tech in root["technologies"]:
                out.append(f"<span class='tag web'>{esc(tech)}</span>")
            out.append("</div>")

        cve_matches = _dict_entries(result.get("cve_matches"))
        if cve_matches:
            out.append(f"<h4>CVE correlations ({len(cve_matches)})</h4>")
            out.append(
                "<div class='sub'>Version-to-feed matches, <strong>not</strong> verified "
                "exploitable conditions. Confirm the exact build and patch level.</div>"
            )
            out.append(
                "<table><thead><tr><th>CVE</th><th class='num'>CVSS</th>"
                "<th>Technology</th><th>Summary</th></tr></thead><tbody>"
            )
            for match in cve_matches[:100]:
                severity = str(match.get("cvss_severity") or "unknown").lower()
                out.append(
                    f"<tr><td><code>{esc(match.get('cve_id'))}</code></td>"
                    f"<td class='num'><span class='sev sev-{esc(severity)}'>"
                    f"{esc(match.get('cvss_score'))}</span></td>"
                    f"<td>{esc(match.get('technology'))} {esc(match.get('version'))}</td>"
                    f"<td>{esc(str(match.get('summary') or '')[:300])}</td></tr>"
                )
            out.append("</tbody></table>")

        if root.get("disclosure_headers"):
            out.append("<h4>Version-disclosing headers</h4><table><tbody>")
            for name, value in root["disclosure_headers"].items():
                out.append(f"<tr><th style='width:30%'>{esc(name)}</th><td><code>{esc(value)}</code></td></tr>")
            out.append("</tbody></table>")

        if root.get("missing_security_headers"):
            out.append("<h4>Security headers not present</h4><div>")
            for name in root["missing_security_headers"]:
                out.append(f"<span class='tag'>{esc(name)}</span>")
            out.append("</div>")

        well_known = [w for w in (_dict_entries(result.get("well_known"))) if w.get("status") == 200]
        if well_known:
            out.append("<h4>Well-known files</h4>")
            for item in well_known:
                out.append(
                    f"<details><summary><code>{esc(item.get('path'))}</code> "
                    f"({esc(item.get('bytes'))} bytes)</summary>"
                    f"<pre>{esc((item.get('preview') or '')[:3000])}</pre></details>"
                )

        if root.get("form_actions"):
            out.append("<h4>Forms found (not submitted)</h4><div>")
            for action in root["form_actions"]:
                out.append(f"<span class='tag'>{esc(action)}</span>")
            out.append("</div>")

        if root.get("html_comments"):
            out.append(
                f"<details><summary>HTML comments ({len(root['html_comments'])})</summary><pre>"
                + esc("\n".join(root["html_comments"]))
                + "</pre></details>"
            )

        paths = _dict_entries(result.get("hidden_paths"))
        accessible = [p for p in paths if p.get("classification") == "accessible"]
        if paths:
            out.append(
                f"<h4>Paths checked ({len(accessible)} accessible of "
                f"{len(paths)} responding)</h4>"
            )
            out.append(
                "<table><thead><tr><th>Path</th><th class='num'>Status</th>"
                "<th>Result</th><th>Why it matters</th><th>Origin</th>"
                "</tr></thead><tbody>"
            )
            for path in paths[:150]:
                high = path.get("high_value")
                classification = str(path.get("classification") or "")
                css = "sev sev-high" if high and classification == "accessible" else "muted"
                out.append(
                    f"<tr><td><code>{esc(path.get('path'))}</code></td>"
                    f"<td class='num'>{esc(path.get('status'))}</td>"
                    f"<td class='{css}'>{esc(classification)}</td>"
                    f"<td>{esc(path.get('reason'))}</td>"
                    f"<td><span class='tag'>{esc(path.get('origin'))}</span></td></tr>"
                )
            out.append("</tbody></table>")

        out.append("<h4>JavaScript analysis</h4>")
        out.append(
            "<div class='sub'>"
            + _dotted(
                [
                    f"{totals.get('scripts_analysed', 0)} script(s) analysed",
                    f"{totals.get('js_endpoints', 0)} path(s) referenced",
                    f"{totals.get('secret_candidates', 0)} secret candidate(s)",
                ]
            )
            + "</div>"
        )

        javascript = result.get("javascript") or {}
        secrets = javascript.get("secret_candidates") or [
            secret
            for script in _dict_entries(result.get("scripts"))
            for secret in (script.get("secret_candidates") or [])
        ]
        if secrets:
            out.append(
                "<table><thead><tr><th>Kind</th><th>Name</th><th>Value (masked)</th>"
                "<th>Source</th><th class='num'>Line</th></tr></thead><tbody>"
            )
            for secret in secrets:
                out.append(
                    f"<tr><td><span class='sev sev-high'>{esc(secret.get('kind'))}</span></td>"
                    f"<td><code>{esc(secret.get('name'))}</code></td>"
                    f"<td class='mono'>{esc(secret.get('value'))}</td>"
                    f"<td class='mono'>{esc(_short(secret.get('source')))}</td>"
                    f"<td class='num'>{esc(secret.get('line'))}</td></tr>"
                )
            out.append("</tbody></table>")
            out.append(
                "<p class='sub'>Values are masked. The full response bodies are saved "
                "under <code>webrecon/</code> for manual verification.</p>"
            )

        pii = _dict_entries(javascript.get("pii_candidates"))
        if pii:
            summary = javascript.get("pii_summary") or {}
            out.append(f"<h4>Personal data candidates ({len(pii)})</h4>")
            out.append(
                "<div class='notice'>Values are masked. The count and the kind are the "
                "finding; the full data is in the saved bodies under <code>webrecon/</code>. "
                "Treat the run directory as personal data and dispose of it accordingly."
                "</div><div>"
            )
            for kind, count in sorted(summary.items()):
                out.append(f"<span class='tag'>{esc(kind)}: {esc(count)}</span>")
            out.append("</div>")
            out.append(
                "<table><thead><tr><th>Kind</th><th>Value (masked)</th>"
                "<th>Source</th><th class='num'>Line</th></tr></thead><tbody>"
            )
            for match in pii[:60]:
                out.append(
                    f"<tr><td><span class='sev sev-medium'>{esc(match.get('kind'))}</span></td>"
                    f"<td class='mono'>{esc(match.get('value'))}</td>"
                    f"<td class='mono'>{esc(_short(match.get('source')))}</td>"
                    f"<td class='num'>{esc(match.get('line'))}</td></tr>"
                )
            out.append("</tbody></table>")

        infrastructure = _dict_entries(javascript.get("infrastructure"))
        if infrastructure:
            out.append(f"<h4>Internal infrastructure referenced ({len(infrastructure)})</h4>")
            out.append("<table><thead><tr><th>Kind</th><th>Value</th><th>Source</th>"
                       "</tr></thead><tbody>")
            for match in infrastructure[:60]:
                out.append(
                    f"<tr><td><span class='sev sev-medium'>{esc(match.get('kind'))}</span></td>"
                    f"<td class='mono'>{esc(match.get('value'))}</td>"
                    f"<td class='mono'>{esc(_short(match.get('source')))}</td></tr>"
                )
            out.append("</tbody></table>")

        api_endpoints = result.get("api_endpoints") or []
        if api_endpoints:
            out.append(f"<h4>API surface reconstructed ({len(api_endpoints)})</h4>")
            out.append(
                "<div class='sub'>Signatures recovered from JavaScript call sites. "
                "Parameters are what the front-end sends, not a published schema.</div>"
            )
            out.append(
                "<table><thead><tr><th>Signature</th><th>Body parameters</th>"
                "<th>Path</th><th>Source</th></tr></thead><tbody>"
            )
            for endpoint in api_endpoints[:200]:
                out.append(
                    f"<tr><td class='mono'>{esc(endpoint.get('signature'))}</td>"
                    f"<td>{esc(', '.join(endpoint.get('body_params') or []) or '-')}</td>"
                    f"<td>{esc(', '.join(endpoint.get('path_params') or []) or '-')}</td>"
                    f"<td class='mono'>{esc(endpoint.get('source_label'))}</td></tr>"
                )
            out.append("</tbody></table>")

        api_paths = _dict_entries(javascript.get("endpoints"))
        if api_paths:
            out.append(
                f"<details><summary>API surface referenced in front-end code "
                f"({len(api_paths)})</summary>"
                "<table><thead><tr><th>Method</th><th>Path or URL</th></tr></thead><tbody>"
            )
            for endpoint in api_paths[:600]:
                out.append(
                    f"<tr><td>{esc(endpoint.get('method') or '')}</td>"
                    f"<td class='mono'>{esc(endpoint.get('value'))}</td></tr>"
                )
            out.append("</tbody></table></details>")

        referenced = javascript.get("hosts_referenced") or []
        if referenced:
            out.append(
                f"<details><summary>Hosts referenced by front-end code "
                f"({len(referenced)}) - out of scope, not contacted</summary><pre>"
                + esc("\n".join(referenced))
                + "</pre></details>"
            )

        source_maps = javascript.get("source_maps") or []
        if source_maps:
            out.append(
                "<details><summary>Source maps referenced "
                f"({len(source_maps)})</summary><pre>"
                + esc("\n".join(source_maps))
                + "</pre></details>"
            )

        script_errors = [s for s in _dict_entries(result.get("scripts")) if s.get("error")]
        if script_errors:
            out.append(
                f"<details><summary>Scripts that could not be fetched "
                f"({len(script_errors)})</summary><pre>"
                + esc("\n".join(f"{s.get('source')}: {s.get('error')}" for s in script_errors))
                + "</pre></details>"
            )

        out.append("</section>")

    failures = webrecon.get("failures") or []
    if failures:
        out.append(
            f"<section class='card'><h3>Unreachable endpoints ({len(failures)})</h3><pre>"
            + esc("\n".join(failures))
            + "</pre></section>"
        )

    out.append("</div>")
    return "".join(out)


def _dotted(pieces: list[str]) -> str:
    """Join already-unescaped pieces with a middot separator, escaping each."""
    return " &middot; ".join(esc(piece) for piece in pieces)


def _render_web_method_notice(limits: dict[str, Any]) -> str:
    """State exactly what was requested, including whether paths were probed.

    This text has to track the run's real configuration. A report that claims
    "no path brute forcing" after the operator passed --hidden-paths would
    misrepresent what was done to the target, which is the one thing a
    reconnaissance report must never do.
    """
    parts = [
        "<div class='notice'>Read-only: one HTTP <code>GET</code> per URL, no redirects "
        "followed, no form submission, no authentication. Requests were capped at "
        f"{esc(limits.get('rate_per_second'))} rps with "
        f"{esc(limits.get('max_scripts_per_endpoint'))} script(s) per endpoint."
    ]
    if limits.get("hidden_paths"):
        parts.append(
            " <strong>Path probing was enabled</strong> (<code>--hidden-paths</code>): up "
            f"to {esc(limits.get('max_hidden_paths'))} curated path(s) per endpoint were "
            "requested, so this run left 404s in the target's access log. The list is a "
            "curated set of commonly exposed files, not a brute-force wordlist."
        )
    else:
        parts.append(
            " No path guessing: the only paths requested were <code>/</code>, the "
            "well-known files, assets the page linked, and paths the site published "
            "in its own robots.txt and sitemap.xml."
        )
    parts.append("</div>")
    return "".join(parts)


def _render_note(note: str) -> str:
    """Render a note, turning its backtick spans into <code>."""
    pieces = str(note).split("`")
    rendered = []
    for index, piece in enumerate(pieces):
        if index % 2 == 1:
            rendered.append(f"<code>{esc(piece)}</code>")
        else:
            rendered.append(esc(piece))
    return "".join(rendered)


def _short(value: Any, limit: int = 70) -> str:
    text = str(value or "")
    return text if len(text) <= limit else "..." + text[-(limit - 3):]


def _slug(ip: str) -> str:
    return str(ip).replace(":", "-").replace(".", "-")
