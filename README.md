# netrecon

Scope-enforced, rate-capped network reconnaissance for **authorised** engagements.

`netrecon` wraps `nmap`, `masscan`/`naabu`, `fping` and (optionally) `nuclei` behind one
pipeline whose central invariant is simple:

> **Nothing is ever scanned unless it is in the explicit, expanded in-scope set derived
> from your targets file.**

Every target list handed to an external tool is produced by the scope layer. Tool output is
re-filtered on the way back in, so a host that answers but was never authorised is dropped
rather than followed up.

> **Authorisation.** This tool sends scan traffic to whatever you point it at. Only use it
> against systems you have written permission to test, within the agreed dates and scope.
> Scanning outside an agreed scope is unlawful in most jurisdictions. netrecon prints an
> authorisation reminder and the effective scope and rate caps before every run and refuses
> to start non-interactively without `--yes`.

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Scope enforcement and CIDR expansion](#scope-enforcement-and-cidr-expansion)
- [Pipeline](#pipeline)
- [Web recon and JavaScript analysis](#web-recon-and-javascript-analysis)
- [Per-service deep analysis](#per-service-deep-analysis)
- [CVE correlation](#cve-correlation)
- [Reports](#reports)
- [Guardrails](#guardrails)
- [Privileges](#privileges)
- [Configuration](#configuration)
- [CLI reference](#cli-reference)
- [Output layout](#output-layout)
- [Checkpoint and resume](#checkpoint-and-resume)
- [Docker](#docker)
- [Development and tests](#development-and-tests)
- [Module layout](#module-layout)
- [Limitations](#limitations)

---

## Install

Target platform: **Linux x86_64**, **Python 3.11+**.

```bash
git clone <this repo> && cd synack_net_recon
./install.sh              # apt: nmap masscan fping; go: naabu nuclei; pip: netrecon
netrecon check-tools      # verify
```

`install.sh` flags:

| Flag | Effect |
| --- | --- |
| `--no-go` | Skip `naabu` and `nuclei` |
| `--no-python` | Skip `pip install -e .` |
| `--caps` | `setcap cap_net_raw,cap_net_admin+eip` on nmap/masscan/fping so raw scans work without `sudo` |

Manual install:

```bash
sudo apt-get install -y nmap masscan fping libcap2-bin
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip install -e .
```

Only `nmap` is strictly required — every other tool has a fallback (see
[Pipeline](#pipeline)). Running without installing the package also works:
`python3 -m netrecon.cli ...`.

## Quick start

```bash
cat > scope.txt <<'EOF'
# Engagement ACME-2024-11, authorised 2024-05-01 .. 2024-05-31
10.10.10.0/24
10.20.0.5
10.20.0.40-10.20.0.48
EOF

# 1. Check the scope expands to what you expect - sends no packets
netrecon show-scope --targets scope.txt

# 2. Plan the run - still sends no packets
netrecon scan --targets scope.txt --dry-run

# 3. Run it (prompts for authorisation confirmation)
sudo netrecon scan --targets scope.txt

# 4. With safe NSE scripts and banners
sudo netrecon scan --targets scope.txt --scripts --banners

# 5. Web recon + JavaScript analysis on any in-scope HTTP(S) port
sudo netrecon scan --targets scope.txt --scripts --web

# 6. The full deep-recon pass: per-service analysis, path probing, CVE feed
sudo netrecon scan --targets scope.txt --scripts --web \
    --service-recon --hidden-paths --cve-feed ./nvd-recent.json

# 6. Add nuclei network templates (rate-capped, explicit opt-in)
sudo netrecon scan --targets scope.txt --scripts --active
```

Each run writes `report.html` (per host **and** per service category, plus the web
recon findings) next to `report.md` and `summary.json`.

## Scope enforcement and CIDR expansion

### Parsing

The targets file is line-oriented. `#` starts a comment, blank lines are ignored, and each
remaining line must be one of:

| Form | Example | Notes |
| --- | --- | --- |
| Single IP | `10.20.0.5` | IPv4 or IPv6 |
| CIDR | `10.10.10.0/24` | Non-aligned prefixes are normalised (`10.0.0.5/29` → `10.0.0.0/29`) |
| Inclusive range | `10.20.0.40-10.20.0.48` | Both endpoints must be the same family |

**Hostnames are rejected.** A name cannot be shown to be in scope without DNS resolution,
and the targets file does not authorise scanning whatever that name happens to resolve to
today. Rejected lines are reported with their line number and reason, in the pre-flight
summary and in `netrecon show-scope`, so a typo is visible rather than silent.

### Expansion

Each accepted entry expands to concrete addresses:

- `/32` and `/31` (and `/128`, `/127`): every address is used.
- Wider **IPv4** prefixes: the network and broadcast addresses are excluded, matching what
  nmap and masscan treat as hosts. `include_network_broadcast: true` opts back in.
- **IPv6** prefixes: expanded in full — there is no broadcast address, and `::0` is a valid
  anycast target.
- Results are de-duplicated and sorted numerically (`10.0.0.3` before `10.0.0.20`).
- If the total exceeds `scope.max_hosts` (default 65536) the run **fails at parse time**
  rather than part way through. A stray `/8` is a typo, not a plan.

### Enforcement

The expanded set is a `frozenset` of `ipaddress` objects. **Membership is tested against
that same set** — not against the original CIDR list — so what the tools receive and what
enforcement checks cannot drift apart. Two distinct paths exist, deliberately:

| Method | Used for | Behaviour on an out-of-scope address |
| --- | --- | --- |
| `Scope.enforce(candidates)` | Data coming back from **tools and files** | Dropped, counted, logged. Untrusted input must not crash the run, and must not widen it. |
| `Scope.enforce_strict(candidates)` | Targets originating **inside netrecon** | Raises `ScopeViolation`. An out-of-scope address here is a bug, so it stops the run. |

`Scope.write_targets()` is the only supported way to hand targets to a subprocess; it runs
`enforce_strict` and writes nothing if any address fails. Every stage therefore re-checks
scope, which covers the realistic failure modes:

- a tool reports a host that was never in its input (broadcast replies, rewritten addresses,
  a misconfigured router);
- `live_hosts.txt` or `open_ports.json` is hand-edited between stages;
- a checkpoint is resumed against a different targets file — refused via a SHA-256
  fingerprint of the expanded set.

The expanded set is also snapshotted to `scope.txt` in the run directory, so a report can
always be audited against exactly what was authorised.

## Pipeline

Stages are modular, individually toggleable, and resumable.

| # | Stage | Tool (privileged → fallback) | Notes |
| --- | --- | --- | --- |
| 1 | Parse & expand input | — | Builds the in-scope set; rejects everything else |
| 2 | Host discovery | `fping` → `nmap -sn` | `--skip-discovery` treats the whole scope as live |
| 3 | Fast port sweep | `masscan` → `naabu` → `nmap -sS`/`-sT` | Rate-capped |
| 4 | Service / version detection | `nmap -sV` | **Only** on ports the sweep found open |
| 5 | OS detection + banners | `nmap -O`, NSE `banner` | `--os-detect` (needs raw sockets), `--banners` |
| 6 | Safe NSE scripts | `nmap --script` | `--scripts`; `default`+`discovery`, forced `and safe` |
| 7 | nuclei network templates | `nuclei` | `--active` only; rate-capped |
| 8 | Web recon + JS analysis | (stdlib HTTP) | `--web` only; GET only, rate-capped |
| 9 | Per-service deep analysis | (offline) | `--service-recon`; sends no packets |
| 10 | Aggregation + reporting | — | `summary.json`, `report.md`, `report.html` |

Stages 4–7 read the previous stage's checkpoint and re-filter it through the scope, so no
stage can broaden the target set of the one before it. Stage 4 in particular scans **only
the discovered open ports** for each host — never a port range.

## Web recon and JavaScript analysis

`--web` turns on a stage that looks at any in-scope TCP port identified as HTTP(S) — by
service name from `nmap -sV`, or by port number when `-sV` did not run. It is **read-only**
and its boundaries are the point of the design:

**What it does**

- One HTTP `GET` of `/` per endpoint, then `GET /robots.txt` and `GET /sitemap.xml`.
- Records the status line, response headers, page title, `<meta generator>`, HTML comments,
  form actions (recorded, never submitted), technology hints, version-disclosing headers,
  and which common security headers are absent.
- Collects `<script src=…>` references **that point at the same in-scope endpoint**, fetches
  each with a `GET`, and pattern-matches the body for API paths, source maps, and strings
  shaped like embedded credentials.
- Inline `<script>` blocks are analysed with no extra request.

**What it never does**

| Boundary | Why |
| --- | --- |
| GET only — no POST/PUT/DELETE, no form submission | This is reconnaissance, not testing |
| No authentication, no cookie jar, no credential handling | Nothing netrecon finds is ever used to log in |
| No redirect following | A `Location` is recorded; a redirect cannot walk the scan off the authorised endpoint |
| No fuzzing, ever | No parameter mutation, no injection payloads, under any flag |
| Path probing is opt-in | By default the only paths requested are `/`, the two well-known files, assets the page linked, and paths the site published in robots.txt / sitemap.xml. `--hidden-paths` adds a curated list — see below |
| No third-party fetches | A script on a CDN or another host is **not** downloaded — that address is not in scope |
| Scope re-checked per endpoint | `enforce_strict` runs immediately before the socket opens; the URL host is always the in-scope IP literal, never a name |
| No proxy | An empty `ProxyHandler` disables `*_PROXY` env vars so scan traffic goes straight to the target |

**Caps** (all in `webrecon:`, all clamped in code): 100 endpoints per run, 25 scripts per
endpoint, 120 curated paths per endpoint (hard max 400), 2 MiB per response (hard max
16 MiB), 5 requests/second (hard max 50, warns above 10), 10 s per request.

### What gets collected

- **Both schemes.** Each open web port is tried over http *and* https rather than guessing
  from the port number — TLS on 8080 and cleartext on 443 are common enough that guessing
  loses whole services. The wrong scheme fails on the first request.
- **Tech stack with versions.** From response headers, `<meta generator>`, framework
  cookies, markup markers, JS bundle filenames (`jquery-3.4.1.min.js` → jQuery 3.4.1) and
  nmap's own CPEs. Each detection carries a confidence and the string it came from.
- **Source maps.** `.map` files referenced by scripts are fetched and their
  `sourcesContent` analysed — the original unminified sources, which routinely contain
  things the bundle does not.
- **Hidden files and folders** (`--hidden-paths`). A curated ~120-entry list of
  commonly exposed paths: `.git/HEAD`, `.env`, `appsettings.json`, `/actuator/env`,
  backups, dumps, `swagger.json`, `/server-status`, editor and CI leftovers. Each entry
  carries *why it matters*, and the result is classified `accessible` / `protected` /
  `redirected`. **This is path probing**: it is off by default, announced in the pre-flight
  summary, and will appear as 404s in the target's access log. It is capped at 400 entries
  in code and is not, and must not become, a brute-force wordlist.

### JavaScript analysis

`netrecon/analyze/jsdata.py` runs over every asset — the page, inline scripts, linked
scripts and source-map sources:

| Extracted | Detail |
| --- | --- |
| **API surface** | Paths and absolute URLs, with the HTTP method where the call site reveals it (`axios.post(...)`, `fetch(..., {method})`, `xhr.open("PUT", ...)`). Template paths (`/users/${id}`) are kept. Static assets are excluded. |
| **Secrets** | AWS/Google/Slack/GitHub/GitLab/Stripe/Twilio/SendGrid/npm/OpenAI key shapes, JWTs, private-key headers, credentials in URLs, connection strings, and `api_key = "…"` assignments |
| **PII** | Emails, phone numbers, credit cards (**Luhn-validated**), IBAN, SSN and national-ID shapes |
| **Infrastructure** | Internal hostnames (`.internal`, `.corp`, `staging.`, `jenkins.`…), private addresses, cloud metadata endpoints |
| **Other** | Source maps, developer comments (TODO/FIXME/"do not ship"), every host referenced |

**Everything sensitive is masked by default.** A secret renders as
`9f2b********e8 (len 32)`, an email as `al*****@acme.vn`, a card as `************1111`.
The full bodies are saved under `webrecon/` for verification. For PII the *count and kind*
are the finding — a bundle containing 4,000 customer addresses is the thing to report;
printing those addresses into a deliverable just moves the breach. `redact_secrets: false`
unmasks and warns loudly in the pre-flight summary.

False positives are filtered hard but not eliminated: placeholders (`your_api_key_here`,
`${API_KEY}`, the documented AWS example key, low-entropy fillers) are dropped, cards must
pass Luhn, IP addresses are not phone numbers, and a dotted identifier is only a hostname if
its last label is a real suffix — so `axios.post` and `ops.team@acme.vn` do not become hosts.
Treat every remaining hit as a lead to check.

**Hosts discovered in front-end code are reported, never contacted.** A hostname found in a
bundle is outside the authorised IP scope until you put it in the scope file. netrecon lists
it under "Hosts referenced by front-end code — out of scope, not contacted" and stops there.

## Per-service deep analysis

`--service-recon` turns raw tool text into structured findings. It **sends no packets**: it
re-reads `services.json` and `scripts.json` and analyses what is already there, so it is
cheap, repeatable, and works offline against an old run directory via `netrecon report`.

| Analyzer | Looks for |
| --- | --- |
| `tls` | Expired / not-yet-valid / expiring certificates, self-signed, hostname mismatch, weak signature algorithms, RSA < 2048, over-long validity, clock skew |
| `smb` | Signing not required, SMBv1 enabled, anonymous shares, guest access, end-of-support Windows, OS/domain/FQDN for pivoting |
| `database` | Unauthenticated access (only on positive proof), exposed engines, readable database names, version age, missing transport encryption |
| `ssh` | Weak host keys (DSA, RSA < 2048), weak KEX/cipher/MAC, SSHv1, outdated OpenSSH |
| `snmp` | Readable with the default community, system information, interface / process / software enumeration, v1/v2c in use |
| `dns` | Open recursion, version disclosure, cache snooping, SRV records |
| `mail` | Missing STARTTLS, cleartext auth offered, VRFY/EXPN, NTLM disclosure, open relay (only on positive proof) |
| `http` | Dangerous methods, exposed `.git`, config backups, open proxy, technology stack, version disclosure |

Severity is an **exposure** judgement — "an assessor should look at this today" — never an
exploitability claim. Every finding quotes the tool output it came from, so a reader can
check the conclusion without rescanning. Findings that the evidence does not support are not
emitted: an open 161/udp does not become "readable with the default community", and an open
3306 does not become "no authentication".

The one exception to "no packets" is the TLS analyzer, which may open a single connection
per endpoint when `--scripts` did not run and no `ssl-cert` output exists. That is
`allow_tls_probe` in the config, and the address is re-checked with `enforce_strict` before
the socket opens.

## CVE correlation

`--cve-feed <file>` correlates detected product versions against a CVE feed **you supply as
a local file**. This is deliberate:

- **netrecon ships no CVE data and makes no network request to fetch any.** Hardcoding a
  CVE list would put stale, unverifiable claims into a penetration-test report.
- Supported feed shapes: NVD JSON 2.0, NVD JSON 1.1, and a simple
  `{"entries": [{"cve", "cpe", "version_start_including", "version_end_excluding", "cvss",
  "severity", "summary"}]}` format.
- Version ranges are honoured (`versionStartIncluding` / `versionEndExcluding` and friends).
  A `*` version with no range never matches — that would flood the report.

Results are labelled, in every output, as **correlation, not verification**: a match means
"this version appears in a feed entry", never "this host is exploitable". Backported
vendor patches and coarse CPE ranges both produce false positives, so confirm the exact
build and patch level before reporting anything.

Get a feed from <https://nvd.nist.gov/vuln/data-feeds> and point `--cve-feed` at it.

**Secret candidates.** Strings matching AWS/Google/Slack/GitHub/Stripe key shapes, JWTs,
private-key headers, credentials in URLs, and `api_key = "…"` style assignments are
reported with the value **masked** (`9f2b********e8 (len 32)`) plus the file and line. The
full response body is saved under `webrecon/` so you can verify by hand. Obvious
placeholders (`your_api_key_here`, `${API_KEY}`, the documented AWS example key, low-entropy
values) are filtered out. These patterns produce false positives by design — treat every hit
as a lead to check, not a finding. `redact_secrets: false` writes values in full and makes
the run directory sensitive; it warns loudly in the pre-flight summary.

TLS certificates are not verified by default, because in-scope hosts routinely present
self-signed or expired certificates and failing closed would hide the service entirely.

## Reports

Every run writes three views of the same data:

| File | Audience |
| --- | --- |
| `summary.json` | Machines. The primary format; everything else is derived from it |
| `report.md` | Terminal, diffs, pasting into notes |
| `report.html` | A single self-contained page for reading and sharing |

`report.html` has four tabs:

1. **Overview** — run parameters, scope bounds, rate caps, per-stage timings.
2. **By host** — each host with its ports, versions, NSE output, nuclei findings and notes,
   with a live filter box.
3. **By service** — the same ports regrouped into categories: web, databases, remote access,
   file sharing, directory, mail, management, messaging, infrastructure, other. Service name
   from `-sV` wins; the port table is only a fallback, so a web server on 3306 is reported as
   a web service. Rows link back to the host section.
4. **Web recon** — per endpoint: status, title, technologies, disclosure and missing security
   headers, well-known files, forms found, and the JavaScript analysis.

The page has **no external resources** — styles and scripts are inline, so opening it on a
client network does not phone home. Everything interpolated into it is HTML-escaped: page
titles, banners and headers come from scanned hosts, and a report that executed a scanned
host's markup when an analyst opened it would be a vulnerability in the tooling. There are
tests for exactly that.

Regenerate the reports from an existing run directory without rescanning:

```bash
netrecon report results/acme/20240520T101320Z
```

## Guardrails

These are enforced in code, not just in the config file, and are covered by
`tests/test_guardrails.py`:

- **Rate caps.** `limits.masscan_rate` defaults to **1000 pps**. A hard maximum of
  **20000 pps** is enforced in `netrecon/core/config.py`: a higher value is clamped and
  logged, never honoured. Anything above the 1000 pps default prints a prominent warning in
  the pre-flight summary. `nuclei_rate` is capped at 300 rps, `webrecon.rate_per_second` at
  50 rps, `concurrency` at 64.
- **No intrusive NSE.** The categories `intrusive`, `brute`, `dos`, `exploit`, `malware`,
  `vuln`, `fuzzer`, `external`, `broadcast` and `auth` are rejected by config and by flag.
  Only `default`, `discovery`, `safe` and `version` may be selected, and the expression
  handed to nmap always ANDs in `safe` and negates every forbidden category:

  ```
  (default or discovery) and safe and not (auth or broadcast or brute or dos or exploit
    or external or fuzzer or intrusive or malware or vuln)
  ```

  Run `netrecon show-policy` to print this. `--script-args` is deliberately not exposed, so
  credentials, wordlists and write operations cannot be passed through.
- **No intrusive nuclei templates.** Template paths containing `fuzzing`, `dos`, `brute`,
  `default-logins` or `takeovers` are refused, as is any path traversal.
- **Authorisation reminder.** Printed before scanning, with the effective scope bounds, host
  count, rate caps, enabled stages, privilege state and rejected scope lines. Interactive
  runs prompt for confirmation; non-interactive runs (no TTY) **refuse to start** without
  `--yes`.
- **No shell.** Every subprocess is invoked with an argv list and `shell=False`, so no
  target or port value can be interpreted as shell syntax.
- **Read-only web stage.** GET only, no redirect following, no form submission, no path
  brute forcing, no third-party fetches. See
  [Web recon and JavaScript analysis](#web-recon-and-javascript-analysis).
- **Report output is escaped.** Scanned hosts control the strings that end up in
  `report.html`; all of it is HTML-escaped, and the page loads no external resources.
- **No destructive actions.** netrecon reads; it never authenticates, brute forces, exploits
  or writes to a target. `report.md` says so, because findings are exposure observations, not
  verified vulnerabilities.

## Privileges

Raw-socket stages (`masscan`, `nmap -sS`, `nmap -O`, `fping` ICMP) need **root** or
**`CAP_NET_RAW`**. netrecon probes once at startup — `os.geteuid()` plus the `CapEff` mask in
`/proc/self/status` — and reports the result in the pre-flight summary.

Without raw sockets it **degrades gracefully** rather than failing:

| Stage | Privileged | Unprivileged fallback |
| --- | --- | --- |
| Discovery | `fping` ICMP echo | `nmap -sn` (TCP connect probes) |
| Sweep | `masscan` SYN scan | `naabu -scan-type c` or `nmap -sT` connect scan |
| OS detection | `nmap -O` | Skipped, with a warning |

Connect scans are slower, more visible in target logs, and distinguish filtered ports less
well. To get the privileged path:

```bash
sudo netrecon scan --targets scope.txt            # run as root
# or grant capabilities once:
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v fping)"
# or: ./install.sh --caps
```

Asking explicitly for a privileged backend without the privileges is an error, not a silent
downgrade: `sweep.backend: masscan` unprivileged fails with a message telling you what to do.

## Configuration

`configs/default.yaml` is loaded automatically when it exists; override with
`--config path.yaml`. Unknown keys are rejected rather than ignored, so a misspelling cannot
silently disable a guardrail.

```yaml
run_name: default
output_dir: results

limits:
  masscan_rate: 1000        # pps; hard max 20000, warns above 1000
  nuclei_rate: 50           # rps; hard max 300
  concurrency: 8            # worker threads; hard max 64
  nmap_timing: 3            # nmap -T
  host_timeout_seconds: 900
  stage_timeout_seconds: 7200

stages:
  discovery: true
  sweep: true
  services: true
  os_detect: false          # needs raw sockets
  scripts: false            # --scripts
  nuclei: false             # --active

scope:
  max_hosts: 65536
  include_network_broadcast: false

ports:
  sweep: 21-23,25,53,80,...  # curated TCP set
  sweep_full: 1-65535        # --full-ports
  udp: 53,67,123,137,161,500,1900,5353

discovery:
  method: auto              # auto | fping | nmap | skip
  assume_live_on_empty: false

sweep:
  backend: auto             # auto | masscan | naabu | nmap
  udp: false

services:
  version_intensity: 5
  banner_grab: false        # --banners

scripts:
  categories: [default, discovery]

nuclei:
  templates: [network/]
  severity: info,low,medium,high,critical
```

CLI flags override the config file, and the result is re-validated (so clamping and warnings
reflect what you actually asked for).

## CLI reference

```
netrecon scan          Run the pipeline
netrecon check-tools   Report installed tools, versions and privilege state
netrecon show-scope    Parse and expand a targets file without scanning
netrecon show-policy   Print the NSE category policy and effective expression
netrecon report        Rebuild report.md / summary.json from a run directory
```

`netrecon scan` options:

| Flag | Meaning |
| --- | --- |
| `-t, --targets PATH` | Targets file (required) |
| `-c, --config PATH` | YAML config |
| `-o, --output-dir DIR` | Override `output_dir` |
| `--run-name NAME` | Override `run_name` |
| `--rate N` | Sweep pps (clamped to the hard max) |
| `--concurrency N` | Worker threads |
| `-p, --ports SPEC` | Override the TCP sweep ports |
| `--full-ports` | Sweep `1-65535` |
| `--scripts` | Enable safe NSE scripts |
| `--os-detect` | Enable OS detection (needs raw sockets) |
| `--banners` | Grab banners via the safe NSE `banner` script |
| `--active` | Enable the nuclei stage |
| `--web` | Enable read-only web recon + JavaScript analysis (GET only) |
| `--skip-discovery` | Treat every in-scope address as live |
| `--stages LIST` | Stage allowlist, e.g. `discovery,sweep` |
| `--resume` / `--resume-dir DIR` | Resume the latest / a specific run |
| `--dry-run` | Plan the run, send no packets |
| `-y, --yes` | Skip the authorisation prompt (required when stdin is not a TTY) |
| `-v/-q` | Verbose / quiet console logging |

Exit codes: `0` success, `2` usage or config error, `3` a stage failed, `4` aborted by the
operator.

## Output layout

```
results/<run_name>/<UTC-timestamp>/
├── live_hosts.txt        # one in-scope live host per line
├── open_ports.json       # sweep results, grouped by host
├── services.json         # nmap -sV results (+ merged NSE output)
├── scripts.json          # NSE stage output and the expression used
├── nuclei.json           # nuclei JSONL (only with --active)
├── nuclei_summary.json   # finding counts by severity
├── webrecon.json         # web recon + JS analysis (only with --web)
├── webrecon/             # saved response bodies and fetched .js, per endpoint
├── summary.json          # PRIMARY machine-readable aggregate
├── report.md             # host → ports → service/version → notable findings
├── report.html           # self-contained: by host, by service category, web recon
├── run.log               # structured JSONL: every command, count and timing
├── state.json            # checkpoint: per-stage status, counts, durations
├── preflight.json        # scope, config, tools and privileges as run
├── scope.txt             # snapshot of the expanded in-scope set
├── nmap/                 # nmap -oA output: .xml, .nmap, .gnmap per host/stage
├── raw/                  # raw masscan / naabu / fping output
└── targets/              # the scope-enforced target files given to each tool
```

`summary.json` is the primary machine-readable format:

```jsonc
{
  "generated_at": "...", "run": {...}, "scope": {...}, "limits": {...},
  "stages":  { "sweep": { "status": "completed", "duration_seconds": 12.4, "counts": {...} } },
  "totals":  { "in_scope_hosts": 254, "live_hosts": 31, "open_ports": 88,
               "service_categories": 5, "web_endpoints": 12,
               "js_secret_candidates": 3, ... },
  "categories": [ { "key": "web", "label": "Web services", "host_count": 9,
                    "port_count": 12, "entries": [ ... ] } ],
  "hosts": [
    { "ip": "10.10.10.5", "hostnames": ["web01"], "os_guess": "Linux 5.0 - 5.14 (95%)",
      "open_ports": [ { "port": 22, "protocol": "tcp", "service": "ssh",
                        "version": "OpenSSH 8.9p1 (Ubuntu Linux)", "scripts": {...} } ],
      "categories": ["web", "database"],
      "notes": ["`3306/tcp` MySQL exposed"], "nuclei_findings": [],
      "web_endpoints": [ { "base_url": "http://10.10.10.5:80", "status": 200,
                           "title": "Acme Portal", "technologies": ["React"],
                           "missing_security_headers": ["content-security-policy"],
                           "secret_candidates": 1 } ] }
  ]
}
```

## Checkpoint and resume

Each stage records its status, counts, durations, backend and output paths in `state.json`
(written atomically). `--resume` picks up the latest run for the run name; `--resume-dir DIR`
targets a specific one. Completed stages are skipped, so an interrupted sweep does not mean
re-running discovery, and a failed `--scripts` stage does not mean re-running `-sV`.

Resume refuses to proceed if the targets file changed since the run started — the scope
fingerprint would no longer match what earlier stages authorised. Start a new run instead.

## Docker

```bash
docker build -t netrecon:latest .

# Raw-socket stages need NET_RAW (and NET_ADMIN for masscan):
docker run --rm \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/scope.txt:/scope/scope.txt:ro" \
  -v "$PWD/results:/data/results" \
  netrecon:latest scan --targets /scope/scope.txt --yes
```

Without `--cap-add=NET_RAW` the container still works and degrades to connect scans, as
described in [Privileges](#privileges). `--net=host` may be needed to reach targets on the
host's networks. The image bundles nmap, masscan, fping, naabu and nuclei.

## Development and tests

```bash
pip install -e '.[dev]'
pytest -q            # ~1000 tests, no network access
ruff check .
```

The suite performs **no live scanning**. Coverage focuses on the parts where a bug becomes a
safety problem:

| File | Covers |
| --- | --- |
| `tests/test_scope.py` | CIDR/range expansion, rejection, enforcement, fingerprints |
| `tests/test_parse_nmap.py` | nmap XML parsing, from recorded fixtures |
| `tests/test_parse_masscan.py` | masscan JSON/list and naabu JSON, including truncated output |
| `tests/test_guardrails.py` | Rate clamping, NSE policy, template policy, privilege detection |
| `tests/test_stage_scope_enforcement.py` | Every stage re-filters its inputs; tampered checkpoints |
| `tests/test_state_and_report.py` | Checkpoint/resume, pre-flight banner, report aggregation |
| `tests/test_categories.py` | Service categorisation and the per-category grouping |
| `tests/test_webrecon.py` | JS analysis, secret masking, and that the web stage stays on the authorised endpoint |
| `tests/test_report_html.py` | HTML structure, no external resources, escaping of hostile host-supplied strings |

Fixtures in `tests/fixtures/` are recorded tool output; subprocess calls are monkeypatched,
and the web stage's HTTP client is replaced with a fake that records every URL it is asked
for - so the "only these paths may be requested" guarantee is asserted, not assumed.

## Module layout

```
netrecon/
├── cli.py                  # typer CLI
├── core/
│   ├── scope.py            # parsing, CIDR expansion, enforcement  <- the invariant
│   ├── config.py           # config loading, validation, rate clamping
│   ├── runner.py           # subprocess execution, RunContext, RunPaths
│   ├── pipeline.py         # pre-flight banner, stage sequencing, checkpointing
│   ├── state.py            # checkpoint/resume (state.json)
│   ├── privileges.py       # root / CAP_NET_RAW detection
│   ├── tools.py            # external tool discovery and versions
│   ├── logging_setup.py    # console + JSONL logging, timers
│   └── jsonio.py           # atomic JSON writes
├── stages/
│   ├── discovery.py        # fping / nmap -sn
│   ├── sweep.py            # masscan / naabu / nmap
│   ├── services.py         # nmap -sV, OS detection, banners
│   ├── scripts.py          # safe NSE policy and execution
│   ├── nuclei.py           # optional active stage
│   ├── webrecon.py         # GET-only web recon + JS analysis
│   ├── wellknown.py        # the curated path list (deliberately not a wordlist)
│   └── servicerecon.py     # offline per-service analysis
├── analyze/
│   ├── base.py             # Finding / ServiceEvidence / Analyzer interface
│   ├── registry.py         # which analyzers exist, listed explicitly
│   ├── tls.py  smb.py  database.py  ssh.py
│   ├── snmp.py  dns.py  mail.py  httpsvc.py
│   ├── techstack.py        # product + version + CPE fingerprinting
│   ├── cve.py              # offline CVE feed correlation
│   └── jsdata.py           # API / secrets / PII / infrastructure from front-end code
├── parse/
│   ├── nmap.py             # nmap XML -> dataclasses
│   └── masscan.py          # masscan JSON/list, naabu JSON
└── report/
    ├── build.py            # summary.json + report.md
    ├── categories.py       # service -> category mapping and grouping
    └── html.py             # self-contained report.html
```

## Limitations

- Linux only. Privilege detection reads `/proc/self/status`; the wrapped tools are packaged
  for Debian/Ubuntu.
- No DNS. Hostnames are rejected by design, and `-n` is passed to nmap, so reverse names do
  not appear in reports.
- UDP support is intentionally minimal (`sweep.udp`, a small port set): UDP scanning is slow
  and easy to overdo against a client network.
- IPv6 works throughout, but a large IPv6 prefix will hit `scope.max_hosts` — list the hosts
  or ranges you actually have.
- The reports hold exposure observations. Nothing in them is a confirmed vulnerability;
  triage is yours.
- Web recon reads only `/` and what that page links. It does not crawl, so an application
  whose routes are all behind a login or a client-side router will show little beyond the
  JavaScript bundle - which is usually where the interesting paths are anyway.
- JS secret and PII patterns are regex-based. They will produce false positives and will
  miss anything obfuscated or assembled at runtime. Verify every candidate against the
  saved body before it reaches a deliverable.
- Hidden-path probing checks a curated list, not every possible path. A negative result
  means "none of these ~120 paths responded", not "nothing is exposed".
- CVE correlation is only as good as the feed you supply, and matches by version string.
  Backported vendor patches make it over-report; coarse CPE ranges make it both over- and
  under-report. It is a triage aid, not a vulnerability assessment.
- The run directory can end up holding personal data and credential material pulled from
  the target's front-end. Treat it as engagement-sensitive and dispose of it accordingly.
