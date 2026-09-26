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

# 5. Add nuclei network templates (rate-capped, explicit opt-in)
sudo netrecon scan --targets scope.txt --scripts --active
```

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
| 8 | Aggregation + reporting | — | `summary.json` + `report.md` |

Stages 4–7 read the previous stage's checkpoint and re-filter it through the scope, so no
stage can broaden the target set of the one before it. Stage 4 in particular scans **only
the discovered open ports** for each host — never a port range.

## Guardrails

These are enforced in code, not just in the config file, and are covered by
`tests/test_guardrails.py`:

- **Rate caps.** `limits.masscan_rate` defaults to **1000 pps**. A hard maximum of
  **20000 pps** is enforced in `netrecon/core/config.py`: a higher value is clamped and
  logged, never honoured. Anything above the 1000 pps default prints a prominent warning in
  the pre-flight summary. `nuclei_rate` is capped at 300 rps, `concurrency` at 64.
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
├── summary.json          # PRIMARY machine-readable aggregate
├── report.md             # host → ports → service/version → notable findings
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
  "totals":  { "in_scope_hosts": 254, "live_hosts": 31, "open_ports": 88, ... },
  "hosts": [
    { "ip": "10.10.10.5", "hostnames": ["web01"], "os_guess": "Linux 5.0 - 5.14 (95%)",
      "open_ports": [ { "port": 22, "protocol": "tcp", "service": "ssh",
                        "version": "OpenSSH 8.9p1 (Ubuntu Linux)", "scripts": {...} } ],
      "notes": ["`3306/tcp` MySQL exposed"], "nuclei_findings": [] }
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
pytest -q            # ~195 tests, no network access
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

Fixtures in `tests/fixtures/` are recorded tool output; subprocess calls are monkeypatched.

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
│   └── nuclei.py           # optional active stage
├── parse/
│   ├── nmap.py             # nmap XML -> dataclasses
│   └── masscan.py          # masscan JSON/list, naabu JSON
└── report/
    └── build.py            # summary.json + report.md
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
- `report.md` reports exposure observations. Nothing in it is a confirmed vulnerability;
  triage is yours.
