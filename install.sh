#!/usr/bin/env bash
#
# Install netrecon's external dependencies on a Debian/Ubuntu x86_64 host.
#
#   nmap, masscan, fping   -> apt
#   naabu, nuclei          -> go install (optional, skipped if go is absent)
#
# Usage:
#   ./install.sh                 # everything: apt, Python package, go tools, templates
#   ./install.sh --no-go         # skip naabu/nuclei
#   ./install.sh --no-python     # skip pip install of netrecon itself
#   ./install.sh --no-templates  # skip the nuclei template fetch (needs network)
#   ./install.sh --caps          # also grant CAP_NET_RAW to nmap/masscan/fping
#
# The go tools are symlinked into /usr/local/bin. Without that they land in
# $GOBIN, which is not on PATH for a login shell and not on sudo's secure_path,
# so netrecon reports them MISSING immediately after installing them.
#
set -euo pipefail

WITH_GO=1
WITH_PYTHON=1
WITH_CAPS=0
WITH_TEMPLATES=1

for arg in "$@"; do
  case "$arg" in
    --no-go) WITH_GO=0 ;;
    --no-python) WITH_PYTHON=0 ;;
    --no-templates) WITH_TEMPLATES=0 ;;
    --caps) WITH_CAPS=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || die "not root and sudo is unavailable"
  SUDO="sudo"
fi

command -v apt-get >/dev/null 2>&1 || die "this installer targets Debian/Ubuntu (apt-get not found)"

log "installing apt packages: nmap masscan fping libcap2-bin"
$SUDO apt-get update -qq
DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y --no-install-recommends \
  nmap masscan fping libcap2-bin ca-certificates

if [[ "$WITH_PYTHON" -eq 1 ]]; then
  if command -v python3 >/dev/null 2>&1; then
    log "installing the netrecon Python package"
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    # --break-system-packages is needed on PEP 668 distros; fall back without it.
    python3 -m pip install --break-system-packages -e . 2>/dev/null \
      || python3 -m pip install -e . \
      || warn "pip install failed; run netrecon with 'python3 -m netrecon.cli' instead"
  else
    warn "python3 not found; skipping the Python package"
  fi
fi

if [[ "$WITH_GO" -eq 1 ]]; then
  if command -v go >/dev/null 2>&1; then
    export GOBIN="${GOBIN:-$HOME/go/bin}"
    mkdir -p "$GOBIN"
    log "installing naabu -> $GOBIN"
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      || warn "naabu install failed (naabu needs libpcap-dev for SYN scans)"
    log "installing nuclei -> $GOBIN"
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      || warn "nuclei install failed"
    # $GOBIN is not on PATH for a login shell, and sudo resets PATH to
    # secure_path, so a raw-socket run as root would not see these at all.
    # A symlink into /usr/local/bin is on both.
    for tool in naabu nuclei; do
      if [[ -x "$GOBIN/$tool" ]]; then
        $SUDO ln -sf "$GOBIN/$tool" "/usr/local/bin/$tool" \
          && log "  linked $tool into /usr/local/bin" \
          || warn "  could not link $tool; add $GOBIN to PATH instead"
      fi
    done
  else
    warn "go is not installed; skipping naabu and nuclei"
    warn "  apt-get install -y golang-go   # then re-run ./install.sh"
  fi
fi

if [[ "$WITH_CAPS" -eq 1 ]]; then
  log "granting CAP_NET_RAW so raw-socket stages work without sudo"
  for tool in nmap masscan fping; do
    path="$(command -v "$tool" 2>/dev/null || true)"
    if [[ -n "$path" ]]; then
      $SUDO setcap cap_net_raw,cap_net_admin+eip "$path" \
        && log "  setcap on $path" \
        || warn "  setcap failed on $path (not supported on this filesystem?)"
    fi
  done
fi

if [[ "$WITH_TEMPLATES" -eq 1 ]] && command -v nuclei >/dev/null 2>&1; then
  # nuclei ships no templates and exits with
  #   "Could not run nuclei: no templates provided for scan"
  # until they are fetched, so netrecon's --active stage is dead on a fresh
  # install without this. This is the one step that reaches the network; it
  # downloads nuclei's own template repository and nothing else.
  log "fetching nuclei templates (downloads from github.com)"
  nuclei -update-templates -silent >/dev/null 2>&1 || true
  # nuclei exits 0 even when the fetch fails (a blocked api.pdtm.sh, a
  # firewall, a rate limit), leaving an empty template directory, so the exit
  # status cannot be trusted. Count the templates instead: without them
  # nuclei dies with "no templates provided for scan" and --active is dead.
  TEMPLATE_DIR="$(nuclei -silent -tv 2>/dev/null | tail -1 || true)"
  [[ -d "${TEMPLATE_DIR:-}" ]] || TEMPLATE_DIR="$HOME/nuclei-templates"
  TEMPLATE_COUNT=0
  if [[ -d "$TEMPLATE_DIR" ]]; then
    TEMPLATE_COUNT="$(find "$TEMPLATE_DIR" -name '*.yaml' 2>/dev/null | wc -l)"
  fi
  if [[ "$TEMPLATE_COUNT" -gt 0 ]]; then
    log "  $TEMPLATE_COUNT template(s) in $TEMPLATE_DIR"
  else
    warn "  NO templates were fetched: 'netrecon scan --active' will fail"
    warn "  nuclei reports success even when this fails, so check by hand:"
    warn "    nuclei -update-templates   # needs github.com and api.pdtm.sh"
    warn "  every other stage works without it; only --active needs templates"
  fi
else
  [[ "$WITH_TEMPLATES" -eq 0 ]] \
    && warn "skipping templates; --active needs 'nuclei -update-templates' first"
fi

log "verifying installation"
if command -v netrecon >/dev/null 2>&1; then
  netrecon check-tools || true
else
  python3 -m netrecon.cli check-tools || true
fi

log "done. Remember: only scan hosts you have written authorisation to test."
