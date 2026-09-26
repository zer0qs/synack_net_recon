#!/usr/bin/env bash
#
# Install netrecon's external dependencies on a Debian/Ubuntu x86_64 host.
#
#   nmap, masscan, fping   -> apt
#   naabu, nuclei          -> go install (optional, skipped if go is absent)
#
# Usage:
#   ./install.sh                 # apt packages + Python package + optional go tools
#   ./install.sh --no-go         # skip naabu/nuclei
#   ./install.sh --no-python     # skip pip install of netrecon itself
#   ./install.sh --caps          # also grant CAP_NET_RAW to nmap/masscan/fping
#
set -euo pipefail

WITH_GO=1
WITH_PYTHON=1
WITH_CAPS=0

for arg in "$@"; do
  case "$arg" in
    --no-go) WITH_GO=0 ;;
    --no-python) WITH_PYTHON=0 ;;
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
    case ":$PATH:" in
      *":$GOBIN:"*) ;;
      *) warn "add $GOBIN to PATH so netrecon can find naabu/nuclei" ;;
    esac
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

log "verifying installation"
if command -v netrecon >/dev/null 2>&1; then
  netrecon check-tools || true
else
  python3 -m netrecon.cli check-tools || true
fi

log "done. Remember: only scan hosts you have written authorisation to test."
