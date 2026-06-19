#!/usr/bin/env bash
# =============================================================================
# zeek-install.sh — Install Zeek LTS on Ubuntu 20.04 / 22.04 / 24.04
#                                        or Debian 11 / 12
#
# Usage:
#   sudo bash ml/zeek/zeek-install.sh [--iface <interface>]
#
# What this script does:
#   1. Detects the OS release and maps it to the Zeek OBS repository.
#   2. Adds the Zeek GPG key and apt source.
#   3. Installs zeek-lts (current LTS: 6.x).
#   4. Configures ZeekControl (node.cfg, networks.cfg).
#   5. Installs the SecureCloud-BD local.zeek policy.
#   6. Adds /opt/zeek/bin to /etc/profile.d so zeekctl is on PATH.
#   7. Prints next-step instructions.
#
# Idempotent: running the script twice is safe.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZEEK_PREFIX="/opt/zeek"
ZEEK_SITE="${ZEEK_PREFIX}/share/zeek/site"
ZEEK_ETC="${ZEEK_PREFIX}/etc"
LOCAL_ZEEK_SRC="${SCRIPT_DIR}/zeek-config/local.zeek"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo "[zeek-install] $*"; }
die()  { echo "[zeek-install] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" &>/dev/null || die "Required command not found: $1"; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

[[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

IFACE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface) IFACE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: sudo bash $0 [--iface <network-interface>]"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# Auto-detect primary interface if not specified
if [[ -z "${IFACE}" ]]; then
    IFACE="$(ip route | awk '/^default/{print $5; exit}')"
    [[ -n "${IFACE}" ]] || die "Could not auto-detect default interface. Pass --iface <name>."
    log "Auto-detected network interface: ${IFACE}"
fi

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

need lsb_release

OS_ID="$(lsb_release -si)"
OS_CODENAME="$(lsb_release -sc)"

case "${OS_ID}:${OS_CODENAME}" in
    Ubuntu:focal)    OBS_OS="xUbuntu_20.04" ;;
    Ubuntu:jammy)    OBS_OS="xUbuntu_22.04" ;;
    Ubuntu:noble)    OBS_OS="xUbuntu_24.04" ;;
    Debian:bullseye) OBS_OS="Debian_11"     ;;
    Debian:bookworm) OBS_OS="Debian_12"     ;;
    *)
        die "Unsupported OS: ${OS_ID} ${OS_CODENAME}.
Supported: Ubuntu 20.04/22.04/24.04, Debian 11/12."
        ;;
esac

OBS_BASE="https://download.opensuse.org/repositories/security:/zeek/${OBS_OS}"
log "OS: ${OS_ID} ${OS_CODENAME} → OBS repo: ${OBS_OS}"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

log "Installing prerequisites…"
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl \
    gnupg2 \
    apt-transport-https \
    ca-certificates \
    lsb-release \
    iproute2

# ---------------------------------------------------------------------------
# Add Zeek OBS repository
# ---------------------------------------------------------------------------

APT_KEY="/etc/apt/trusted.gpg.d/security_zeek.gpg"
APT_LIST="/etc/apt/sources.list.d/security-zeek.list"

if [[ ! -f "${APT_KEY}" ]]; then
    log "Importing Zeek GPG key…"
    curl -fsSL "${OBS_BASE}/Release.key" \
        | gpg --dearmor -o "${APT_KEY}"
fi

if [[ ! -f "${APT_LIST}" ]]; then
    log "Adding Zeek apt repository…"
    echo "deb ${OBS_BASE}/ /" > "${APT_LIST}"
fi

apt-get update -qq

# ---------------------------------------------------------------------------
# Install Zeek
# ---------------------------------------------------------------------------

if command -v zeek &>/dev/null; then
    INSTALLED_VER="$(zeek --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)"
    log "Zeek already installed: ${INSTALLED_VER} — skipping package install."
else
    log "Installing zeek-lts…"
    apt-get install -y --no-install-recommends zeek-lts
fi

# Verify
ZEEK_BIN="${ZEEK_PREFIX}/bin/zeek"
[[ -x "${ZEEK_BIN}" ]] || die "Zeek binary not found at ${ZEEK_BIN}."
log "Zeek binary: $(${ZEEK_BIN} --version 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# PATH setup
# ---------------------------------------------------------------------------

PROFILE_D="/etc/profile.d/zeek.sh"
if [[ ! -f "${PROFILE_D}" ]]; then
    log "Adding ${ZEEK_PREFIX}/bin to PATH via ${PROFILE_D}"
    cat > "${PROFILE_D}" <<'EOF'
# Zeek — added by zeek-install.sh
export PATH="/opt/zeek/bin:${PATH}"
EOF
fi

export PATH="${ZEEK_PREFIX}/bin:${PATH}"

# ---------------------------------------------------------------------------
# Configure ZeekControl
# ---------------------------------------------------------------------------

log "Writing ZeekControl configuration…"

# node.cfg — single standalone sensor
cat > "${ZEEK_ETC}/node.cfg" <<EOF
# ZeekControl node configuration — generated by zeek-install.sh
[zeek]
type=standalone
host=localhost
interface=${IFACE}
EOF

# networks.cfg — local address ranges to mark as "local"
if [[ ! -s "${ZEEK_ETC}/networks.cfg" ]]; then
    cat > "${ZEEK_ETC}/networks.cfg" <<'EOF'
# List of local networks (CIDR notation)
# Adjust to match your environment.
10.0.0.0/8          Private class A
172.16.0.0/12       Private class B
192.168.0.0/16      Private class C
EOF
fi

# zeekctl.cfg — set log rotation interval and log directory
ZEEKCTL_CFG="${ZEEK_ETC}/zeekctl.cfg"
grep -q "^LogRotationInterval" "${ZEEKCTL_CFG}" \
    || echo "LogRotationInterval = 3600" >> "${ZEEKCTL_CFG}"
grep -q "^LogDir" "${ZEEKCTL_CFG}" \
    || echo "LogDir = /opt/zeek/logs" >> "${ZEEKCTL_CFG}"

# ---------------------------------------------------------------------------
# Install SecureCloud-BD local.zeek policy
# ---------------------------------------------------------------------------

if [[ -f "${LOCAL_ZEEK_SRC}" ]]; then
    log "Installing SecureCloud-BD local.zeek → ${ZEEK_SITE}/local.zeek"
    cp "${LOCAL_ZEEK_SRC}" "${ZEEK_SITE}/local.zeek"
else
    log "WARNING: ${LOCAL_ZEEK_SRC} not found — leaving default local.zeek in place."
fi

# ---------------------------------------------------------------------------
# Python dependencies for SecureCloud-BD Zeek scripts
# ---------------------------------------------------------------------------

log "Installing Python dependencies for Zeek integration scripts…"
python3 -m pip install --quiet \
    watchdog>=4.0.0 \
    requests>=2.32.0 \
    urllib3>=2.2.0 \
    2>/dev/null || log "pip install failed — install manually: pip3 install watchdog requests"

# ---------------------------------------------------------------------------
# Install and deploy
# ---------------------------------------------------------------------------

log "Running zeekctl install…"
"${ZEEK_PREFIX}/bin/zeekctl" install

log "Checking configuration…"
"${ZEEK_PREFIX}/bin/zeekctl" check

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Zeek installed successfully on interface: ${IFACE}

  Next steps:
    1. Start Zeek:
         sudo zeekctl start

    2. Verify logs are being written:
         tail -f /opt/zeek/logs/current/conn.log

    3. Start the SecureCloud-BD feature extractor:
         python3 ml/zeek/flow-to-features.py \\
           --conn-log /opt/zeek/logs/current/conn.log \\
           --api-url  http://localhost:8080/score \\
           --output   zeek-scored-flows.log

    4. Ship scored flows to Elasticsearch:
         python3 ml/zeek/scored-to-elastic.py \\
           --input   zeek-scored-flows.log \\
           --es-url  http://localhost:9200

  Stop Zeek:
    sudo zeekctl stop

  See ml/zeek/README.md for the full data path documentation.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
