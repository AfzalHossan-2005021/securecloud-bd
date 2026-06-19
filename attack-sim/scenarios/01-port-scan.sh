#!/usr/bin/env bash
# =============================================================================
# 01-port-scan.sh — TCP SYN Scan + Service Version Detection
#
# MITRE ATT&CK : T1046 — Network Service Discovery
# Tools        : nmap
# Detection    : Falco (unexpected outbound / high connection rate rule)
#                Zeek (conn.log: many S0 state flows from single source)
# Expected     : DETECTED within 30 seconds
#
# Usage: bash attack-sim/scenarios/01-port-scan.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------
SCENARIO_ID="01-port-scan"
SCENARIO_NAME="TCP SYN Port Scan + Service Version Detection"
MITRE_ID="T1046"

NS="${NS:-securecloud}"
SIEM_NS="${SIEM_NS:-siem}"
RESULTS_DIR="$(cd "$(dirname "$0")/../results" && pwd)"
WORDLISTS_DIR="$(cd "$(dirname "$0")/../wordlists" && pwd)"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="${RESULTS_DIR}/${SCENARIO_ID}-${TIMESTAMP}.txt"
DETECTION_WAIT="${DETECTION_WAIT:-30}"   # seconds to wait for Falco alert

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
check_prereqs() {
    local missing=()
    for cmd in nmap kubectl; do
        command -v "${cmd}" &>/dev/null || missing+=("${cmd}")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}ERROR: Missing tools: ${missing[*]}${RESET}" >&2
        echo "Install on Kali: sudo apt-get install -y nmap" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Auto-detect Minikube IP and NodePorts
# ---------------------------------------------------------------------------
detect_targets() {
    if [[ -z "${MINIKUBE_IP:-}" ]]; then
        MINIKUBE_IP="$(minikube ip 2>/dev/null)" \
            || { echo -e "${RED}Cannot detect minikube IP. Set MINIKUBE_IP manually.${RESET}" >&2; exit 1; }
    fi

    # Collect all NodePorts across all namespaces
    NODEPORTS="$(kubectl get svc -A \
        -o=jsonpath='{range .items[?(@.spec.type=="NodePort")]}{range .spec.ports[*]}{.nodePort}{","}{end}{end}' \
        2>/dev/null | tr ',' '\n' | sort -un | paste -sd ',' -)"

    if [[ -z "${NODEPORTS}" ]]; then
        echo -e "${YELLOW}WARNING: No NodePort services found. Falling back to common range 30000-32767.${RESET}"
        NODEPORTS="30000-32767"
    fi

    echo -e "${CYAN}Target IP : ${MINIKUBE_IP}${RESET}"
    echo -e "${CYAN}NodePorts : ${NODEPORTS}${RESET}"
}

# ---------------------------------------------------------------------------
# Write result metadata header
# ---------------------------------------------------------------------------
init_results() {
    mkdir -p "${RESULTS_DIR}"
    {
        echo "SECURECLOUD_RESULT_V1"
        echo "SCENARIO_ID: ${SCENARIO_ID}"
        echo "SCENARIO_NAME: ${SCENARIO_NAME}"
        echo "MITRE_ID: ${MITRE_ID}"
        echo "START_TIME: ${START_ISO}"
        echo "TARGET_IP: ${MINIKUBE_IP}"
        echo "TARGET_PORTS: ${NODEPORTS}"
        echo "CATEGORY: reconnaissance"
        echo "SEVERITY: MEDIUM"
        echo "---"
    } > "${RESULT_FILE}"
}

# ---------------------------------------------------------------------------
# Falco alert check
# ---------------------------------------------------------------------------
check_falco_alerts() {
    local since_iso="$1"
    local pattern="${2:-Notice|Warning}"
    kubectl logs -n "${SIEM_NS}" \
        -l app.kubernetes.io/name=falco \
        --since-time="${since_iso}" 2>/dev/null \
        | grep -Ec "${pattern}" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SecureCloud-BD  |  Scenario ${SCENARIO_ID}${RESET}"
    echo -e "${BOLD}  ${SCENARIO_NAME}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    check_prereqs
    detect_targets

    START_EPOCH="$(date +%s)"
    START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    init_results

    # ── Phase 1: SYN scan ──────────────────────────────────────────────────
    echo -e "\n${CYAN}[Phase 1] TCP SYN scan on ports: ${NODEPORTS}${RESET}"
    echo -e "          nmap -sS -p${NODEPORTS} ${MINIKUBE_IP} --open\n"

    SYN_OUTPUT="$(nmap -sS \
        -p "${NODEPORTS}" \
        --open \
        --reason \
        --stats-every 5s \
        -T4 \
        "${MINIKUBE_IP}" 2>&1)"

    echo "${SYN_OUTPUT}"
    {
        echo ""
        echo "=== PHASE 1: TCP SYN SCAN ==="
        echo "${SYN_OUTPUT}"
    } >> "${RESULT_FILE}"

    OPEN_PORTS="$(echo "${SYN_OUTPUT}" | grep -c '/tcp.*open' || true)"
    echo -e "\n${GREEN}Open ports found: ${OPEN_PORTS}${RESET}"

    # ── Phase 2: Service + version detection ──────────────────────────────
    echo -e "\n${CYAN}[Phase 2] Service & version scan${RESET}"
    echo -e "          nmap -sV -p${NODEPORTS} ${MINIKUBE_IP}\n"

    SVC_OUTPUT="$(nmap -sV \
        -p "${NODEPORTS}" \
        --version-intensity 5 \
        -T3 \
        "${MINIKUBE_IP}" 2>&1)"

    echo "${SVC_OUTPUT}"
    {
        echo ""
        echo "=== PHASE 2: SERVICE VERSION SCAN ==="
        echo "${SVC_OUTPUT}"
    } >> "${RESULT_FILE}"

    SCAN_END_EPOCH="$(date +%s)"
    SCAN_END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    SCAN_DURATION=$(( SCAN_END_EPOCH - START_EPOCH ))

    echo -e "\n${CYAN}Scan completed in ${SCAN_DURATION}s.  Waiting ${DETECTION_WAIT}s for Falco…${RESET}"
    sleep "${DETECTION_WAIT}"

    # ── Falco detection check ──────────────────────────────────────────────
    FALCO_COUNT="$(check_falco_alerts "${START_ISO}" "Notice|Warning|port.scan\|Port.Scan\|Outbound")"
    END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    END_EPOCH="$(date +%s)"

    if [[ "${FALCO_COUNT}" -gt 0 ]]; then
        DETECTION_STATUS="DETECTED"
        # Approximate MTTD: mid-point of scan duration + detection wait
        MTTD=$(( SCAN_DURATION / 2 ))
        DETECTION_TIME="${SCAN_END_ISO}"
        echo -e "\n${GREEN}${BOLD}✓ DETECTED — Falco raised ${FALCO_COUNT} alert(s)${RESET}"
    else
        DETECTION_STATUS="UNDETECTED"
        MTTD=0
        DETECTION_TIME=""
        echo -e "\n${RED}${BOLD}✗ UNDETECTED — no Falco alerts in ${DETECTION_WAIT}s window${RESET}"
        echo -e "${YELLOW}  Check: siem/falco/falco-values.yaml → add port-scan detection rule${RESET}"
    fi

    # ── Finalise results file ──────────────────────────────────────────────
    {
        echo ""
        echo "=== SUMMARY ==="
        echo "END_TIME: ${END_ISO}"
        echo "SCAN_DURATION_SECONDS: ${SCAN_DURATION}"
        echo "OPEN_PORTS_FOUND: ${OPEN_PORTS}"
        echo "FALCO_ALERT_COUNT: ${FALCO_COUNT}"
        echo "DETECTION_STATUS: ${DETECTION_STATUS}"
        echo "DETECTION_TIME: ${DETECTION_TIME}"
        echo "MTTD_SECONDS: ${MTTD}"
    } >> "${RESULT_FILE}"

    # Patch the header with end-time and detection outcome
    sed -i "s|^END_TIME:.*|END_TIME: ${END_ISO}|" "${RESULT_FILE}" 2>/dev/null || true

    # Append the detection outcome lines to the header block too
    sed -i "/^---$/i DETECTION_STATUS: ${DETECTION_STATUS}\nFALCO_ALERT_COUNT: ${FALCO_COUNT}\nMTTD_SECONDS: ${MTTD}" \
        "${RESULT_FILE}" 2>/dev/null || true

    echo -e "\n${CYAN}Results saved to: ${RESULT_FILE}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

main "$@"
