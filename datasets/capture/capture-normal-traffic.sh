#!/usr/bin/env bash
# =============================================================================
# capture-normal-traffic.sh — Zeek capture of normal Kubernetes traffic
#
# Runs a traffic generator (k6 → curl loop) against the SecureCloud ML API
# while Zeek captures conn.log on the Minikube network interface.
#
# Output: datasets/raw/normal-{timestamp}.log (Zeek conn.log, JSON format)
#
# Environment overrides:
#   CAPTURE_DURATION  seconds to capture (default 3600 = 60 min)
#   CONCURRENT_VUS    k6 virtual users (default 10)
#   MINIKUBE_IP       override auto-detected Minikube IP
#   API_NODEPORT      override auto-detected NodePort
#   ZEEK_IFACE        override auto-detected network interface
#   ZEEK_SITE         override Zeek site config dir (default /opt/zeek/share/zeek/site)
#
# Usage:
#   sudo bash datasets/capture/capture-normal-traffic.sh
#   sudo CAPTURE_DURATION=300 bash datasets/capture/capture-normal-traffic.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CAPTURE_DURATION="${CAPTURE_DURATION:-3600}"
CONCURRENT_VUS="${CONCURRENT_VUS:-10}"
NS="${NS:-securecloud}"
ZEEK_SITE="${ZEEK_SITE:-/opt/zeek/share/zeek/site}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RAW_DIR="${REPO_ROOT}/datasets/raw"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_FILE="${RAW_DIR}/normal-${TIMESTAMP}.log"

ZEEK_WORKDIR=""
ZEEK_PID=""
K6_TMPFILE=""

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
cleanup() {
    if [[ -n "${ZEEK_PID:-}" ]]; then
        kill "${ZEEK_PID}" 2>/dev/null || true
        wait "${ZEEK_PID}" 2>/dev/null || true
    fi
    if [[ -n "${ZEEK_WORKDIR:-}" && -d "${ZEEK_WORKDIR}" ]]; then
        if [[ -f "${ZEEK_WORKDIR}/conn.log" ]]; then
            mkdir -p "${RAW_DIR}"
            cp "${ZEEK_WORKDIR}/conn.log" "${OUTPUT_FILE}"
            echo -e "\n${GREEN}conn.log → ${OUTPUT_FILE}${RESET}"
            local lines
            lines="$(wc -l < "${OUTPUT_FILE}" 2>/dev/null || echo 0)"
            echo -e "${CYAN}  Captured ${lines} flow records${RESET}"
        else
            echo -e "${YELLOW}WARNING: conn.log not found in ${ZEEK_WORKDIR}${RESET}"
        fi
        rm -rf "${ZEEK_WORKDIR}"
    fi
    [[ -n "${K6_TMPFILE:-}" ]] && rm -f "${K6_TMPFILE}" || true
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
check_prereqs() {
    # Root required for packet capture
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}Zeek packet capture requires root. Run: sudo bash $0${RESET}" >&2
        exit 1
    fi

    local missing=()
    command -v zeek &>/dev/null || missing+=("zeek")
    command -v kubectl &>/dev/null || missing+=("kubectl")

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing tools: ${missing[*]}${RESET}" >&2
        echo "Install Zeek: bash ml/zeek/zeek-install.sh" >&2
        exit 1
    fi

    if [[ ! -f "${ZEEK_SITE}/local.zeek" ]]; then
        echo -e "${YELLOW}WARNING: ${ZEEK_SITE}/local.zeek not found.${RESET}"
        echo -e "${YELLOW}Copy ml/zeek/zeek-config/local.zeek → ${ZEEK_SITE}/local.zeek${RESET}"
        echo -e "${YELLOW}Falling back to bare Zeek (no JSON logs — TSV format).${RESET}"
        ZEEK_POLICY_ARGS=""
    else
        ZEEK_POLICY_ARGS="${ZEEK_SITE}/local.zeek"
    fi

    # Traffic generator: k6 preferred, curl loop fallback
    if command -v k6 &>/dev/null; then
        TRAFFIC_GENERATOR="k6"
    else
        echo -e "${YELLOW}k6 not found — using curl loop (less realistic).${RESET}"
        echo -e "${YELLOW}Install k6: https://k6.io/docs/get-started/installation/${RESET}"
        TRAFFIC_GENERATOR="curl"
    fi
}

# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------
detect_interface() {
    if [[ -z "${MINIKUBE_IP:-}" ]]; then
        MINIKUBE_IP="$(minikube ip 2>/dev/null)" \
            || { echo -e "${RED}Cannot determine Minikube IP. Set MINIKUBE_IP.${RESET}" >&2; exit 1; }
    fi

    if [[ -z "${ZEEK_IFACE:-}" ]]; then
        # ip route get gives the exact interface for this destination
        ZEEK_IFACE="$(ip route get "${MINIKUBE_IP}" 2>/dev/null \
            | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')" || true

        if [[ -z "${ZEEK_IFACE:-}" ]]; then
            # Fallback: find interface whose subnet contains the Minikube IP
            local prefix
            prefix="$(echo "${MINIKUBE_IP}" | cut -d. -f1-3)"
            ZEEK_IFACE="$(ip -o addr show | awk -v p="${prefix}" '$4 ~ p {print $2; exit}')" || true
        fi

        [[ -n "${ZEEK_IFACE:-}" ]] || {
            echo -e "${RED}Cannot auto-detect Minikube interface. Set ZEEK_IFACE.${RESET}" >&2
            echo "Try: ip route | grep $(echo ${MINIKUBE_IP} | cut -d. -f1-3)" >&2
            exit 1
        }
    fi

    echo -e "${CYAN}  Minikube IP  : ${MINIKUBE_IP}${RESET}"
    echo -e "${CYAN}  Zeek iface   : ${ZEEK_IFACE}${RESET}"
}

# ---------------------------------------------------------------------------
# API endpoint detection
# ---------------------------------------------------------------------------
detect_api() {
    if [[ -z "${API_NODEPORT:-}" ]]; then
        API_NODEPORT="$(kubectl get svc -n "${NS}" \
            -o=jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.spec.ports[0].nodePort}{"\n"}{end}' \
            2>/dev/null | head -1)" || true
    fi

    if [[ -z "${API_NODEPORT:-}" ]]; then
        echo -e "${YELLOW}No NodePort found — health endpoint will return errors (still useful for Zeek capture).${RESET}"
        TARGET_URL="http://${MINIKUBE_IP}:8080"
    else
        TARGET_URL="http://${MINIKUBE_IP}:${API_NODEPORT}"
    fi
    echo -e "${CYAN}  API target   : ${TARGET_URL}${RESET}"
}

# ---------------------------------------------------------------------------
# Zeek capture
# ---------------------------------------------------------------------------
start_zeek() {
    ZEEK_WORKDIR="$(mktemp -d /tmp/zeek-normal-XXXXXX)"
    echo -e "\n${CYAN}[Zeek] Starting on ${ZEEK_IFACE} → ${ZEEK_WORKDIR}/conn.log${RESET}"

    pushd "${ZEEK_WORKDIR}" > /dev/null
    # shellcheck disable=SC2086
    zeek -i "${ZEEK_IFACE}" ${ZEEK_POLICY_ARGS} \
        "Log::rotation_interval = 0secs" \
        > "${ZEEK_WORKDIR}/zeek.stdout" 2>&1 &
    ZEEK_PID=$!
    popd > /dev/null

    # Wait for Zeek to open conn.log (up to 10 s)
    local waited=0
    while [[ ! -f "${ZEEK_WORKDIR}/conn.log" && ${waited} -lt 10 ]]; do
        sleep 1
        (( waited++ )) || true
    done

    if [[ ! -f "${ZEEK_WORKDIR}/conn.log" ]]; then
        echo -e "${YELLOW}  conn.log not yet created — capture may be delayed${RESET}"
    else
        echo -e "${GREEN}  Zeek PID ${ZEEK_PID} — conn.log open${RESET}"
    fi
}

# ---------------------------------------------------------------------------
# k6 traffic generator
# ---------------------------------------------------------------------------
run_k6() {
    K6_TMPFILE="$(mktemp /tmp/k6-normal-XXXXXX.js)"

    cat > "${K6_TMPFILE}" <<'K6_SCRIPT'
import http from 'k6/http';
import { sleep, check } from 'k6';
import { Counter } from 'k6/metrics';

const errors = new Counter('errors');

export const options = {
    vus: parseInt(__ENV.VUS || '10'),
    duration: `${__ENV.DURATION_SECONDS || '3600'}s`,
    thresholds: { errors: ['count<100'] },
};

const TARGET = __ENV.TARGET_URL;

// Realistic benign API flow features (raw, pre-scaling)
// Order: duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
//        orig_ip_bytes, resp_ip_bytes, missed_bytes,
//        proto_tcp, proto_udp, proto_icmp,
//        conn_state_S0, conn_state_SF, conn_state_REJ, conn_state_RSTO,
//        service_http, service_dns, service_ssl,
//        bytes_per_pkt_orig, bytes_per_pkt_resp
const BENIGN_TEMPLATES = [
    // Short GET /health
    [0.005, 74, 180, 2, 2, 114, 220, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 37.0, 90.0],
    // POST /score (small payload)
    [0.082, 412, 876, 4, 5, 492, 956, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 103.0, 175.2],
    // POST /score (medium payload with sequence)
    [0.134, 1850, 924, 6, 5, 1970, 1004, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 308.3, 184.8],
    // POST /score/batch (5 items)
    [0.291, 3420, 4100, 9, 8, 3560, 4240, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 380.0, 512.5],
    // DNS resolution (incidental)
    [0.003, 42, 98, 1, 1, 70, 126, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 42.0, 98.0],
];

function jitter(v, frac) {
    return Math.max(0, v + (Math.random() - 0.5) * v * frac);
}

function randomFeatures() {
    const tmpl = BENIGN_TEMPLATES[Math.floor(Math.random() * BENIGN_TEMPLATES.length)];
    // Jitter continuous features (first 8), keep one-hot stable
    return tmpl.map((v, i) => (i < 8 || i >= 18) ? jitter(v, 0.3) : v);
}

export default function () {
    const r = Math.random();
    let res;

    if (r < 0.30) {
        res = http.get(`${TARGET}/health`, { tags: { endpoint: 'health' } });
    } else if (r < 0.75) {
        res = http.post(
            `${TARGET}/score`,
            JSON.stringify({ features: randomFeatures() }),
            { headers: { 'Content-Type': 'application/json' }, tags: { endpoint: 'score' } },
        );
    } else {
        const batch = Array.from(
            { length: Math.floor(Math.random() * 8) + 1 },
            () => ({ features: randomFeatures() }),
        );
        res = http.post(
            `${TARGET}/score/batch`,
            JSON.stringify({ requests: batch }),
            { headers: { 'Content-Type': 'application/json' }, tags: { endpoint: 'batch' } },
        );
    }

    if (!res || res.status >= 500) errors.add(1);
    sleep(0.5 + Math.random() * 1.5);
}
K6_SCRIPT

    echo -e "\n${CYAN}[k6] Generating traffic for ${CAPTURE_DURATION}s  (${CONCURRENT_VUS} VUs)${RESET}"
    k6 run \
        -e TARGET_URL="${TARGET_URL}" \
        -e DURATION_SECONDS="${CAPTURE_DURATION}" \
        -e VUS="${CONCURRENT_VUS}" \
        "${K6_TMPFILE}" || true   # non-zero exit (e.g., threshold breach) is OK
}

# ---------------------------------------------------------------------------
# curl fallback traffic generator
# ---------------------------------------------------------------------------
run_curl_loop() {
    local end_epoch=$(( $(date +%s) + CAPTURE_DURATION ))
    local req_count=0

    echo -e "\n${CYAN}[curl] Generating traffic for ${CAPTURE_DURATION}s${RESET}"

    # Realistic benign feature vector
    local FEATURES='[0.082,412,876,4,5,492,956,0,1,0,0,0,1,0,0,1,0,0,103.0,175.2]'

    while [[ $(date +%s) -lt ${end_epoch} ]]; do
        local r=$(( RANDOM % 100 ))

        if (( r < 30 )); then
            curl -s -o /dev/null --max-time 3 "${TARGET_URL}/health" || true
        elif (( r < 75 )); then
            curl -s -o /dev/null --max-time 3 \
                -X POST "${TARGET_URL}/score" \
                -H "Content-Type: application/json" \
                -d "{\"features\":${FEATURES}}" || true
        else
            curl -s -o /dev/null --max-time 5 \
                -X POST "${TARGET_URL}/score/batch" \
                -H "Content-Type: application/json" \
                -d "{\"requests\":[{\"features\":${FEATURES}},{\"features\":${FEATURES}}]}" || true
        fi

        (( req_count++ )) || true
        sleep "$(echo "scale=2; 0.5 + $((RANDOM % 150)) / 100" | bc -l 2>/dev/null || echo 1)"

        if (( req_count % 50 == 0 )); then
            local remaining=$(( end_epoch - $(date +%s) ))
            echo -e "  ${req_count} requests sent — ${remaining}s remaining…"
        fi
    done

    echo -e "${GREEN}  curl loop done: ${req_count} requests${RESET}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SecureCloud-BD  |  Normal Traffic Capture${RESET}"
    echo -e "${BOLD}  Duration: ${CAPTURE_DURATION}s  |  Output: ${OUTPUT_FILE}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    check_prereqs
    detect_interface
    detect_api

    mkdir -p "${RAW_DIR}"

    start_zeek
    sleep 3   # give Zeek time to start capturing before traffic begins

    echo -e "\n${CYAN}[Traffic] Starting ${TRAFFIC_GENERATOR} generator…${RESET}"
    if [[ "${TRAFFIC_GENERATOR}" == "k6" ]]; then
        run_k6
    else
        run_curl_loop
    fi

    echo -e "\n${CYAN}[Zeek] Stopping capture…${RESET}"
    # cleanup trap will copy conn.log on exit

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}Done. Run build-k8s-dataset.py to incorporate this capture.${RESET}"
}

main "$@"
