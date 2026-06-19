#!/usr/bin/env bash
# =============================================================================
# capture-attack-traffic.sh — Zeek capture of labelled attack traffic
#
# For each scenario in attack-sim/scenarios/, starts Zeek, runs the scenario,
# stops Zeek, then saves the labelled conn.log.
#
# Output: datasets/raw/attack-{type}-{timestamp}.log
#
# Environment overrides:
#   SCENARIO          run only this scenario ID (e.g. "01-port-scan")
#   MINIKUBE_IP       override auto-detected Minikube IP
#   ZEEK_IFACE        override auto-detected network interface
#   ZEEK_SITE         override Zeek site config dir
#   ZEEK_SETTLE       seconds to wait after attack before stopping Zeek (default 5)
#
# Usage:
#   sudo bash datasets/capture/capture-attack-traffic.sh           # all scenarios
#   sudo bash datasets/capture/capture-attack-traffic.sh --scenario 01-port-scan
#   sudo SCENARIO=02-dos-flood bash datasets/capture/capture-attack-traffic.sh
#
# Note: 02-dos-flood.sh requires root itself (hping3 raw sockets), so this
#       script must also run as root. The other scenarios work without root
#       but are captured here under the same root session.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ZEEK_SITE="${ZEEK_SITE:-/opt/zeek/share/zeek/site}"
ZEEK_SETTLE="${ZEEK_SETTLE:-5}"   # seconds to let Zeek flush after attack ends

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RAW_DIR="${REPO_ROOT}/datasets/raw"
SCENARIOS_DIR="${REPO_ROOT}/attack-sim/scenarios"

# Scenario ID → dataset label type
declare -A SCENARIO_LABEL
SCENARIO_LABEL["01-port-scan"]="portscan"
SCENARIO_LABEL["02-dos-flood"]="dos"
SCENARIO_LABEL["03-ssh-brute-force"]="brute_force"
SCENARIO_LABEL["04-lateral-movement"]="lateral_movement"
SCENARIO_LABEL["05-bkash-scenario"]="bkash_scenario"

# Ordered list (consistent with filenames)
SCENARIO_ORDER=("01-port-scan" "02-dos-flood" "03-ssh-brute-force" "04-lateral-movement" "05-bkash-scenario")

ZEEK_WORKDIR=""
ZEEK_PID=""
CURRENT_OUTPUT=""

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
stop_zeek_and_collect() {
    if [[ -n "${ZEEK_PID:-}" ]]; then
        kill "${ZEEK_PID}" 2>/dev/null || true
        wait "${ZEEK_PID}" 2>/dev/null || true
        ZEEK_PID=""
    fi
    if [[ -n "${ZEEK_WORKDIR:-}" && -d "${ZEEK_WORKDIR}" ]]; then
        if [[ -f "${ZEEK_WORKDIR}/conn.log" && -n "${CURRENT_OUTPUT:-}" ]]; then
            cp "${ZEEK_WORKDIR}/conn.log" "${CURRENT_OUTPUT}"
            local lines
            lines="$(wc -l < "${CURRENT_OUTPUT}" 2>/dev/null || echo 0)"
            echo -e "${GREEN}  → ${CURRENT_OUTPUT} (${lines} flows)${RESET}"
        fi
        rm -rf "${ZEEK_WORKDIR}"
        ZEEK_WORKDIR=""
    fi
}

cleanup_on_exit() {
    echo -e "\n${YELLOW}Interrupted — stopping Zeek and saving partial capture…${RESET}"
    stop_zeek_and_collect
}
trap cleanup_on_exit EXIT INT TERM

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
check_prereqs() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}Root required (for Zeek capture + 02-dos-flood hping3).${RESET}" >&2
        echo -e "${RED}Run: sudo bash $0${RESET}" >&2
        exit 1
    fi

    local missing=()
    command -v zeek &>/dev/null || missing+=("zeek")
    command -v kubectl &>/dev/null || missing+=("kubectl")
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing: ${missing[*]}${RESET}" >&2; exit 1
    fi

    if [[ ! -f "${ZEEK_SITE}/local.zeek" ]]; then
        echo -e "${YELLOW}WARNING: ${ZEEK_SITE}/local.zeek not found — TSV format will be used.${RESET}"
        ZEEK_POLICY_ARGS=""
    else
        ZEEK_POLICY_ARGS="${ZEEK_SITE}/local.zeek"
    fi
}

# ---------------------------------------------------------------------------
# Interface detection (same logic as capture-normal-traffic.sh)
# ---------------------------------------------------------------------------
detect_interface() {
    if [[ -z "${MINIKUBE_IP:-}" ]]; then
        MINIKUBE_IP="$(minikube ip 2>/dev/null)" \
            || { echo -e "${RED}Cannot detect Minikube IP. Set MINIKUBE_IP.${RESET}" >&2; exit 1; }
    fi

    if [[ -z "${ZEEK_IFACE:-}" ]]; then
        ZEEK_IFACE="$(ip route get "${MINIKUBE_IP}" 2>/dev/null \
            | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')" || true

        if [[ -z "${ZEEK_IFACE:-}" ]]; then
            local prefix
            prefix="$(echo "${MINIKUBE_IP}" | cut -d. -f1-3)"
            ZEEK_IFACE="$(ip -o addr show | awk -v p="${prefix}" '$4 ~ p {print $2; exit}')" || true
        fi

        [[ -n "${ZEEK_IFACE:-}" ]] || {
            echo -e "${RED}Cannot detect Minikube interface. Set ZEEK_IFACE.${RESET}" >&2; exit 1
        }
    fi
    echo -e "${CYAN}  Minikube IP: ${MINIKUBE_IP}  |  Zeek iface: ${ZEEK_IFACE}${RESET}"
}

# ---------------------------------------------------------------------------
# Zeek helpers
# ---------------------------------------------------------------------------
start_zeek_for() {
    local label_type="$1"
    local timestamp="$2"
    CURRENT_OUTPUT="${RAW_DIR}/attack-${label_type}-${timestamp}.log"
    ZEEK_WORKDIR="$(mktemp -d /tmp/zeek-attack-XXXXXX)"

    echo -e "  ${CYAN}Starting Zeek on ${ZEEK_IFACE}…${RESET}"
    pushd "${ZEEK_WORKDIR}" > /dev/null
    # shellcheck disable=SC2086
    zeek -i "${ZEEK_IFACE}" ${ZEEK_POLICY_ARGS} \
        "Log::rotation_interval = 0secs" \
        > "${ZEEK_WORKDIR}/zeek.stdout" 2>&1 &
    ZEEK_PID=$!
    popd > /dev/null

    # Wait for conn.log to appear (up to 10 s)
    local waited=0
    while [[ ! -f "${ZEEK_WORKDIR}/conn.log" && ${waited} -lt 10 ]]; do
        sleep 1; (( waited++ )) || true
    done
    echo -e "  ${GREEN}Zeek PID ${ZEEK_PID} — capturing${RESET}"
    sleep 2   # brief buffer before scenario starts
}

# ---------------------------------------------------------------------------
# Run one scenario
# ---------------------------------------------------------------------------
run_scenario() {
    local scenario_id="$1"
    local label_type="${SCENARIO_LABEL[${scenario_id}]}"
    local scenario_script="${SCENARIOS_DIR}/${scenario_id}.sh"
    local timestamp
    timestamp="$(date +%Y%m%d-%H%M%S)"

    echo -e "\n${BOLD}──────────────────────────────────────────────────────────${RESET}"
    echo -e "${BOLD}  Scenario: ${scenario_id}  (label: ${label_type})${RESET}"
    echo -e "${BOLD}──────────────────────────────────────────────────────────${RESET}"

    if [[ ! -f "${scenario_script}" ]]; then
        echo -e "${YELLOW}  Script not found: ${scenario_script} — skipping${RESET}"
        return 0
    fi

    mkdir -p "${RAW_DIR}"
    start_zeek_for "${label_type}" "${timestamp}"

    echo -e "  ${CYAN}Running ${scenario_script}…${RESET}"

    # Inherit MINIKUBE_IP so each scenario doesn't have to re-detect
    local exit_code=0
    MINIKUBE_IP="${MINIKUBE_IP}" \
    bash "${scenario_script}" || exit_code=$?

    if [[ ${exit_code} -ne 0 ]]; then
        echo -e "  ${YELLOW}Scenario exited with code ${exit_code} (non-fatal — partial capture usable)${RESET}"
    fi

    # Allow Zeek to capture residual traffic (connection teardowns, etc.)
    echo -e "  ${CYAN}Waiting ${ZEEK_SETTLE}s for Zeek to flush…${RESET}"
    sleep "${ZEEK_SETTLE}"

    stop_zeek_and_collect

    if [[ -f "${CURRENT_OUTPUT}" ]]; then
        local flows
        flows="$(wc -l < "${CURRENT_OUTPUT}" 2>/dev/null || echo 0)"
        if [[ ${flows} -lt 5 ]]; then
            echo -e "  ${YELLOW}WARNING: Only ${flows} flows captured for ${scenario_id}.${RESET}"
            echo -e "  ${YELLOW}The scenario may have needed more time or wider ZEEK_IFACE.${RESET}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    ONLY_SCENARIO="${SCENARIO:-}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scenario|-s)
                ONLY_SCENARIO="$2"; shift 2 ;;
            --scenario=*)
                ONLY_SCENARIO="${1#*=}"; shift ;;
            --help|-h)
                sed -n '2,30p' "$0"; exit 0 ;;
            *)
                echo -e "${RED}Unknown argument: $1${RESET}" >&2; exit 1 ;;
        esac
    done

    if [[ -n "${ONLY_SCENARIO}" ]]; then
        if [[ -z "${SCENARIO_LABEL[${ONLY_SCENARIO}]:-}" ]]; then
            echo -e "${RED}Unknown scenario: ${ONLY_SCENARIO}${RESET}" >&2
            echo "Valid: ${SCENARIO_ORDER[*]}" >&2
            exit 1
        fi
    fi
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
print_summary() {
    local -a captured_files=()
    while IFS= read -r -d '' f; do
        captured_files+=("${f}")
    done < <(find "${RAW_DIR}" -name "attack-*.log" -newer "${RAW_DIR}" -print0 2>/dev/null) || true

    echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  Capture Summary${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    printf "  %-45s  %8s\n" "File" "Flows"
    printf "  %-45s  %8s\n" "----" "-----"

    local total_flows=0
    for pattern in portscan dos brute_force lateral_movement bkash_scenario; do
        for f in "${RAW_DIR}"/attack-"${pattern}"-*.log; do
            [[ -f "${f}" ]] || continue
            local flows
            flows="$(wc -l < "${f}" 2>/dev/null || echo 0)"
            printf "  %-45s  %8d\n" "$(basename "${f}")" "${flows}"
            (( total_flows += flows )) || true
        done
    done

    echo -e "  ${CYAN}Total attack flows: ${total_flows}${RESET}"
    echo -e "\n${GREEN}Next step:${RESET}"
    echo -e "  python3 datasets/capture/build-k8s-dataset.py --pretty"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SecureCloud-BD  |  Attack Traffic Capture${RESET}"
    if [[ -n "${ONLY_SCENARIO:-}" ]]; then
        echo -e "${BOLD}  Mode: single scenario (${ONLY_SCENARIO})${RESET}"
    else
        echo -e "${BOLD}  Mode: all 5 scenarios${RESET}"
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    check_prereqs
    detect_interface
    mkdir -p "${RAW_DIR}"

    if [[ -n "${ONLY_SCENARIO:-}" ]]; then
        run_scenario "${ONLY_SCENARIO}"
    else
        for scenario_id in "${SCENARIO_ORDER[@]}"; do
            run_scenario "${scenario_id}"
            # Brief pause between scenarios so Kubernetes recovers
            sleep 10
        done
    fi

    # Disable the EXIT trap's cleanup (already done per-scenario)
    trap - EXIT INT TERM

    print_summary
}

main "$@"
