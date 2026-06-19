#!/usr/bin/env bash
# =============================================================================
# 04-lateral-movement.sh — Network Policy Lateral Movement Validation
#
# MITRE ATT&CK : T1021 — Remote Services / T1570 — Lateral Tool Transfer
# Tools        : kubectl exec, curl (inside pods)
# Detection    : Istio AuthorizationPolicy + Kubernetes NetworkPolicy
#
# Steps
# ─────
#   Step 1  Exec into frontend pod (simulates RCE / initial access)
#   Step 2  frontend → user-db:5432   (EXPECTED: BLOCKED by NetworkPolicy)
#   Step 3  frontend → payment-api    (EXPECTED: ALLOWED)
#   Step 4  payment-api → user-db     (EXPECTED: ALLOWED)
#
# Each step records ALLOWED/BLOCKED/ERROR with a timestamp.
# Overall result: PASS if all expected outcomes match, FAIL otherwise.
#
# Usage: bash attack-sim/scenarios/04-lateral-movement.sh
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

SCENARIO_ID="04-lateral-movement"
SCENARIO_NAME="Lateral Movement — NetworkPolicy Validation"
MITRE_ID="T1021"

NS="${NS:-securecloud}"
SIEM_NS="${SIEM_NS:-siem}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"

# Pod / service labels — override if your deployment uses different names
FRONTEND_APP="${FRONTEND_APP:-frontend}"
PAYMENT_API_APP="${PAYMENT_API_APP:-securecloud-api}"
USER_DB_APP="${USER_DB_APP:-user-db}"
USER_DB_PORT="${USER_DB_PORT:-5432}"
PAYMENT_API_PORT="${PAYMENT_API_PORT:-8080}"

CONN_TIMEOUT="${CONN_TIMEOUT:-5}"    # seconds for each connectivity probe
DETECTION_WAIT="${DETECTION_WAIT:-20}"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="${RESULTS_DIR}/${SCENARIO_ID}-${TIMESTAMP}.txt"

# Tracking
declare -A STEP_STATUS=()
declare -A STEP_EXPECTED=()
declare -A STEP_TIME=()
TOTAL_STEPS=4
STEPS_PASSED=0

# ---------------------------------------------------------------------------
check_prereqs() {
    command -v kubectl &>/dev/null || { echo -e "${RED}kubectl not found${RESET}" >&2; exit 1; }
}

# ---------------------------------------------------------------------------
# Find a running pod by app label; return its name or empty string
# ---------------------------------------------------------------------------
find_pod() {
    local app_label="$1" namespace="${2:-${NS}}"
    kubectl get pod -n "${namespace}" \
        -l "app=${app_label}" \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Probe TCP connectivity from inside a pod using /dev/tcp bash builtin.
# Falls back to nc → python3 → curl if bash devtcp fails.
# Returns "ALLOWED" or "BLOCKED" and the raw output.
# ---------------------------------------------------------------------------
probe_connection() {
    local from_pod="$1" target_host="$2" target_port="$3"
    local namespace="${4:-${NS}}"
    local timeout="${5:-${CONN_TIMEOUT}}"
    local result raw

    # Try /dev/tcp first (always present in bash)
    raw="$(kubectl exec -n "${namespace}" "${from_pod}" -- \
        bash -c "timeout ${timeout} bash -c '
            (echo >/dev/tcp/${target_host}/${target_port}) 2>&1 \
            && echo CONNECTED || echo REFUSED_OR_TIMEOUT
        '" 2>&1)" || true

    if echo "${raw}" | grep -q "CONNECTED"; then
        result="ALLOWED"
    elif echo "${raw}" | grep -qiE "timeout|refused|REFUSED_OR_TIMEOUT|timed out|network"; then
        result="BLOCKED"
    else
        # Fallback: try nc
        raw2="$(kubectl exec -n "${namespace}" "${from_pod}" -- \
            sh -c "nc -z -w ${timeout} ${target_host} ${target_port} 2>&1 && echo NC_OK || echo NC_FAIL" \
            2>&1)" || true
        if echo "${raw2}" | grep -q "NC_OK"; then
            result="ALLOWED"
            raw="${raw2}"
        else
            # Fallback: try curl connect-only
            raw3="$(kubectl exec -n "${namespace}" "${from_pod}" -- \
                sh -c "curl --connect-timeout ${timeout} -s ${target_host}:${target_port} \
                    -o /dev/null -w '%{http_code}' 2>&1 || echo CURL_FAIL" \
                2>&1)" || true
            if echo "${raw3}" | grep -qvE "CURL_FAIL|000|Could not"; then
                result="ALLOWED"
            else
                result="BLOCKED"
            fi
            raw="${raw3}"
        fi
    fi

    echo "${result}|||${raw}"
}

# ---------------------------------------------------------------------------
# Record a step result
# ---------------------------------------------------------------------------
record_step() {
    local step_num="$1" step_name="$2" actual="$3" expected="$4" detail="$5"
    local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    STEP_STATUS["${step_num}"]="${actual}"
    STEP_EXPECTED["${step_num}"]="${expected}"
    STEP_TIME["${step_num}"]="${ts}"

    local icon colour
    if [[ "${actual}" == "${expected}" ]]; then
        icon="✓"; colour="${GREEN}"; (( STEPS_PASSED++ )) || true
    else
        icon="✗"; colour="${RED}"
    fi

    echo -e "${colour}${BOLD}  [Step ${step_num}] ${step_name}${RESET}"
    echo -e "${colour}    Result  : ${actual}  (expected: ${expected})  ${icon}${RESET}"
    [[ -n "${detail}" ]] && echo -e "${CYAN}    Detail  : ${detail}${RESET}"
    echo -e "    Time    : ${ts}"

    {
        echo ""
        echo "STEP_${step_num}_NAME: ${step_name}"
        echo "STEP_${step_num}_RESULT: ${actual}"
        echo "STEP_${step_num}_EXPECTED: ${expected}"
        echo "STEP_${step_num}_MATCH: $( [[ "${actual}" == "${expected}" ]] && echo PASS || echo FAIL )"
        echo "STEP_${step_num}_TIME: ${ts}"
        echo "STEP_${step_num}_DETAIL: ${detail}"
    } >> "${RESULT_FILE}"
}

init_results() {
    mkdir -p "${RESULTS_DIR}"
    {
        echo "SECURECLOUD_RESULT_V1"
        echo "SCENARIO_ID: ${SCENARIO_ID}"
        echo "SCENARIO_NAME: ${SCENARIO_NAME}"
        echo "MITRE_ID: ${MITRE_ID}"
        echo "START_TIME: ${START_ISO}"
        echo "NAMESPACE: ${NS}"
        echo "FRONTEND_POD: ${FRONTEND_POD}"
        echo "PAYMENT_POD: ${PAYMENT_POD}"
        echo "CATEGORY: lateral-movement"
        echo "SEVERITY: HIGH"
        echo "TOTAL_STEPS: ${TOTAL_STEPS}"
        echo "---"
    } > "${RESULT_FILE}"
}

check_falco_alerts() {
    local since_iso="$1"
    kubectl logs -n "${SIEM_NS}" \
        -l app.kubernetes.io/name=falco \
        --since-time="${since_iso}" 2>/dev/null \
        | grep -Ec "Notice|Warning|shell|exec|lateral" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
main() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SecureCloud-BD  |  Scenario ${SCENARIO_ID}${RESET}"
    echo -e "${BOLD}  ${SCENARIO_NAME}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    check_prereqs

    # Discover pods
    FRONTEND_POD="$(find_pod "${FRONTEND_APP}")"
    PAYMENT_POD="$(find_pod "${PAYMENT_API_APP}")"

    if [[ -z "${FRONTEND_POD}" ]] && [[ -z "${PAYMENT_POD}" ]]; then
        # Fall back to ANY running pod in the namespace
        FRONTEND_POD="$(kubectl get pod -n "${NS}" \
            --field-selector=status.phase=Running \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
        PAYMENT_POD="$(kubectl get pod -n "${NS}" \
            --field-selector=status.phase=Running \
            -o jsonpath='{.items[1].metadata.name}' 2>/dev/null || true)"
        echo -e "${YELLOW}Could not find pods by label — using first available pods in ${NS}${RESET}"
        echo -e "${YELLOW}Set FRONTEND_APP and PAYMENT_API_APP env vars if needed.${RESET}"
    fi

    [[ -n "${FRONTEND_POD}" ]] || {
        echo -e "${RED}No running pod found in namespace ${NS}.${RESET}" >&2
        echo "Is the cluster deployed? Run: helm upgrade --install securecloud infra/helm/securecloud" >&2
        exit 1
    }
    [[ -n "${PAYMENT_POD}" ]] || PAYMENT_POD="${FRONTEND_POD}"   # single-pod fallback

    echo -e "${CYAN}Frontend pod : ${FRONTEND_POD}${RESET}"
    echo -e "${CYAN}Payment pod  : ${PAYMENT_POD}${RESET}"
    echo -e "${CYAN}user-db host : ${USER_DB_APP}:${USER_DB_PORT}${RESET}"

    START_EPOCH="$(date +%s)"
    START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    init_results

    # ── Step 1: exec into frontend (simulates RCE) ─────────────────────────
    echo -e "\n${BOLD}─── Step 1: Exec into ${FRONTEND_POD} (simulating RCE) ───${RESET}"
    EXEC_OUT="$(kubectl exec -n "${NS}" "${FRONTEND_POD}" -- \
        sh -c 'echo "exec ok: $(id) @ $(hostname)"' 2>&1)" || EXEC_OUT="exec failed"

    if echo "${EXEC_OUT}" | grep -q "exec ok"; then
        record_step 1 "kubectl exec into ${FRONTEND_POD}" \
            "ALLOWED" "ALLOWED" "${EXEC_OUT}"
    else
        record_step 1 "kubectl exec into ${FRONTEND_POD}" \
            "BLOCKED" "ALLOWED" "${EXEC_OUT}"
    fi

    # ── Step 2: frontend → user-db (EXPECT BLOCKED) ────────────────────────
    echo -e "\n${BOLD}─── Step 2: ${FRONTEND_POD} → user-db:${USER_DB_PORT} ───${RESET}"
    echo -e "    (NetworkPolicy SHOULD block this — frontend has no policy to reach DB)"
    PROBE="$(probe_connection "${FRONTEND_POD}" "${USER_DB_APP}" "${USER_DB_PORT}")"
    STEP2_STATUS="${PROBE%%|||*}"
    STEP2_DETAIL="${PROBE##*|||}"
    record_step 2 \
        "${FRONTEND_APP} → ${USER_DB_APP}:${USER_DB_PORT}  (DB access from frontend)" \
        "${STEP2_STATUS}" "BLOCKED" \
        "${STEP2_DETAIL:0:120}"

    if [[ "${STEP2_STATUS}" == "ALLOWED" ]]; then
        echo -e "${RED}    ⚠ POLICY GAP: frontend can reach user-db — check NetworkPolicy / Istio AuthorizationPolicy${RESET}"
    fi

    # ── Step 3: frontend → payment-api (EXPECT ALLOWED) ────────────────────
    echo -e "\n${BOLD}─── Step 3: ${FRONTEND_POD} → payment-api:${PAYMENT_API_PORT} ───${RESET}"
    echo -e "    (AuthorizationPolicy SHOULD allow frontend → payment-api)"
    PROBE="$(probe_connection "${FRONTEND_POD}" "${PAYMENT_API_APP}" "${PAYMENT_API_PORT}")"
    STEP3_STATUS="${PROBE%%|||*}"
    STEP3_DETAIL="${PROBE##*|||}"
    record_step 3 \
        "${FRONTEND_APP} → ${PAYMENT_API_APP}:${PAYMENT_API_PORT}  (API call)" \
        "${STEP3_STATUS}" "ALLOWED" \
        "${STEP3_DETAIL:0:120}"

    if [[ "${STEP3_STATUS}" == "BLOCKED" ]]; then
        echo -e "${YELLOW}    ⚠ Application path broken: frontend cannot reach payment-api${RESET}"
    fi

    # ── Step 4: payment-api → user-db (EXPECT ALLOWED) ─────────────────────
    echo -e "\n${BOLD}─── Step 4: ${PAYMENT_POD} → user-db:${USER_DB_PORT} ───${RESET}"
    echo -e "    (AuthorizationPolicy SHOULD allow payment-api → user-db)"
    PROBE="$(probe_connection "${PAYMENT_POD}" "${USER_DB_APP}" "${USER_DB_PORT}")"
    STEP4_STATUS="${PROBE%%|||*}"
    STEP4_DETAIL="${PROBE##*|||}"
    record_step 4 \
        "${PAYMENT_API_APP} → ${USER_DB_APP}:${USER_DB_PORT}  (DB query)" \
        "${STEP4_STATUS}" "ALLOWED" \
        "${STEP4_DETAIL:0:120}"

    # ── Falco detection check ──────────────────────────────────────────────
    echo -e "\n${CYAN}Waiting ${DETECTION_WAIT}s for Falco shell-in-container alert…${RESET}"
    sleep "${DETECTION_WAIT}"
    FALCO_COUNT="$(check_falco_alerts "${START_ISO}")"

    # ── Print step matrix ──────────────────────────────────────────────────
    echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  STEP RESULTS${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    printf "  %-4s %-42s %-10s %-10s %s\n" "Step" "Description" "Expected" "Actual" "Verdict"
    printf "  %-4s %-42s %-10s %-10s %s\n" "----" "-----------------------------------------" "--------" "------" "-------"

    for i in 1 2 3 4; do
        local expected="${STEP_EXPECTED[$i]:-?}" actual="${STEP_STATUS[$i]:-?}"
        local verdict icon col
        if [[ "${actual}" == "${expected}" ]]; then
            verdict="PASS"; icon="✓"; col="${GREEN}"
        else
            verdict="FAIL"; icon="✗"; col="${RED}"
        fi
        case $i in
            1) desc="Exec into frontend pod (RCE sim)";;
            2) desc="Frontend → user-db (DB direct access)";;
            3) desc="Frontend → payment-api (app path)";;
            4) desc="Payment-api → user-db (DB query)";;
        esac
        printf "${col}  %-4s %-42s %-10s %-10s %s${RESET}\n" \
            "${i}" "${desc}" "${expected}" "${actual}" "${icon} ${verdict}"
    done

    POLICY_GAPS=$(( TOTAL_STEPS - STEPS_PASSED ))
    echo -e "\n${BOLD}  Steps passed : ${STEPS_PASSED} / ${TOTAL_STEPS}${RESET}"
    [[ "${POLICY_GAPS}" -eq 0 ]] \
        && echo -e "${GREEN}  All NetworkPolicy assertions PASS${RESET}" \
        || echo -e "${RED}  ${POLICY_GAPS} policy assertion(s) FAILED — review NetworkPolicy / Istio config${RESET}"

    if [[ "${FALCO_COUNT}" -gt 0 ]]; then
        echo -e "${GREEN}  Falco: DETECTED shell-in-container (${FALCO_COUNT} alerts)${RESET}"
    else
        echo -e "${YELLOW}  Falco: No shell-in-container alert — ensure Falco 'Run shell in container' rule is active${RESET}"
    fi

    END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    OVERALL_STATUS="$( [[ "${STEPS_PASSED}" -eq "${TOTAL_STEPS}" ]] && echo PASS || echo FAIL )"

    {
        echo ""
        echo "=== SUMMARY ==="
        echo "STEPS_PASSED: ${STEPS_PASSED}"
        echo "TOTAL_STEPS: ${TOTAL_STEPS}"
        echo "POLICY_GAPS: ${POLICY_GAPS}"
        echo "FALCO_ALERT_COUNT: ${FALCO_COUNT}"
        echo "DETECTION_STATUS: $( [[ "${FALCO_COUNT}" -gt 0 ]] && echo DETECTED || echo UNDETECTED )"
        echo "MTTD_SECONDS: 0"
        echo "OVERALL_STATUS: ${OVERALL_STATUS}"
        echo "END_TIME: ${END_ISO}"
    } >> "${RESULT_FILE}"

    sed -i "/^---$/i DETECTION_STATUS: $( [[ "${FALCO_COUNT}" -gt 0 ]] && echo DETECTED || echo UNDETECTED )\nFALCO_ALERT_COUNT: ${FALCO_COUNT}\nMTTD_SECONDS: 0\nSTEPS_PASSED: ${STEPS_PASSED}\nTOTAL_STEPS: ${TOTAL_STEPS}" \
        "${RESULT_FILE}" 2>/dev/null || true

    echo -e "\n${CYAN}Results → ${RESULT_FILE}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

main "$@"
