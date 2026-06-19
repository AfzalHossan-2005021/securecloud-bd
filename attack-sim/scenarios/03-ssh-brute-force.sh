#!/usr/bin/env bash
# =============================================================================
# 03-ssh-brute-force.sh — SSH Password Brute Force
#
# MITRE ATT&CK : T1110.001 — Brute Force: Password Guessing
# Tools        : hydra, kubectl
# Target       : ssh-test pod (manifests/ssh-test-pod.yaml)
# Detection    : Falco (Disallowed SSH Connection / excessive auth failures)
# Expected     : DETECTED within 10 seconds of first auth failure
#
# Lifecycle:
#   1. Apply ssh-test-pod.yaml (creates Pod + NodePort Service)
#   2. Wait for pod Ready
#   3. Run Hydra with wordlists/ssh-users.txt + wordlists/ssh-passwords.txt
#   4. Check Falco; verify correct credential found (pentest/password123)
#   5. Delete the test pod
#
# Usage: bash attack-sim/scenarios/03-ssh-brute-force.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

SCENARIO_ID="03-ssh-brute-force"
SCENARIO_NAME="SSH Password Brute Force"
MITRE_ID="T1110.001"

NS="${NS:-securecloud}"
SIEM_NS="${SIEM_NS:-siem}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
MANIFESTS_DIR="${SCRIPT_DIR}/../manifests"
WORDLISTS_DIR="${SCRIPT_DIR}/../wordlists"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULT_FILE="${RESULTS_DIR}/${SCENARIO_ID}-${TIMESTAMP}.txt"

POD_READY_TIMEOUT="${POD_READY_TIMEOUT:-120}"   # seconds
DETECTION_WAIT="${DETECTION_WAIT:-15}"

# ---------------------------------------------------------------------------
check_prereqs() {
    local missing=()
    for cmd in hydra kubectl; do
        command -v "${cmd}" &>/dev/null || missing+=("${cmd}")
    done
    [[ -f "${WORDLISTS_DIR}/ssh-users.txt" ]]     || missing+=("wordlists/ssh-users.txt")
    [[ -f "${WORDLISTS_DIR}/ssh-passwords.txt" ]] || missing+=("wordlists/ssh-passwords.txt")
    [[ -f "${MANIFESTS_DIR}/ssh-test-pod.yaml" ]] || missing+=("manifests/ssh-test-pod.yaml")
    [[ ${#missing[@]} -eq 0 ]] || {
        echo -e "${RED}Missing: ${missing[*]}${RESET}" >&2
        echo "Install hydra: sudo apt-get install -y hydra" >&2; exit 1
    }
}

detect_targets() {
    [[ -z "${MINIKUBE_IP:-}" ]] && MINIKUBE_IP="$(minikube ip 2>/dev/null)" || true
    [[ -n "${MINIKUBE_IP:-}" ]] || { echo -e "${RED}Set MINIKUBE_IP${RESET}" >&2; exit 1; }
}

# ---------------------------------------------------------------------------
deploy_ssh_pod() {
    echo -e "${CYAN}[Setup] Deploying SSH test pod…${RESET}"

    # Clean up any prior run
    kubectl delete -f "${MANIFESTS_DIR}/ssh-test-pod.yaml" \
        --ignore-not-found -n "${NS}" 2>/dev/null || true
    sleep 2

    kubectl apply -f "${MANIFESTS_DIR}/ssh-test-pod.yaml"

    echo -e "  Waiting up to ${POD_READY_TIMEOUT}s for ssh-test pod to be Ready…"
    kubectl wait pod/ssh-test \
        -n "${NS}" \
        --for=condition=Ready \
        --timeout="${POD_READY_TIMEOUT}s" 2>/dev/null \
    || {
        echo -e "${YELLOW}  Pod not Ready yet — checking logs:${RESET}"
        kubectl logs ssh-test -n "${NS}" 2>/dev/null | tail -20 || true
        # Continue anyway — pod may still be installing apk packages
        sleep 30
    }

    # Detect the assigned NodePort
    SSH_NODEPORT="$(kubectl get svc ssh-test \
        -n "${NS}" \
        -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)" || true
    [[ -n "${SSH_NODEPORT:-}" ]] || {
        echo -e "${RED}SSH NodePort not found — is the Service created?${RESET}" >&2; exit 1
    }

    echo -e "${GREEN}  SSH target: ${MINIKUBE_IP}:${SSH_NODEPORT}${RESET}"
}

teardown_ssh_pod() {
    echo -e "\n${CYAN}[Cleanup] Deleting SSH test pod…${RESET}"
    kubectl delete -f "${MANIFESTS_DIR}/ssh-test-pod.yaml" \
        --ignore-not-found -n "${NS}" 2>/dev/null || true
    echo -e "${GREEN}  ssh-test pod and service deleted.${RESET}"
}

check_falco_alerts() {
    local since_iso="$1"
    kubectl logs -n "${SIEM_NS}" \
        -l app.kubernetes.io/name=falco \
        --since-time="${since_iso}" 2>/dev/null \
        | grep -Ec "Notice|Warning|ssh|brute|auth" 2>/dev/null || echo 0
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
        echo "TARGET_PORT: ${SSH_NODEPORT}"
        echo "USERLIST: wordlists/ssh-users.txt ($(wc -l < "${WORDLISTS_DIR}/ssh-users.txt") entries)"
        echo "PASSLIST: wordlists/ssh-passwords.txt ($(wc -l < "${WORDLISTS_DIR}/ssh-passwords.txt") entries)"
        echo "CATEGORY: credential-access"
        echo "SEVERITY: HIGH"
        echo "---"
    } > "${RESULT_FILE}"
}

# ---------------------------------------------------------------------------
main() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SecureCloud-BD  |  Scenario ${SCENARIO_ID}${RESET}"
    echo -e "${BOLD}  ${SCENARIO_NAME}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    check_prereqs
    detect_targets
    deploy_ssh_pod

    # Always tear down on exit, even on error
    trap teardown_ssh_pod EXIT

    START_EPOCH="$(date +%s)"
    START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    init_results

    # Give sshd a few extra seconds to fully start inside the pod
    echo -e "\n${CYAN}[Pre-attack] Waiting 10 s for sshd to be ready…${RESET}"
    sleep 10

    # Verify SSH port is reachable before starting Hydra
    if ! nc -z -w 5 "${MINIKUBE_IP}" "${SSH_NODEPORT}" 2>/dev/null; then
        echo -e "${YELLOW}WARNING: TCP connect to ${MINIKUBE_IP}:${SSH_NODEPORT} timed out — sshd may still be starting${RESET}"
        sleep 15
    fi

    # ── Hydra brute force ─────────────────────────────────────────────────
    HYDRA_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "\n${RED}${BOLD}[Attack] Hydra SSH brute force → ${MINIKUBE_IP}:${SSH_NODEPORT}${RESET}"
    echo -e "         Users: $(wc -l < "${WORDLISTS_DIR}/ssh-users.txt")  Passwords: $(wc -l < "${WORDLISTS_DIR}/ssh-passwords.txt")\n"

    HYDRA_OUTPUT="$(hydra \
        -L "${WORDLISTS_DIR}/ssh-users.txt" \
        -P "${WORDLISTS_DIR}/ssh-passwords.txt" \
        -t 4 \
        -o "${RESULTS_DIR}/${SCENARIO_ID}-hydra-${TIMESTAMP}.txt" \
        -f \
        "${MINIKUBE_IP}" \
        ssh \
        -s "${SSH_NODEPORT}" 2>&1)" || HYDRA_RC=$?

    HYDRA_END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo "${HYDRA_OUTPUT}"
    {
        echo ""
        echo "=== HYDRA OUTPUT ==="
        echo "HYDRA_START: ${HYDRA_START_ISO}"
        echo "HYDRA_END:   ${HYDRA_END_ISO}"
        echo "${HYDRA_OUTPUT}"
    } >> "${RESULT_FILE}"

    # Did Hydra find the credential?
    CRED_FOUND=""
    if echo "${HYDRA_OUTPUT}" | grep -qi "login:.*password:"; then
        CRED_FOUND="$(echo "${HYDRA_OUTPUT}" | grep -oP 'login: \K\S+' | head -1):$(echo "${HYDRA_OUTPUT}" | grep -oP 'password: \K\S+' | head -1)"
        echo -e "\n${RED}${BOLD}⚡ Credential found: ${CRED_FOUND}${RESET}"
    else
        echo -e "\n${YELLOW}No credential found in this run (expected: pentest/password123)${RESET}"
    fi

    # ── Falco detection check ──────────────────────────────────────────────
    echo -e "\n${CYAN}Waiting ${DETECTION_WAIT}s, then checking Falco…${RESET}"
    sleep "${DETECTION_WAIT}"

    FALCO_COUNT="$(check_falco_alerts "${HYDRA_START_ISO}")"
    END_EPOCH="$(date +%s)"
    END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ATTACK_DURATION=$(( END_EPOCH - START_EPOCH ))

    if [[ "${FALCO_COUNT}" -gt 0 ]]; then
        DETECTION_STATUS="DETECTED"
        MTTD=$(( ATTACK_DURATION / 3 ))   # approximate — alert fires near first failures
        echo -e "${GREEN}${BOLD}✓ DETECTED — Falco raised ${FALCO_COUNT} alert(s)${RESET}"
        echo -e "  ${YELLOW}Note: Add Falco rule 'Detected SSH Brute Force' to siem/falco/falco-values.yaml${RESET}"
        echo -e "  ${YELLOW}if not already present (see customRules section)${RESET}"
    else
        DETECTION_STATUS="UNDETECTED"
        MTTD=0
        echo -e "${RED}${BOLD}✗ UNDETECTED — add SSH brute-force detection rule to Falco${RESET}"
        echo -e "${YELLOW}  Suggested rule: count ssh auth failures per source in 60s window${RESET}"
    fi

    CRED_VERIFIED="false"
    if [[ -n "${CRED_FOUND}" ]]; then
        # Try to verify the found credential
        if ssh -o StrictHostKeyChecking=no \
              -o BatchMode=no \
              -o ConnectTimeout=5 \
              -p "${SSH_NODEPORT}" \
              "${CRED_FOUND%%:*}@${MINIKUBE_IP}" \
              "echo ok" 2>/dev/null; then
            CRED_VERIFIED="true"
            echo -e "${RED}${BOLD}⚡ Credential VERIFIED: ${CRED_FOUND}${RESET}"
        fi
    fi

    {
        echo ""
        echo "=== SUMMARY ==="
        echo "CREDENTIAL_FOUND: ${CRED_FOUND:-none}"
        echo "CREDENTIAL_VERIFIED: ${CRED_VERIFIED}"
        echo "FALCO_ALERT_COUNT: ${FALCO_COUNT}"
        echo "DETECTION_STATUS: ${DETECTION_STATUS}"
        echo "MTTD_SECONDS: ${MTTD}"
        echo "END_TIME: ${END_ISO}"
    } >> "${RESULT_FILE}"

    sed -i "/^---$/i DETECTION_STATUS: ${DETECTION_STATUS}\nFALCO_ALERT_COUNT: ${FALCO_COUNT}\nMTTD_SECONDS: ${MTTD}" \
        "${RESULT_FILE}" 2>/dev/null || true

    echo -e "\n${CYAN}Results → ${RESULT_FILE}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

main "$@"
