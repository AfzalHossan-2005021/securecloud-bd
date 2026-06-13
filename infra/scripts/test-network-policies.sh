#!/usr/bin/env bash
# infra/scripts/test-network-policies.sh
#
# Verifies that Kubernetes NetworkPolicies enforce the intended zero-trust
# segmentation for the bKash demo application.
#
# Test matrix
# ┌─────────────────────────────────┬──────────┬────────────────────────────────┐
# │ Connection                      │ Expected │ Policy governing it            │
# ├─────────────────────────────────┼──────────┼────────────────────────────────┤
# │ frontend       → payment-api    │ ALLOWED  │ allow-frontend-to-api.yaml     │
# │ frontend       → user-db        │ BLOCKED  │ default-deny-all.yaml          │
# │ payment-api    → user-db        │ ALLOWED  │ allow-api-to-db.yaml           │
# │ frontend       → external IP    │ BLOCKED  │ default-deny-all.yaml (egress) │
# │ any pod        → kube-dns       │ ALLOWED  │ allow-egress-dns.yaml          │
# └─────────────────────────────────┴──────────┴────────────────────────────────┘
#
# Usage:
#   bash infra/scripts/test-network-policies.sh [OPTIONS]
#
# Options:
#   --namespace   NS   Target namespace (default: apps)
#   --timeout     N    nc/curl timeout in seconds (default: 5)
#   --verbose          Print full kubectl exec output for each test
#   --skip-apply       Skip policy apply step (policies already in cluster)
#   --dry-run          Print test commands without running them

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

pass()  { echo -e "  ${GREEN}✓ PASS${RESET}  $*"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()  { echo -e "  ${RED}✗ FAIL${RESET}  $*"; FAIL_COUNT=$((FAIL_COUNT+1)); }
skip()  { echo -e "  ${YELLOW}~ SKIP${RESET}  $*"; }
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
header(){ echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

PASS_COUNT=0
FAIL_COUNT=0

# ─────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────
NAMESPACE=apps
TIMEOUT=5
VERBOSE=false
SKIP_APPLY=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)  NAMESPACE="$2"; shift 2 ;;
    --timeout)    TIMEOUT="$2";   shift 2 ;;
    --verbose)    VERBOSE=true;   shift ;;
    --skip-apply) SKIP_APPLY=true; shift ;;
    --dry-run)    DRY_RUN=true;   shift ;;
    -h|--help)
      sed -n '/^# Usage/,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
POLICY_DIR="${REPO_ROOT}/infra/network-policies"

# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

# Run a command, respecting --dry-run.
# Returns the exit code of the command (or 0 in dry-run).
run_cmd() {
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${YELLOW}[DRY-RUN]${RESET} $*"
    return 0
  fi
  "$@"
}

# Return the name of the first Running pod matching an app label.
get_pod() {
  local app="$1"
  kubectl get pod \
    -n "${NAMESPACE}" \
    -l "app=${app}" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Execute a command inside a pod and return its exit code.
# Usage: exec_in_pod <pod> <namespace> -- <cmd...>
exec_in_pod() {
  local pod="$1" ns="$2"; shift 2
  if [[ "$VERBOSE" == true ]]; then
    kubectl exec -n "${ns}" "${pod}" -- "$@"
  else
    kubectl exec -n "${ns}" "${pod}" -- "$@" >/dev/null 2>&1
  fi
}

# Test that a TCP connection SUCCEEDS (exit 0 from nc).
# Usage: assert_reachable <label> <from-pod> <from-ns> <host> <port>
assert_reachable() {
  local label="$1" from_pod="$2" from_ns="$3" host="$4" port="$5"
  if [[ "$DRY_RUN" == true ]]; then
    skip "[DRY-RUN] ${label}"
    return
  fi
  if exec_in_pod "${from_pod}" "${from_ns}" \
       nc -z -w "${TIMEOUT}" "${host}" "${port}"; then
    pass "${label}"
  else
    fail "${label}  (expected reachable — got timeout/refused)"
  fi
}

# Test that a TCP connection FAILS (nc exits non-zero within timeout).
# The test PASSES if nc cannot connect (policy is blocking correctly).
# Usage: assert_blocked <label> <from-pod> <from-ns> <host> <port>
assert_blocked() {
  local label="$1" from_pod="$2" from_ns="$3" host="$4" port="$5"
  if [[ "$DRY_RUN" == true ]]; then
    skip "[DRY-RUN] ${label}"
    return
  fi
  if exec_in_pod "${from_pod}" "${from_ns}" \
       nc -z -w "${TIMEOUT}" "${host}" "${port}"; then
    fail "${label}  (expected BLOCKED — but connection SUCCEEDED; policy gap!)"
  else
    pass "${label}"
  fi
}

# Test DNS resolution works from a pod.
assert_dns() {
  local label="$1" from_pod="$2" from_ns="$3" hostname="$4"
  if [[ "$DRY_RUN" == true ]]; then
    skip "[DRY-RUN] ${label}"
    return
  fi
  if exec_in_pod "${from_pod}" "${from_ns}" \
       nslookup "${hostname}" >/dev/null 2>&1 \
     || exec_in_pod "${from_pod}" "${from_ns}" \
       getent hosts "${hostname}" >/dev/null 2>&1; then
    pass "${label}"
  else
    fail "${label}  (DNS resolution failed — check allow-egress-dns.yaml)"
  fi
}

# Test that an HTTP endpoint returns 200.
assert_http_200() {
  local label="$1" from_pod="$2" from_ns="$3" url="$4"
  if [[ "$DRY_RUN" == true ]]; then
    skip "[DRY-RUN] ${label}"
    return
  fi
  local status
  status=$(kubectl exec -n "${from_ns}" "${from_pod}" -- \
    curl -s -o /dev/null -w "%{http_code}" \
    --max-time "${TIMEOUT}" "${url}" 2>/dev/null || echo "000")
  if [[ "$status" == "200" ]]; then
    pass "${label}  (HTTP ${status})"
  else
    fail "${label}  (expected HTTP 200 — got HTTP ${status})"
  fi
}

# ─────────────────────────────────────────────────────────────────────
# 0. Pre-flight checks
# ─────────────────────────────────────────────────────────────────────
header "Pre-flight checks"

if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  echo -e "${RED}ERROR: Namespace '${NAMESPACE}' not found.${RESET}" >&2
  echo "       Run 'make deploy-apps' or 'bash infra/apps/deploy.sh' first." >&2
  exit 1
fi
info "Namespace '${NAMESPACE}' exists"

for tool in kubectl nc curl nslookup; do
  if kubectl exec \
      -n "${NAMESPACE}" \
      "$(kubectl get pod -n "${NAMESPACE}" -l app=frontend \
          -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo 'NOPOD')" \
      -- which "${tool}" &>/dev/null 2>&1; then
    true  # tool is available in the pod
  fi
done

# ─────────────────────────────────────────────────────────────────────
# 1. Apply network policies (unless --skip-apply)
# ─────────────────────────────────────────────────────────────────────
header "Applying NetworkPolicies"

if [[ "$SKIP_APPLY" == true ]]; then
  info "--skip-apply set; assuming policies are already in the cluster"
else
  run_cmd kubectl apply -f "${POLICY_DIR}/default-deny-all.yaml"
  run_cmd kubectl apply -f "${POLICY_DIR}/allow-egress-dns.yaml"
  run_cmd kubectl apply -f "${POLICY_DIR}/allow-frontend-to-api.yaml"
  run_cmd kubectl apply -f "${POLICY_DIR}/allow-api-to-db.yaml"
  info "Policies applied. Waiting 3s for CNI to propagate rules…"
  [[ "$DRY_RUN" == false ]] && sleep 3
fi

# ─────────────────────────────────────────────────────────────────────
# 2. Discover pods
# ─────────────────────────────────────────────────────────────────────
header "Discovering pods in namespace '${NAMESPACE}'"

if [[ "$DRY_RUN" == false ]]; then
  FRONTEND_POD=$(get_pod "frontend")
  API_POD=$(get_pod "payment-api")
  DB_POD=$(get_pod "user-db")

  for pair in "frontend:${FRONTEND_POD}" "payment-api:${API_POD}" "user-db:${DB_POD}"; do
    label="${pair%%:*}"
    pod="${pair##*:}"
    if [[ -z "$pod" ]]; then
      echo -e "${RED}ERROR: No Running pod found for app=${label} in ${NAMESPACE}.${RESET}" >&2
      echo "       Deploy the app first: bash infra/apps/deploy.sh" >&2
      exit 1
    fi
    info "  app=${label} → pod=${pod}"
  done
else
  FRONTEND_POD="frontend-xxxx"
  API_POD="payment-api-xxxx"
  DB_POD="user-db-0"
  info "(Dry-run) pod names: ${FRONTEND_POD}, ${API_POD}, ${DB_POD}"
fi

# Stable DNS names for services inside the cluster
API_HOST="payment-api.${NAMESPACE}.svc.cluster.local"
DB_HOST="user-db.${NAMESPACE}.svc.cluster.local"

# ─────────────────────────────────────────────────────────────────────
# 3. DNS reachability — allow-egress-dns.yaml
# ─────────────────────────────────────────────────────────────────────
header "DNS reachability (allow-egress-dns.yaml)"

assert_dns \
  "frontend can resolve payment-api DNS name" \
  "${FRONTEND_POD}" "${NAMESPACE}" "${API_HOST}"

assert_dns \
  "payment-api can resolve user-db DNS name" \
  "${API_POD}" "${NAMESPACE}" "${DB_HOST}"

# ─────────────────────────────────────────────────────────────────────
# 4. Allowed flows — must SUCCEED
# ─────────────────────────────────────────────────────────────────────
header "Allowed connections (must succeed)"

# frontend → payment-api:8000
assert_reachable \
  "frontend → payment-api TCP 8000 (allow-frontend-to-api.yaml)" \
  "${FRONTEND_POD}" "${NAMESPACE}" \
  "${API_HOST}" 8000

# Verify the HTTP health endpoint too
assert_http_200 \
  "frontend → payment-api GET /health returns 200" \
  "${FRONTEND_POD}" "${NAMESPACE}" \
  "http://${API_HOST}:8000/health"

# payment-api → user-db:5432
assert_reachable \
  "payment-api → user-db TCP 5432 (allow-api-to-db.yaml)" \
  "${API_POD}" "${NAMESPACE}" \
  "${DB_HOST}" 5432

# ─────────────────────────────────────────────────────────────────────
# 5. Blocked flows — must TIME OUT
# ─────────────────────────────────────────────────────────────────────
header "Blocked connections (must time out — default-deny-all.yaml)"

# frontend → user-db:5432   MUST be blocked
# This is the critical security assertion: the UI layer cannot bypass the
# API and query the database directly.
assert_blocked \
  "frontend → user-db TCP 5432  BLOCKED (critical: no direct DB access from UI)" \
  "${FRONTEND_POD}" "${NAMESPACE}" \
  "${DB_HOST}" 5432

# frontend → random internal port on payment-api (only 8000 is allowed)
assert_blocked \
  "frontend → payment-api TCP 5432  BLOCKED (port not permitted)" \
  "${FRONTEND_POD}" "${NAMESPACE}" \
  "${API_HOST}" 5432

# payment-api → external internet  MUST be blocked (egress default-deny)
assert_blocked \
  "payment-api → 1.1.1.1 TCP 80  BLOCKED (egress default-deny)" \
  "${API_POD}" "${NAMESPACE}" \
  "1.1.1.1" 80

# frontend → external internet  MUST be blocked
assert_blocked \
  "frontend → 8.8.8.8 TCP 443  BLOCKED (egress default-deny)" \
  "${FRONTEND_POD}" "${NAMESPACE}" \
  "8.8.8.8" 443

# ─────────────────────────────────────────────────────────────────────
# 6. List active policies for audit trail
# ─────────────────────────────────────────────────────────────────────
header "Active NetworkPolicies in '${NAMESPACE}'"

if [[ "$DRY_RUN" == false ]]; then
  kubectl get networkpolicies -n "${NAMESPACE}" \
    -o custom-columns='NAME:.metadata.name,POD-SELECTOR:.spec.podSelector,TYPES:.spec.policyTypes' \
    2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────
# 7. Summary
# ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║     Network Policy Test Results          ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${GREEN}Passed:${RESET} ${PASS_COUNT}"
echo -e "  ${RED}Failed:${RESET} ${FAIL_COUNT}"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo -e "${RED}${BOLD}RESULT: FAIL — ${FAIL_COUNT} test(s) did not meet the expected outcome.${RESET}"
  echo ""
  echo "  Troubleshooting hints:"
  echo "  • 'ALLOWED but got timeout' → check the allow policy exists and label"
  echo "    selectors match the pod labels exactly (kubectl get pod --show-labels)"
  echo "  • 'BLOCKED but got success' → the CNI plugin may not enforce NetworkPolicy."
  echo "    Minikube requires --cni=calico or --cni=cilium for enforcement."
  echo "    Run: minikube start --cni=calico"
  echo "  • Apply order: default-deny must be applied BEFORE allow policies."
  echo ""
  exit 1
else
  echo -e "${GREEN}${BOLD}RESULT: PASS — all ${PASS_COUNT} assertions matched expectations.${RESET}"
  echo ""
  exit 0
fi
