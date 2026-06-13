#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test-policies.sh
#
# Verifies that OPA Gatekeeper constraints are enforced by attempting to deploy
# pods that violate each policy and confirming they are rejected.
#
# Each test:
#   1. Applies a violating pod manifest via `kubectl apply --dry-run=server`
#      (this exercises the admission webhook without creating real resources)
#   2. Expects the API server to return a non-zero exit code with the constraint
#      name in the error message
#   3. Prints PASS or FAIL
#
# Note on --dry-run=server:
#   `--dry-run=client` skips the admission webhooks entirely and is useless for
#   testing Gatekeeper.  `--dry-run=server` sends the request all the way to
#   the API server, which invokes the ValidatingWebhookConfiguration, so
#   Gatekeeper evaluates the pod spec and rejects it if it violates a constraint.
#
# Usage:
#   bash infra/opa/test-policies.sh
#   bash infra/opa/test-policies.sh --verbose   # show full rejection messages
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PASS=0; FAIL=0; SKIP=0
VERBOSE=false

for arg in "$@"; do
  case "$arg" in
    --verbose|-v) VERBOSE=true ;;
    --help|-h)
      echo "Usage: $0 [--verbose]"
      exit 0 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

pass() { echo -e "  ${GREEN}✓ PASS${RESET}  $*"; (( PASS++ )) || true; }
fail() { echo -e "  ${RED}✗ FAIL${RESET}  $*"; (( FAIL++ )) || true; }
skip() { echo -e "  ${YELLOW}– SKIP${RESET}  $*"; (( SKIP++ )) || true; }
info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }

# ── Preflight ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  OPA Gatekeeper Policy Tests — SecureCloud-BD     ${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""

if ! kubectl cluster-info &>/dev/null; then
  echo -e "${RED}ERROR:${RESET} Cannot reach cluster. Run: bash infra/scripts/setup-cluster.sh"
  exit 1
fi

# Check Gatekeeper is running
if ! kubectl get deployment gatekeeper-controller-manager -n gatekeeper-system &>/dev/null; then
  echo -e "${RED}ERROR:${RESET} Gatekeeper not installed. Run: bash infra/opa/install-gatekeeper.sh"
  exit 1
fi

# Check all ConstraintTemplate CRDs exist
for crd in \
    noprivilegedcontainers.constraints.gatekeeper.sh \
    requireresourcelimits.constraints.gatekeeper.sh \
    allowedregistries.constraints.gatekeeper.sh \
    nohostnamespace.constraints.gatekeeper.sh; do
  if ! kubectl get crd "$crd" &>/dev/null; then
    echo -e "${RED}ERROR:${RESET} CRD '$crd' not found. Run: bash infra/opa/install-gatekeeper.sh"
    exit 1
  fi
done

info "Gatekeeper and ConstraintTemplate CRDs confirmed. Running tests..."
echo ""

# ── Helper: test that a manifest is REJECTED ──────────────────────────────────
# $1 = test description
# $2 = expected substring in rejection message (the constraint kind or error text)
# $3 = manifest YAML (heredoc string)
expect_denied() {
  local desc="$1"
  local expected_fragment="$2"
  local manifest="$3"

  local output
  local exit_code=0

  # --dry-run=server invokes the admission webhook
  output=$(echo "$manifest" | kubectl apply --dry-run=server -f - 2>&1) || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    if echo "$output" | grep -qi "$expected_fragment"; then
      pass "$desc"
      $VERBOSE && echo -e "       ${CYAN}Rejection message:${RESET} $(echo "$output" | head -3)"
    else
      # Rejected but not by the expected constraint — unexpected error
      fail "$desc — rejected but constraint name not found in output"
      echo -e "       Expected: ${YELLOW}$expected_fragment${RESET}"
      echo -e "       Got: ${RED}$(echo "$output" | head -5)${RESET}"
    fi
  else
    # kubectl returned 0 → the pod was NOT rejected (constraint not working)
    fail "$desc — pod was ADMITTED when it should have been DENIED"
    $VERBOSE && echo -e "       ${YELLOW}Output: $output${RESET}"
  fi
}

# ── Helper: test that a COMPLIANT manifest is ADMITTED ───────────────────────
expect_admitted() {
  local desc="$1"
  local manifest="$2"

  local output
  local exit_code=0

  output=$(echo "$manifest" | kubectl apply --dry-run=server -f - 2>&1) || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    pass "$desc"
  else
    fail "$desc — compliant pod was unexpectedly DENIED"
    echo -e "       ${RED}Output: $(echo "$output" | head -5)${RESET}"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 1: NoPrivilegedContainers
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}1. NoPrivilegedContainers${RESET}"

expect_denied \
  "privileged: true container is rejected" \
  "noprivilegedcontainers" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged-violating
  namespace: apps
spec:
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        privileged: true
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_admitted \
  "non-privileged container is admitted" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged-compliant
  namespace: apps
spec:
  containers:
    - name: ok
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 1001
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 2: RequireResourceLimits
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}2. RequireResourceLimits${RESET}"

expect_denied \
  "missing cpu limit is rejected" \
  "requireresourcelimits" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-limits-no-cpu
  namespace: apps
spec:
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          memory: "64Mi"
          # cpu limit intentionally missing
EOF
)"

expect_denied \
  "missing memory limit is rejected" \
  "requireresourcelimits" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-limits-no-memory
  namespace: apps
spec:
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          # memory limit intentionally missing
EOF
)"

expect_denied \
  "no resources block at all is rejected" \
  "requireresourcelimits" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-limits-none
  namespace: apps
spec:
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
EOF
)"

expect_admitted \
  "container with both limits is admitted" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-limits-compliant
  namespace: apps
spec:
  containers:
    - name: ok
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 3: AllowedRegistries
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}3. AllowedRegistries${RESET}"

expect_denied \
  "unknown registry (docker.evil.io) is rejected" \
  "allowedregistries" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-registry-bad
  namespace: apps
spec:
  containers:
    - name: bad
      image: docker.evil.io/attacker/malicious:latest
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_denied \
  "unqualified image from unknown registry context is rejected" \
  "allowedregistries" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-registry-privateregistry
  namespace: apps
spec:
  containers:
    - name: bad
      image: private-internal-registry.corp/myimage:1.0
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_admitted \
  "docker.io image is admitted" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-registry-dockerio
  namespace: apps
spec:
  containers:
    - name: ok
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_admitted \
  "ghcr.io image is admitted" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-registry-ghcrio
  namespace: apps
spec:
  containers:
    - name: ok
      image: ghcr.io/someowner/someimage:v1.0.0
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 4: NoHostNamespace
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}4. NoHostNamespace${RESET}"

expect_denied \
  "hostNetwork: true is rejected" \
  "nohostnamespace" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-hostnetwork
  namespace: apps
spec:
  hostNetwork: true
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_denied \
  "hostPID: true is rejected" \
  "nohostnamespace" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpid
  namespace: apps
spec:
  hostPID: true
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_denied \
  "hostIPC: true is rejected" \
  "nohostnamespace" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-hostipc
  namespace: apps
spec:
  hostIPC: true
  containers:
    - name: bad
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

expect_admitted \
  "pod without host namespace fields is admitted" \
  "$(cat <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-hostns-compliant
  namespace: apps
spec:
  containers:
    - name: ok
      image: docker.io/library/busybox:1.36
      command: ["sh", "-c", "sleep 3600"]
      resources:
        limits:
          cpu: "100m"
          memory: "64Mi"
EOF
)"

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 5: Audit report (existing violations in cluster)
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}5. Audit report (existing violations in cluster)${RESET}"
info "Gatekeeper audits running workloads every 30s. Current violations:"
echo ""

for kind in \
    noprivilegedcontainers \
    requireresourcelimits \
    allowedregistries \
    nohostnamespace; do
  violations=$(kubectl get "$kind" -A -o json 2>/dev/null | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
total = 0
for item in data.get('items', []):
    v = item.get('status', {}).get('totalViolations', 0)
    if v:
        name = item['metadata']['name']
        print(f'  {name}: {v} violation(s)')
        total += v
if total == 0:
    print('  (no violations)')
" 2>/dev/null || echo "  (kubectl query failed)")
  echo -e "  ${BOLD}${kind}${RESET}:"
  echo "$violations"
done

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
TOTAL=$(( PASS + FAIL + SKIP ))
echo -e "${BOLD}  Results: ${GREEN}${PASS} passed${RESET} / ${RED}${FAIL} failed${RESET} / ${YELLOW}${SKIP} skipped${RESET} (of ${TOTAL} tests)${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""

if (( FAIL > 0 )); then
  echo -e "${RED}One or more policy tests failed.${RESET}"
  echo -e "Troubleshooting:"
  echo -e "  kubectl get constrainttemplates"
  echo -e "  kubectl get constraints -A"
  echo -e "  kubectl describe noprivilegedcontainers deny-privileged-containers-apps"
  echo -e "  kubectl logs -n gatekeeper-system -l control-plane=controller-manager --tail=50"
  exit 1
fi

echo -e "${GREEN}All OPA Gatekeeper policy tests passed.${RESET}"
