#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# install-gatekeeper.sh
#
# Installs OPA Gatekeeper into the cluster using Helm, then applies all
# ConstraintTemplates and Constraints from this directory.
#
# Prerequisites:
#   - kubectl configured to point at the target cluster
#   - helm 3 installed
#   - Cluster must be running (minikube, k3s, or any conformant Kubernetes ≥1.26)
#
# Usage:
#   bash infra/opa/install-gatekeeper.sh
#   bash infra/opa/install-gatekeeper.sh --dry-run
#   bash infra/opa/install-gatekeeper.sh --uninstall
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── CLI flags ──────────────────────────────────────────────────────────────────
DRY_RUN=false
UNINSTALL=false
GATEKEEPER_VERSION="3.16.3"   # pin to a tested version; bump deliberately
NAMESPACE="gatekeeper-system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=true ;;
    --uninstall) UNINSTALL=true ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--uninstall]"
      echo "  --dry-run    Print what would happen without making changes"
      echo "  --uninstall  Remove Gatekeeper and all constraints"
      exit 0 ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# ── kubectl dry-run wrapper ────────────────────────────────────────────────────
kubectl_apply() {
  if "$DRY_RUN"; then
    info "[DRY-RUN] kubectl apply $*"
  else
    kubectl apply "$@"
  fi
}

# ── Uninstall path ─────────────────────────────────────────────────────────────
if "$UNINSTALL"; then
  warn "Removing all Constraints and ConstraintTemplates..."
  kubectl delete -f "${SCRIPT_DIR}/constraints/" --ignore-not-found 2>/dev/null || true
  kubectl delete -f "${SCRIPT_DIR}/constraint-templates/" --ignore-not-found 2>/dev/null || true
  warn "Uninstalling Gatekeeper Helm release..."
  helm uninstall gatekeeper -n "${NAMESPACE}" 2>/dev/null || true
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found 2>/dev/null || true
  success "Gatekeeper uninstalled."
  exit 0
fi

# ── Preflight checks ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  OPA Gatekeeper Installation — SecureCloud-BD     ${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""

info "Verifying prerequisites..."

if ! command -v kubectl &>/dev/null; then
  die "kubectl not found. Install kubectl and configure your kubeconfig."
fi

if ! command -v helm &>/dev/null; then
  die "helm not found. Install Helm 3 from https://helm.sh/docs/intro/install/"
fi

HELM_VERSION=$(helm version --short 2>/dev/null | grep -oE 'v[0-9]+' | head -1)
if [[ "${HELM_VERSION:-v2}" == "v2" ]]; then
  die "Helm 2 detected. This script requires Helm 3."
fi

if ! kubectl cluster-info &>/dev/null; then
  die "Cannot reach Kubernetes cluster. Check your kubeconfig."
fi

success "Prerequisites OK"

# ── Add Gatekeeper Helm repo ───────────────────────────────────────────────────
info "Adding OPA Gatekeeper Helm repository..."
if "$DRY_RUN"; then
  info "[DRY-RUN] helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts"
else
  helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || \
    info "Repo already exists, updating..."
  helm repo update gatekeeper
fi
success "Helm repo ready"

# ── Install / upgrade Gatekeeper ──────────────────────────────────────────────
info "Installing Gatekeeper v${GATEKEEPER_VERSION} in namespace ${NAMESPACE}..."

HELM_ARGS=(
  upgrade --install gatekeeper gatekeeper/gatekeeper
  --namespace "${NAMESPACE}"
  --create-namespace
  --version "${GATEKEEPER_VERSION}"
  --set replicas=1                    # single-node constraint (8 GB RAM)
  --set auditInterval=30              # audit every 30s (default 60s)
  --set constraintViolationsLimit=20  # report up to 20 violations per constraint
  --set logLevel=INFO
  # Emit violations as structured JSON so Filebeat can ship them to ELK
  --set logDenies=true
  # Resource limits tuned for single-node 8 GB workstation
  --set resources.limits.memory=512Mi
  --set resources.limits.cpu=500m
  --set resources.requests.memory=256Mi
  --set resources.requests.cpu=100m
  --wait
  --timeout 3m
)

if "$DRY_RUN"; then
  info "[DRY-RUN] helm ${HELM_ARGS[*]}"
else
  helm "${HELM_ARGS[@]}"
fi
success "Gatekeeper installed"

# ── Wait for webhook to be ready ──────────────────────────────────────────────
if ! "$DRY_RUN"; then
  info "Waiting for Gatekeeper controller pods to be ready..."
  kubectl wait --for=condition=Available \
    deployment/gatekeeper-controller-manager \
    -n "${NAMESPACE}" \
    --timeout=120s
  success "Gatekeeper controller ready"

  # Gatekeeper registers a ValidatingWebhookConfiguration; give the apiserver
  # a moment to pick it up before we apply CRDs.
  info "Sleeping 5s for webhook registration..."
  sleep 5
fi

# ── Apply ConstraintTemplates ──────────────────────────────────────────────────
info "Applying ConstraintTemplates..."

TEMPLATES=(
  "${SCRIPT_DIR}/constraint-templates/no-privileged-containers.yaml"
  "${SCRIPT_DIR}/constraint-templates/require-resource-limits.yaml"
  "${SCRIPT_DIR}/constraint-templates/allowed-registries.yaml"
  "${SCRIPT_DIR}/constraint-templates/no-host-namespace.yaml"
)

for tmpl in "${TEMPLATES[@]}"; do
  if [[ ! -f "$tmpl" ]]; then
    warn "Template not found, skipping: $tmpl"
    continue
  fi
  kubectl_apply -f "$tmpl"
  success "Applied: $(basename "$tmpl")"
done

# Wait for the CRDs created by ConstraintTemplates to be established
if ! "$DRY_RUN"; then
  info "Waiting for ConstraintTemplate CRDs to be established..."
  sleep 10
  kubectl wait --for=condition=Established \
    crd/noprivilegedcontainers.constraints.gatekeeper.sh \
    crd/requireresourcelimits.constraints.gatekeeper.sh \
    crd/allowedregistries.constraints.gatekeeper.sh \
    crd/nohostnamespace.constraints.gatekeeper.sh \
    --timeout=60s 2>/dev/null || \
    warn "Some CRDs may not be ready yet; constraints may fail if applied immediately."
fi

# ── Apply Constraints ──────────────────────────────────────────────────────────
info "Applying Constraints..."

CONSTRAINTS=(
  "${SCRIPT_DIR}/constraints/no-privileged-containers.yaml"
  "${SCRIPT_DIR}/constraints/require-resource-limits.yaml"
  "${SCRIPT_DIR}/constraints/allowed-registries.yaml"
  "${SCRIPT_DIR}/constraints/no-host-namespace.yaml"
)

for constraint in "${CONSTRAINTS[@]}"; do
  if [[ ! -f "$constraint" ]]; then
    warn "Constraint not found, skipping: $constraint"
    continue
  fi
  kubectl_apply -f "$constraint"
  success "Applied: $(basename "$constraint")"
done

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation Summary${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"

if ! "$DRY_RUN"; then
  echo ""
  echo -e "${BOLD}Gatekeeper pods:${RESET}"
  kubectl get pods -n "${NAMESPACE}" 2>/dev/null || true

  echo ""
  echo -e "${BOLD}ConstraintTemplates:${RESET}"
  kubectl get constrainttemplates 2>/dev/null || true

  echo ""
  echo -e "${BOLD}Constraints:${RESET}"
  kubectl get constraints -A 2>/dev/null || true
fi

echo ""
success "OPA Gatekeeper installation complete."
echo ""
echo -e "  Run ${CYAN}bash infra/opa/test-policies.sh${RESET} to verify constraints are enforced."
echo ""
