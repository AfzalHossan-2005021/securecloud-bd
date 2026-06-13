#!/usr/bin/env bash
# infra/istio/install-istio.sh
#
# Installs Istio using istioctl with the "demo" profile, waits for the control
# plane to be ready, then applies STRICT mTLS across all project namespaces.
#
# Idempotent: safe to re-run. Detects existing installations and upgrades
# in-place rather than failing.
#
# Usage:
#   bash infra/istio/install-istio.sh [OPTIONS]
#
# Options:
#   --version  X.Y.Z   Istio version to install (default: 1.21.2)
#   --dry-run          Print commands without executing them
#   --skip-download    Use an istioctl already on PATH

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
  CYAN='\033[0;36m' BOLD='\033[1m' RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ─────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────
ISTIO_VERSION="1.21.2"
DRY_RUN=false
SKIP_DOWNLOAD=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)       ISTIO_VERSION="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=true;       shift ;;
    --skip-download) SKIP_DOWNLOAD=true; shift ;;
    -h|--help)
      sed -n '/^# Usage/,/^[^#]/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Namespaces that will receive sidecar injection and STRICT mTLS
NAMESPACES=(apps ml-engine monitoring securecloud siem ml)

run() {
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${YELLOW}[DRY-RUN]${RESET} $*"
  else
    "$@"
  fi
}

# ─────────────────────────────────────────────────────────────────────
# Step 1 — Prerequisites
# ─────────────────────────────────────────────────────────────────────
header "Step 1 — Checking prerequisites"

command -v kubectl >/dev/null || die "kubectl not found on PATH"
command -v helm    >/dev/null || die "helm not found on PATH"
success "kubectl $(kubectl version --client -o json 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["clientVersion"]["gitVersion"])' \
  2>/dev/null || kubectl version --client --short 2>/dev/null | head -1)"

if ! kubectl cluster-info &>/dev/null; then
  die "kubectl cannot reach a cluster. Start one first:\n  make start-cluster"
fi
success "Cluster reachable: $(kubectl config current-context)"

# ─────────────────────────────────────────────────────────────────────
# Step 2 — Download istioctl
# ─────────────────────────────────────────────────────────────────────
header "Step 2 — Obtaining istioctl ${ISTIO_VERSION}"

ISTIOCTL=""

if [[ "$SKIP_DOWNLOAD" == true ]] && command -v istioctl &>/dev/null; then
  ISTIOCTL="istioctl"
  success "Using existing istioctl: $(istioctl version --remote=false 2>/dev/null || true)"
elif command -v istioctl &>/dev/null; then
  EXISTING_VER=$(istioctl version --remote=false 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
  if [[ "$EXISTING_VER" == "$ISTIO_VERSION" ]]; then
    ISTIOCTL="istioctl"
    success "istioctl ${EXISTING_VER} already on PATH — skipping download"
  else
    warn "istioctl ${EXISTING_VER} on PATH but requested ${ISTIO_VERSION}; downloading fresh copy"
  fi
fi

if [[ -z "$ISTIOCTL" ]]; then
  DOWNLOAD_DIR="${REPO_ROOT}/istio-${ISTIO_VERSION}"

  if [[ -x "${DOWNLOAD_DIR}/bin/istioctl" ]]; then
    ISTIOCTL="${DOWNLOAD_DIR}/bin/istioctl"
    success "Found cached download at ${DOWNLOAD_DIR}"
  else
    info "Downloading Istio ${ISTIO_VERSION}…"
    run curl -sL https://istio.io/downloadIstio \
      | ISTIO_VERSION="${ISTIO_VERSION}" TARGET_ARCH="$(uname -m)" sh -
    ISTIOCTL="${DOWNLOAD_DIR}/bin/istioctl"
    success "Downloaded to ${DOWNLOAD_DIR}"
  fi
fi

# Export so verify-mtls.sh can find the same binary
export PATH="$(dirname "${ISTIOCTL}"):${PATH}"
ISTIOCTL="$(command -v istioctl)"

# ─────────────────────────────────────────────────────────────────────
# Step 3 — Pre-install check
# ─────────────────────────────────────────────────────────────────────
header "Step 3 — Pre-install compatibility check"

run "${ISTIOCTL}" x precheck 2>/dev/null || {
  warn "istioctl x precheck reported warnings (continuing — some are informational)"
}

# ─────────────────────────────────────────────────────────────────────
# Step 4 — Install / upgrade Istio (demo profile)
#
# The "demo" profile enables:
#   - istiod (Pilot, CA, Galley merged)
#   - istio-ingressgateway
#   - istio-egressgateway
#   - Prometheus, Grafana, Kiali, Jaeger (for observability in dev)
#
# For production, swap "demo" for "default" and manage addons separately.
# The demo profile is chosen here because this project runs on a single
# 8-GB workstation and benefits from the pre-bundled observability stack.
# ─────────────────────────────────────────────────────────────────────
header "Step 4 — Installing Istio (profile: demo)"

ISTIOD_RUNNING=$(kubectl get deployment istiod -n istio-system \
  --ignore-not-found -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")

if [[ "${ISTIOD_RUNNING}" -ge 1 ]] 2>/dev/null; then
  warn "istiod already running (${ISTIOD_RUNNING} replica(s)) — performing in-place upgrade"
  run "${ISTIOCTL}" upgrade \
    --set profile=demo \
    --set values.global.proxy.resources.requests.cpu=50m \
    --set values.global.proxy.resources.requests.memory=64Mi \
    -y
else
  run "${ISTIOCTL}" install \
    --set profile=demo \
    --set values.global.proxy.resources.requests.cpu=50m \
    --set values.global.proxy.resources.requests.memory=64Mi \
    -y
fi

# ─────────────────────────────────────────────────────────────────────
# Step 5 — Wait for control plane
# ─────────────────────────────────────────────────────────────────────
header "Step 5 — Waiting for Istio control plane"

if [[ "$DRY_RUN" == false ]]; then
  info "Waiting for istiod Deployment to be available…"
  kubectl rollout status deployment/istiod \
    -n istio-system \
    --timeout=180s

  info "Waiting for ingress gateway…"
  kubectl rollout status deployment/istio-ingressgateway \
    -n istio-system \
    --timeout=120s

  success "Istio control plane is ready"
  "${ISTIOCTL}" version 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────
# Step 6 — Enable sidecar injection on all project namespaces
#
# The label istio-injection=enabled causes istiod's mutating webhook to
# inject an Envoy proxy sidecar into every new pod in the namespace.
# Existing pods are NOT retroactively injected — they must be restarted.
# ─────────────────────────────────────────────────────────────────────
header "Step 6 — Enabling sidecar injection on project namespaces"

for ns in "${NAMESPACES[@]}"; do
  # Create namespace if it does not exist yet
  if ! kubectl get namespace "${ns}" &>/dev/null; then
    run kubectl create namespace "${ns}"
    info "Created namespace '${ns}'"
  fi

  run kubectl label namespace "${ns}" \
    istio-injection=enabled \
    --overwrite

  # Annotate so operations tooling can identify managed namespaces
  run kubectl annotate namespace "${ns}" \
    securecloud.io/istio-managed=true \
    --overwrite

  success "Namespace '${ns}': istio-injection=enabled"
done

# ─────────────────────────────────────────────────────────────────────
# Step 7 — Apply STRICT mTLS PeerAuthentication and DestinationRules
#
# These two resources work as a complementary pair:
#
#   PeerAuthentication (server-side):
#     Tells the Envoy sidecar on the RECEIVING pod to reject any connection
#     that does not present a valid Istio-issued certificate.  Without this,
#     the sidecar will still accept plain-text connections from pods that
#     do not yet have sidecars (PERMISSIVE mode default).
#
#   DestinationRule (client-side):
#     Tells the Envoy sidecar on the SENDING pod to use ISTIO_MUTUAL TLS
#     when connecting to a destination.  Without this, a pod might send
#     plain-text even though the server requires mTLS, causing 503s.
#
# Together they close both ends of the channel and ensure that:
#   - No plain-text traffic is accepted (server enforcement)
#   - No plain-text traffic is sent (client enforcement)
# ─────────────────────────────────────────────────────────────────────
header "Step 7 — Applying STRICT mTLS policies"

run kubectl apply -f "${SCRIPT_DIR}/peer-authentication.yaml"
success "PeerAuthentication applied (STRICT mTLS on all namespaces)"

run kubectl apply -f "${SCRIPT_DIR}/destination-rules.yaml"
success "DestinationRules applied (ISTIO_MUTUAL on all services)"

# ─────────────────────────────────────────────────────────────────────
# Step 8 — Verify installation
# ─────────────────────────────────────────────────────────────────────
header "Step 8 — Verifying installation"

if [[ "$DRY_RUN" == false ]]; then
  run "${ISTIOCTL}" verify-install 2>/dev/null || \
    warn "verify-install reported warnings — check output above"

  info "Installed CRDs:"
  kubectl get crd | grep -c 'istio.io' | xargs -I{} echo "  {} Istio CRDs registered"
fi

# ─────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║         Istio Installation Complete                ║${RESET}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════╝${RESET}"
echo ""
printf "  %-24s %s\n" "Version:"        "${CYAN}${ISTIO_VERSION}${RESET}"
printf "  %-24s %s\n" "Profile:"        "${CYAN}demo${RESET}"
printf "  %-24s %s\n" "mTLS mode:"      "${CYAN}STRICT (all namespaces)${RESET}"
printf "  %-24s %s\n" "Injection:"      "${CYAN}${NAMESPACES[*]}${RESET}"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "    Restart existing pods to inject sidecars:"
echo -e "    ${CYAN}kubectl rollout restart deployment -n apps${RESET}"
echo ""
echo -e "    Verify mTLS is active:"
echo -e "    ${CYAN}bash infra/istio/verify-mtls.sh${RESET}"
echo ""
