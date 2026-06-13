#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# install-falco.sh
#
# Installs Falco into the siem namespace using the official falcosecurity Helm
# chart, then deploys the custom rules ConfigMap and Falco Sidekick.
#
# Driver choice — kernel module (kmod):
#   Falco needs to observe kernel syscalls.  There are three drivers:
#
#   kmod   — Loads a kernel module (.ko) compiled for the host kernel.  The
#             falcosecurity Helm chart's init container downloads or compiles
#             the right module for the running kernel automatically.  Most
#             compatible with Minikube (which runs a standard Linux kernel
#             inside a VM) because the module is compiled against the VM kernel
#             headers, not the host machine's headers.
#
#   ebpf   — Uses a BPF program attached to tracepoints.  Requires kernel
#             ≥4.14 and BPF enabled in kernel config.  Better for production
#             cloud nodes; slightly less compatible with Minikube VMs where
#             BPF JIT may be disabled.
#
#   modern_ebpf — CO-RE eBPF (kernel ≥5.8).  Best performance, zero module
#                 compilation step.  Requires Minikube ≥v1.32 or k3s.
#
#   This script defaults to kmod for maximum Minikube compatibility.
#   Override with:  bash install-falco.sh --driver ebpf
#                   bash install-falco.sh --driver modern_ebpf
#
# Prerequisites:
#   - kubectl configured and pointing at the target cluster
#   - helm 3 installed
#   - siem namespace exists  (bash infra/scripts/setup-cluster.sh)
#   - Elasticsearch running  (bash siem/elk/install-elk.sh)
#
# Usage:
#   bash siem/falco/install-falco.sh
#   bash siem/falco/install-falco.sh --driver ebpf
#   bash siem/falco/install-falco.sh --driver modern_ebpf
#   bash siem/falco/install-falco.sh --dry-run
#   bash siem/falco/install-falco.sh --uninstall
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

# ── Constants ─────────────────────────────────────────────────────────────────
FALCO_CHART_VERSION="4.3.0"       # pin; bump deliberately after testing
FALCO_IMAGE_TAG="0.38.0"          # Falco daemon version
SIDEKICK_CHART_VERSION="0.7.14"   # Falco Sidekick chart version
NAMESPACE="siem"
FALCO_RELEASE="falco"
SIDEKICK_RELEASE="falcosidekick"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ───────────────────────────────────────────────────────────────────
DRIVER="kmod"
DRY_RUN=false
UNINSTALL=false
SKIP_SIDEKICK=false

# ── CLI args ───────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --driver)       DRIVER="$2"; shift 2 ;;
    --dry-run)      DRY_RUN=true; shift ;;
    --uninstall)    UNINSTALL=true; shift ;;
    --no-sidekick)  SKIP_SIDEKICK=true; shift ;;
    --help|-h)
      echo "Usage: $0 [--driver kmod|ebpf|modern_ebpf] [--dry-run] [--uninstall] [--no-sidekick]"
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ── Driver validation ─────────────────────────────────────────────────────────
case "${DRIVER}" in
  kmod|ebpf|modern_ebpf) ;;
  *) die "Unknown driver '${DRIVER}'. Choose: kmod, ebpf, modern_ebpf" ;;
esac

run() {
  if "${DRY_RUN}"; then
    info "[DRY-RUN] $*"
  else
    "$@"
  fi
}

# ── Uninstall path ─────────────────────────────────────────────────────────────
if "${UNINSTALL}"; then
  warn "Uninstalling Falco and Falco Sidekick from namespace '${NAMESPACE}'..."
  run helm uninstall "${SIDEKICK_RELEASE}" -n "${NAMESPACE}" 2>/dev/null || true
  run helm uninstall "${FALCO_RELEASE}"    -n "${NAMESPACE}" 2>/dev/null || true
  run kubectl delete configmap falco-custom-rules -n "${NAMESPACE}" --ignore-not-found
  success "Uninstalled."
  exit 0
fi

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Falco Installation — SecureCloud-BD               ${RESET}"
echo -e "${BOLD}  Chart v${FALCO_CHART_VERSION} | Falco v${FALCO_IMAGE_TAG} | Driver: ${DRIVER}  ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""

# ── Preflight ──────────────────────────────────────────────────────────────────
info "Checking prerequisites..."

command -v kubectl &>/dev/null || die "kubectl not found."
command -v helm    &>/dev/null || die "helm 3 not found."
kubectl cluster-info &>/dev/null || die "Cannot reach cluster."

if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  warn "Namespace '${NAMESPACE}' does not exist. Creating it..."
  run kubectl create namespace "${NAMESPACE}"
fi

success "Prerequisites OK."

# ── Add falcosecurity Helm repo ────────────────────────────────────────────────
info "Adding falcosecurity Helm repository..."
if "${DRY_RUN}"; then
  info "[DRY-RUN] helm repo add falcosecurity https://falcosecurity.github.io/charts"
else
  helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
  helm repo update falcosecurity
fi
success "Helm repo ready."

# ── Apply custom rules ConfigMap ───────────────────────────────────────────────
info "Applying custom rules ConfigMap from ${SCRIPT_DIR}/custom-rules.yaml..."
if "${DRY_RUN}"; then
  info "[DRY-RUN] kubectl apply -f ${SCRIPT_DIR}/custom-rules.yaml"
else
  kubectl apply -f "${SCRIPT_DIR}/custom-rules.yaml"
fi
success "Custom rules ConfigMap applied."

# ── Build driver-specific Helm args ───────────────────────────────────────────
# The falcosecurity chart uses driver.kind to select the driver.
# kmod requires the kernel headers init container; modern_ebpf does not.
case "${DRIVER}" in
  kmod)
    DRIVER_ARGS=(
      "--set" "driver.kind=kmod"
      "--set" "driver.loader.initContainer.enabled=true"
    )
    warn "kmod driver: Falco will compile the kernel module inside an init container."
    warn "This requires kernel headers and may take 2-5 minutes on first install."
    ;;
  ebpf)
    DRIVER_ARGS=(
      "--set" "driver.kind=ebpf"
      "--set" "driver.loader.initContainer.enabled=true"
    )
    info "eBPF driver: requires kernel ≥4.14 with BPF enabled."
    ;;
  modern_ebpf)
    DRIVER_ARGS=(
      "--set" "driver.kind=modern_ebpf"
      "--set" "driver.loader.initContainer.enabled=false"
    )
    info "Modern eBPF (CO-RE): no module compilation needed. Requires kernel ≥5.8."
    ;;
esac

# ── Install Falco ──────────────────────────────────────────────────────────────
echo ""
info "Installing Falco (release: ${FALCO_RELEASE})..."

FALCO_HELM_ARGS=(
  upgrade --install "${FALCO_RELEASE}" falcosecurity/falco
  --namespace "${NAMESPACE}"
  --version "${FALCO_CHART_VERSION}"
  "${DRIVER_ARGS[@]}"

  # ── Core settings ──────────────────────────────────────────────────────────
  --set "image.tag=${FALCO_IMAGE_TAG}"
  --set "tty=true"

  # ── Output: JSON to stdout + file ─────────────────────────────────────────
  # JSON to stdout so Filebeat autodiscover can pick it up as a container log.
  --set "falco.json_output=true"
  --set "falco.json_include_output_property=true"
  --set "falco.log_stderr=true"
  --set "falco.log_syslog=false"
  --set "falco.log_level=info"

  # File output: Filebeat also reads /var/log/falco/falco.json (hostPath mount)
  --set "falco.file_output.enabled=true"
  --set "falco.file_output.keep_alive=false"
  --set "falco.file_output.filename=/var/log/falco/falco.json"

  # gRPC: allows Falco Sidekick to receive alerts over Unix socket
  --set "falco.grpc.enabled=true"
  --set "falco.grpc.bind_address=unix:///var/run/falco/falco.sock"
  --set "falco.grpc.threadiness=0"
  --set "falco.grpc_output.enabled=true"

  # ── Webhook output to Sidekick ─────────────────────────────────────────────
  # Sidekick receives alerts over HTTP on port 2801.
  --set "falco.http_output.enabled=true"
  --set "falco.http_output.url=http://${SIDEKICK_RELEASE}:2801/"

  # ── Rules files ────────────────────────────────────────────────────────────
  # Mount the custom rules ConfigMap alongside the built-in rules.
  # Falco loads all *.yaml files listed in rules_file in order;
  # later files can override macros/lists from earlier files.
  --set "falco.rules_file[0]=/etc/falco/falco_rules.yaml"
  --set "falco.rules_file[1]=/etc/falco/falco_rules.local.yaml"
  --set "falco.rules_file[2]=/etc/falco/rules.d/securecloud_rules.yaml"

  # Mount the custom rules ConfigMap as a volume in rules.d/
  --set "extraVolumes[0].name=custom-rules"
  --set "extraVolumes[0].configMap.name=falco-custom-rules"
  --set "extraVolumeMounts[0].name=custom-rules"
  --set "extraVolumeMounts[0].mountPath=/etc/falco/rules.d"
  --set "extraVolumeMounts[0].readOnly=true"

  # Mount the Falco log dir so Filebeat can read it from the host
  --set "extraVolumes[1].name=falco-log-dir"
  --set "extraVolumes[1].hostPath.path=/var/log/falco"
  --set "extraVolumes[1].hostPath.type=DirectoryOrCreate"
  --set "extraVolumeMounts[1].name=falco-log-dir"
  --set "extraVolumeMounts[1].mountPath=/var/log/falco"

  # ── Tolerations ────────────────────────────────────────────────────────────
  # Run on the Minikube single node even if it has control-plane taint.
  --set "tolerations[0].key=node-role.kubernetes.io/control-plane"
  --set "tolerations[0].operator=Exists"
  --set "tolerations[0].effect=NoSchedule"
  --set "tolerations[1].key=node-role.kubernetes.io/master"
  --set "tolerations[1].operator=Exists"
  --set "tolerations[1].effect=NoSchedule"

  # ── Resource limits ────────────────────────────────────────────────────────
  # Sized for single-node 8 GB budget; Falco is typically CPU-bound, not RAM.
  --set "resources.requests.cpu=100m"
  --set "resources.requests.memory=256Mi"
  --set "resources.limits.cpu=500m"
  --set "resources.limits.memory=512Mi"

  --wait
  --timeout 8m   # kmod compilation can take several minutes
)

run helm "${FALCO_HELM_ARGS[@]}"
success "Falco installed."

# ── Wait for Falco DaemonSet readiness ────────────────────────────────────────
if ! "${DRY_RUN}"; then
  info "Waiting for Falco DaemonSet to be ready..."
  kubectl rollout status daemonset/falco -n "${NAMESPACE}" --timeout=300s
  success "Falco DaemonSet ready."
fi

# ── Install Falco Sidekick ─────────────────────────────────────────────────────
if ! "${SKIP_SIDEKICK}"; then
  echo ""
  info "Installing Falco Sidekick (release: ${SIDEKICK_RELEASE})..."

  SIDEKICK_VALUES="${SCRIPT_DIR}/falco-sidekick-values.yaml"

  if [[ ! -f "${SIDEKICK_VALUES}" ]]; then
    warn "falco-sidekick-values.yaml not found at ${SIDEKICK_VALUES}. Skipping Sidekick."
  else
    run helm upgrade --install "${SIDEKICK_RELEASE}" falcosecurity/falcosidekick \
      --namespace "${NAMESPACE}" \
      --version "${SIDEKICK_CHART_VERSION}" \
      --values "${SIDEKICK_VALUES}" \
      --wait \
      --timeout 3m

    if ! "${DRY_RUN}"; then
      kubectl rollout status deployment/"${SIDEKICK_RELEASE}" -n "${NAMESPACE}" --timeout=120s
    fi
    success "Falco Sidekick installed."
  fi
fi

# ── Smoke test: verify Falco is generating events ─────────────────────────────
if ! "${DRY_RUN}"; then
  echo ""
  info "Running smoke test: triggering a 'Shell spawned in container' alert..."

  # Find a running pod in the apps namespace to trigger the rule in
  TEST_POD=$(kubectl get pods -n apps \
    --field-selector="status.phase=Running" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

  if [[ -n "${TEST_POD}" ]]; then
    info "Exec-ing a shell into pod ${TEST_POD} to trigger the shell-spawn rule..."
    # This will fire the "Shell Spawned Inside Container" rule
    kubectl exec -n apps "${TEST_POD}" -- sh -c 'echo "falco-test: shell spawn trigger"' \
      2>/dev/null || true

    sleep 3  # give Falco a moment to process the syscall event

    # Check if Falco logged the event
    FALCO_POD=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=falco" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

    if [[ -n "${FALCO_POD}" ]]; then
      ALERT_COUNT=$(kubectl logs -n "${NAMESPACE}" "${FALCO_POD}" --tail=50 2>/dev/null | \
        grep -c "Shell Spawned" || echo "0")
      if [[ "${ALERT_COUNT}" -gt 0 ]]; then
        success "Smoke test PASSED — Falco generated ${ALERT_COUNT} shell-spawn alert(s)."
      else
        warn "Smoke test: no shell-spawn alert found in recent Falco logs."
        warn "Alert may still be in flight or the rule may not be loaded yet."
        warn "Check: kubectl logs -n ${NAMESPACE} ${FALCO_POD} --tail=100"
      fi
    fi
  else
    warn "No running pods found in apps namespace for smoke test. Skipping."
    warn "Deploy the demo app first: kubectl apply -k infra/apps/manifests/"
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Falco Installation Complete                       ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""
if ! "${DRY_RUN}"; then
  echo -e "${BOLD}Pods:${RESET}"
  kubectl get pods -n "${NAMESPACE}" \
    -l "app.kubernetes.io/name in (falco,falcosidekick)" 2>/dev/null || \
    kubectl get pods -n "${NAMESPACE}" 2>/dev/null || true
  echo ""
fi
echo -e "${BOLD}Useful commands:${RESET}"
echo ""
echo -e "  # Live Falco alert stream"
echo -e "  ${CYAN}kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=falco -f${RESET}"
echo ""
echo -e "  # Verify custom rules loaded"
echo -e "  ${CYAN}kubectl exec -n ${NAMESPACE} \$(kubectl get pod -n ${NAMESPACE} -l app.kubernetes.io/name=falco -o name | head -1) -- falco --list-rules 2>/dev/null | grep -i securecloud${RESET}"
echo ""
echo -e "  # Trigger a test alert manually"
echo -e "  ${CYAN}kubectl exec -n apps \$(kubectl get pod -n apps -o name | head -1) -- sh -c 'id'${RESET}"
echo ""
echo -e "  # View Sidekick UI (if deployed)"
echo -e "  ${CYAN}kubectl port-forward -n ${NAMESPACE} svc/${SIDEKICK_RELEASE}-ui 2802:2802${RESET}"
echo -e "  ${CYAN}open http://localhost:2802${RESET}"
echo ""
