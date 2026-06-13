#!/usr/bin/env bash
# infra/scripts/setup-cluster.sh
#
# Idempotent cluster bootstrap for SecureCloud-BD.
# Detects minikube (preferred) or k3s, starts the cluster, enables addons,
# and creates the four project namespaces.
#
# Usage:
#   bash infra/scripts/setup-cluster.sh [OPTIONS]
#
# Options:
#   --cpus    N    vCPUs to allocate  (default: 4)
#   --memory  MB   RAM in MiB         (default: 6144)
#   --driver  STR  Minikube driver    (default: docker; ignored for k3s)
#   --dry-run      Print commands without executing them

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ─────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────
CPUS=4
MEMORY=6144
DRIVER=docker
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cpus)    CPUS="$2";   shift 2 ;;
    --memory)  MEMORY="$2"; shift 2 ;;
    --driver)  DRIVER="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      sed -n '/^# Usage/,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) die "Unknown option: $1" ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────
# Dry-run wrapper — prefix every side-effecting command with this
# ─────────────────────────────────────────────────────────────────────
run() {
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${YELLOW}[DRY-RUN]${RESET} $*"
  else
    "$@"
  fi
}

# ─────────────────────────────────────────────────────────────────────
# Prerequisite checks
# ─────────────────────────────────────────────────────────────────────
check_prerequisites() {
  header "Checking prerequisites"

  local missing=()

  command -v kubectl &>/dev/null || missing+=("kubectl")
  command -v helm    &>/dev/null || missing+=("helm")

  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}\nInstall them before running this script."
  fi

  success "kubectl $(kubectl version --client -o json 2>/dev/null | \
    python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["clientVersion"]["gitVersion"])' \
    2>/dev/null || kubectl version --client --short 2>/dev/null | head -1)"
  success "helm $(helm version --short 2>/dev/null)"
}

# ─────────────────────────────────────────────────────────────────────
# Detect which runtime is available
# Returns "minikube" or "k3s" via stdout; exits if neither is found
# ─────────────────────────────────────────────────────────────────────
detect_runtime() {
  header "Detecting cluster runtime"

  if command -v minikube &>/dev/null; then
    success "Found minikube $(minikube version --short 2>/dev/null || true)"
    echo "minikube"
    return
  fi

  # k3s may be installed as the k3s binary or via k3s server already running
  if command -v k3s &>/dev/null || command -v k3sup &>/dev/null; then
    success "Found k3s $(k3s --version 2>/dev/null | head -1 || true)"
    echo "k3s"
    return
  fi

  die "Neither minikube nor k3s found on PATH.\n" \
      "  Install minikube: https://minikube.sigs.k8s.io/docs/start/\n" \
      "  Install k3s:      https://k3s.io/"
}

# ─────────────────────────────────────────────────────────────────────
# Minikube — start or reuse an existing cluster
# ─────────────────────────────────────────────────────────────────────
start_minikube() {
  header "Starting Minikube (cpus=${CPUS}, memory=${MEMORY}MiB, driver=${DRIVER})"

  local status
  status=$(minikube status --format='{{.Host}}' 2>/dev/null || true)

  if [[ "$status" == "Running" ]]; then
    warn "Minikube is already running — skipping start (idempotent)"
  else
    run minikube start \
      --cpus="${CPUS}" \
      --memory="${MEMORY}" \
      --driver="${DRIVER}" \
      --kubernetes-version=stable \
      --embed-certs
    success "Minikube started"
  fi

  # Always point kubectl at minikube context (safe to re-run)
  run kubectl config use-context minikube
}

# ─────────────────────────────────────────────────────────────────────
# Minikube — enable addons (idempotent: already-enabled is a no-op)
# ─────────────────────────────────────────────────────────────────────
enable_minikube_addons() {
  header "Enabling Minikube addons"

  local addons=(ingress metrics-server)

  for addon in "${addons[@]}"; do
    local state
    state=$(minikube addons list --output=json 2>/dev/null | \
      python3 -c "
import sys, json
data = json.load(sys.stdin)
# addons list returns either a dict or a list depending on minikube version
if isinstance(data, dict):
    print(data.get('${addon}', {}).get('Status', 'disabled'))
else:
    for item in data:
        if item.get('Name') == '${addon}':
            print(item.get('Status', 'disabled'))
            break
" 2>/dev/null || echo "unknown")

    if [[ "$state" == "enabled" ]]; then
      success "Addon '${addon}' already enabled"
    else
      run minikube addons enable "${addon}"
      success "Addon '${addon}' enabled"
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────
# k3s — start or verify the cluster is reachable
# ─────────────────────────────────────────────────────────────────────
start_k3s() {
  header "Checking k3s cluster"

  if kubectl cluster-info &>/dev/null 2>&1; then
    warn "kubectl can already reach a cluster — assuming k3s is running (idempotent)"
    return
  fi

  if [[ "$EUID" -ne 0 ]]; then
    die "k3s server requires root. Re-run with sudo, or start k3s manually:\n" \
        "  sudo k3s server --disable traefik &"
  fi

  info "Starting k3s server (disable traefik; we use ingress-nginx)"
  run k3s server \
    --disable traefik \
    --write-kubeconfig-mode 644 \
    &

  info "Waiting for k3s API server to become reachable…"
  local retries=30
  until kubectl cluster-info &>/dev/null 2>&1; do
    retries=$((retries - 1))
    [[ $retries -le 0 ]] && die "k3s API server did not become ready in time"
    sleep 5
  done
  success "k3s API server is reachable"

  warn "Minikube addons (ingress, metrics-server) are not applicable to k3s."
  warn "Install ingress-nginx and metrics-server via Helm if needed."
}

# ─────────────────────────────────────────────────────────────────────
# Namespaces — create if absent, skip if present (idempotent)
# ─────────────────────────────────────────────────────────────────────
create_namespaces() {
  header "Creating namespaces"

  local namespaces=(apps monitoring security ml-engine)

  for ns in "${namespaces[@]}"; do
    if kubectl get namespace "${ns}" &>/dev/null; then
      warn "Namespace '${ns}' already exists — skipping"
    else
      run kubectl create namespace "${ns}"
      success "Namespace '${ns}' created"
    fi

    # Label for Istio sidecar injection regardless of whether we just created it
    run kubectl label namespace "${ns}" \
      istio-injection=enabled \
      securecloud.io/managed=true \
      --overwrite
  done
}

# ─────────────────────────────────────────────────────────────────────
# Wait for core system pods to be ready before handing back to the user
# ─────────────────────────────────────────────────────────────────────
wait_for_system_pods() {
  header "Waiting for kube-system pods"

  if [[ "$DRY_RUN" == true ]]; then
    warn "Dry-run: skipping pod readiness wait"
    return
  fi

  local retries=24   # 2-minute timeout at 5s intervals
  until kubectl wait pod \
      --all \
      --for=condition=Ready \
      --namespace=kube-system \
      --timeout=10s &>/dev/null; do
    retries=$((retries - 1))
    if [[ $retries -le 0 ]]; then
      warn "Some kube-system pods are not Ready yet — continuing anyway"
      return
    fi
    info "  Still waiting… (${retries} retries left)"
    sleep 5
  done
  success "All kube-system pods are Ready"
}

# ─────────────────────────────────────────────────────────────────────
# Coloured status summary
# ─────────────────────────────────────────────────────────────────────
print_summary() {
  local runtime="$1"

  echo ""
  echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${GREEN}║        SecureCloud-BD Cluster — Setup Complete       ║${RESET}"
  echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${RESET}"
  echo ""

  # Runtime
  printf "  %-22s %s\n" "Runtime:" "${CYAN}${runtime}${RESET}"

  # Kubernetes version
  local k8s_version
  k8s_version=$(kubectl version --short 2>/dev/null | grep "Server" | awk '{print $3}' || \
                kubectl version -o json 2>/dev/null | python3 -c \
                  'import sys,json; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' \
                  2>/dev/null || echo "unknown")
  printf "  %-22s %s\n" "Kubernetes:" "${CYAN}${k8s_version}${RESET}"

  # Cluster endpoint
  local endpoint
  endpoint=$(kubectl cluster-info 2>/dev/null | grep "control plane" | \
    grep -oE 'https?://[^ ]+' | head -1 || echo "unknown")
  printf "  %-22s %s\n" "API endpoint:" "${CYAN}${endpoint}${RESET}"

  # Namespaces
  echo ""
  echo -e "  ${BOLD}Namespaces:${RESET}"
  local namespaces=(apps monitoring security ml-engine)
  for ns in "${namespaces[@]}"; do
    local status_icon
    if kubectl get namespace "${ns}" &>/dev/null 2>&1; then
      status_icon="${GREEN}✓${RESET}"
    else
      status_icon="${RED}✗${RESET}"
    fi
    printf "    %b  %-20s\n" "${status_icon}" "${ns}"
  done

  # Minikube addons (only relevant for minikube)
  if [[ "$runtime" == "minikube" ]]; then
    echo ""
    echo -e "  ${BOLD}Addons:${RESET}"
    for addon in ingress metrics-server; do
      local astate
      astate=$(minikube addons list --output=json 2>/dev/null | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
if isinstance(data, dict):
    print(data.get('${addon}', {}).get('Status', 'disabled'))
else:
    for item in data:
        if item.get('Name') == '${addon}':
            print(item.get('Status', 'disabled'))
            break
" 2>/dev/null || echo "unknown")
      if [[ "$astate" == "enabled" ]]; then
        printf "    ${GREEN}✓${RESET}  %-20s  %b\n" "${addon}" "${GREEN}enabled${RESET}"
      else
        printf "    ${RED}✗${RESET}  %-20s  %b\n" "${addon}" "${YELLOW}${astate}${RESET}"
      fi
    done
  fi

  # Node summary
  echo ""
  echo -e "  ${BOLD}Nodes:${RESET}"
  kubectl get nodes --no-headers 2>/dev/null | while IFS= read -r line; do
    local node_name node_status
    node_name=$(echo "$line" | awk '{print $1}')
    node_status=$(echo "$line" | awk '{print $2}')
    if [[ "$node_status" == "Ready" ]]; then
      printf "    ${GREEN}✓${RESET}  %s  ${GREEN}%s${RESET}\n" "${node_name}" "${node_status}"
    else
      printf "    ${YELLOW}⚠${RESET}  %s  ${YELLOW}%s${RESET}\n" "${node_name}" "${node_status}"
    fi
  done

  echo ""
  echo -e "  ${BOLD}Next steps:${RESET}"
  echo -e "    ${CYAN}make deploy-infra${RESET}   → Istio + OPA Gatekeeper + Helm chart"
  echo -e "    ${CYAN}make deploy-siem${RESET}    → ELK stack + Filebeat + Falco"
  echo -e "    ${CYAN}make train${RESET}          → preprocess datasets + train ML models"
  echo -e "    ${CYAN}make deploy-ml${RESET}      → build + deploy threat-scoring API"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────
main() {
  echo -e "${BOLD}${CYAN}"
  echo "  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗"
  echo "  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝"
  echo "  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  "
  echo "  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  "
  echo "  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗"
  echo "  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝"
  echo -e "${RESET}${BOLD}  SecureCloud-BD — Cluster Setup${RESET}"
  echo ""

  [[ "$DRY_RUN" == true ]] && warn "DRY-RUN mode — no changes will be made"

  check_prerequisites

  local runtime
  runtime=$(detect_runtime)

  case "$runtime" in
    minikube)
      start_minikube
      enable_minikube_addons
      ;;
    k3s)
      start_k3s
      ;;
    *)
      die "Unexpected runtime value: ${runtime}"
      ;;
  esac

  create_namespaces
  wait_for_system_pods
  print_summary "${runtime}"
}

main "$@"
