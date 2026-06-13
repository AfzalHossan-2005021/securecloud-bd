#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# install-elk.sh
#
# Installs the ELK stack (Elasticsearch, Logstash, Kibana) into the siem
# namespace using the official Elastic Helm charts.
#
# Prerequisites:
#   - kubectl configured and pointing at a running cluster
#   - helm 3 installed
#   - siem namespace must exist (created by infra/scripts/setup-cluster.sh)
#   - ~4 GB RAM headroom in the cluster (Minikube started with at least 6 GB)
#
# Usage:
#   bash siem/elk/install-elk.sh
#   bash siem/elk/install-elk.sh --dry-run        # print commands, no changes
#   bash siem/elk/install-elk.sh --uninstall       # remove all ELK releases
#   bash siem/elk/install-elk.sh --skip-wait       # don't wait for readiness
#   bash siem/elk/install-elk.sh --reset-password  # regenerate elastic secret
#
# What this script does:
#   1. Adds the Elastic Helm repository
#   2. Creates the elastic-credentials Secret (if it does not exist)
#   3. Creates the logstash-pipeline ConfigMap from logstash-pipeline.conf
#   4. Installs Elasticsearch, waits for it to be ready
#   5. Installs Kibana, waits for it to be ready
#   6. Installs Logstash, waits for it to be ready
#   7. Prints access URLs and a quick health check
#
# Memory budget (all limits from helm-values/):
#   Elasticsearch:  4 Gi  (2 Gi heap)
#   Kibana:       768 Mi
#   Logstash:     1.5 Gi  (1 Gi heap)
#   Total:       ~6.3 Gi  — fits in an 8 Gi node with OS + Istio sidecars
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
ELASTIC_VERSION="8.12.2"
NAMESPACE="siem"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALUES_DIR="${SCRIPT_DIR}/helm-values"
PIPELINE_CONF="${SCRIPT_DIR}/logstash-pipeline.conf"

ES_RELEASE="securecloud-es"
KB_RELEASE="securecloud-kb"
LS_RELEASE="securecloud-ls"

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
SKIP_WAIT=false
RESET_PASSWORD=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)        DRY_RUN=true ;;
    --uninstall)      UNINSTALL=true ;;
    --skip-wait)      SKIP_WAIT=true ;;
    --reset-password) RESET_PASSWORD=true ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--uninstall] [--skip-wait] [--reset-password]"
      exit 0 ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# Wrapper: skip actual execution in dry-run mode
run() {
  if "$DRY_RUN"; then
    info "[DRY-RUN] $*"
  else
    "$@"
  fi
}

# ── Uninstall path ─────────────────────────────────────────────────────────────
if "$UNINSTALL"; then
  warn "Uninstalling ELK stack from namespace '${NAMESPACE}'..."
  run helm uninstall "${LS_RELEASE}" -n "${NAMESPACE}" 2>/dev/null || true
  run helm uninstall "${KB_RELEASE}" -n "${NAMESPACE}" 2>/dev/null || true
  run helm uninstall "${ES_RELEASE}" -n "${NAMESPACE}" 2>/dev/null || true
  run kubectl delete configmap logstash-pipeline -n "${NAMESPACE}" --ignore-not-found
  warn "PVCs are NOT deleted automatically. To also remove data:"
  warn "  kubectl delete pvc -n ${NAMESPACE} --all"
  success "ELK Helm releases removed."
  exit 0
fi

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  ELK Stack Installation — SecureCloud-BD           ${RESET}"
echo -e "${BOLD}  Elastic ${ELASTIC_VERSION} | namespace: ${NAMESPACE}          ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""

# ── Preflight checks ───────────────────────────────────────────────────────────
info "Running preflight checks..."

command -v kubectl &>/dev/null || die "kubectl not found."
command -v helm    &>/dev/null || die "helm 3 not found."

# Helm 3 check
HELM_MAJOR=$(helm version --short 2>/dev/null | grep -oE 'v[0-9]+' | head -1 | tr -d 'v')
[[ "${HELM_MAJOR}" -ge 3 ]] || die "Helm 3 required (found v${HELM_MAJOR})."

kubectl cluster-info &>/dev/null || die "Cannot reach cluster. Check kubeconfig."

# Namespace
if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  warn "Namespace '${NAMESPACE}' does not exist. Creating it..."
  run kubectl create namespace "${NAMESPACE}"
fi

# Values files
for f in \
    "${VALUES_DIR}/elasticsearch-values.yaml" \
    "${VALUES_DIR}/kibana-values.yaml" \
    "${VALUES_DIR}/logstash-values.yaml"; do
  [[ -f "$f" ]] || die "Missing values file: $f"
done

[[ -f "${PIPELINE_CONF}" ]] || die "Missing pipeline config: ${PIPELINE_CONF}"

success "Preflight checks passed."

# ── Add Elastic Helm repo ──────────────────────────────────────────────────────
info "Adding Elastic Helm repository..."
if "$DRY_RUN"; then
  info "[DRY-RUN] helm repo add elastic https://helm.elastic.co"
  info "[DRY-RUN] helm repo update"
else
  helm repo add elastic https://helm.elastic.co 2>/dev/null || true
  helm repo update elastic
fi
success "Helm repo ready."

# ── Create elastic-credentials Secret ─────────────────────────────────────────
# The Secret stores the Elasticsearch password used by Kibana, Logstash, and
# the API.  We generate a random password on first install and never commit it.
# Re-run with --reset-password to rotate.
info "Checking elastic-credentials Secret..."

if "$RESET_PASSWORD"; then
  warn "Deleting existing elastic-credentials Secret (--reset-password)..."
  run kubectl delete secret elastic-credentials -n "${NAMESPACE}" --ignore-not-found
fi

if ! kubectl get secret elastic-credentials -n "${NAMESPACE}" &>/dev/null; then
  ELASTIC_PASSWORD=$(openssl rand -base64 20 | tr -d '/+=' | head -c 20)
  info "Generating new elastic-credentials Secret..."
  if "$DRY_RUN"; then
    info "[DRY-RUN] kubectl create secret generic elastic-credentials -n ${NAMESPACE} --from-literal=password=<generated>"
  else
    kubectl create secret generic elastic-credentials \
      --namespace "${NAMESPACE}" \
      --from-literal=password="${ELASTIC_PASSWORD}"
    success "Secret 'elastic-credentials' created."
    echo ""
    echo -e "  ${BOLD}Save this password — it will not be shown again:${RESET}"
    echo -e "  ${YELLOW}ELASTIC_PASSWORD=${ELASTIC_PASSWORD}${RESET}"
    echo ""
    echo -e "  To retrieve later: ${CYAN}kubectl get secret elastic-credentials -n ${NAMESPACE} -o jsonpath='{.data.password}' | base64 -d${RESET}"
    echo ""
  fi
else
  info "Secret 'elastic-credentials' already exists. Skipping generation."
  info "To rotate: rerun with --reset-password"
fi

# ── Create logstash-pipeline ConfigMap ────────────────────────────────────────
info "Creating logstash-pipeline ConfigMap from ${PIPELINE_CONF}..."
if "$DRY_RUN"; then
  info "[DRY-RUN] kubectl create configmap logstash-pipeline --from-file=logstash-pipeline.conf=... -n ${NAMESPACE}"
else
  # Replace existing ConfigMap if pipeline conf was updated
  kubectl create configmap logstash-pipeline \
    --namespace "${NAMESPACE}" \
    --from-file=logstash-pipeline.conf="${PIPELINE_CONF}" \
    --dry-run=client -o yaml | kubectl apply -f -
  success "ConfigMap 'logstash-pipeline' applied."
fi

# ── Helper: wait for Deployment/StatefulSet readiness ─────────────────────────
wait_for_ready() {
  local kind="$1"    # StatefulSet or Deployment
  local name="$2"
  local timeout="${3:-300}"

  if "$SKIP_WAIT"; then
    warn "Skipping readiness wait for ${name} (--skip-wait)"
    return 0
  fi

  info "Waiting for ${kind}/${name} to be ready (timeout: ${timeout}s)..."

  if "$DRY_RUN"; then
    info "[DRY-RUN] kubectl rollout status ${kind}/${name} -n ${NAMESPACE} --timeout=${timeout}s"
    return 0
  fi

  if kubectl rollout status "${kind}/${name}" \
      -n "${NAMESPACE}" \
      --timeout="${timeout}s"; then
    success "${name} is ready."
  else
    error "${name} did not become ready within ${timeout}s."
    error "Check pod events:"
    error "  kubectl describe pods -n ${NAMESPACE} -l app=${name}"
    error "  kubectl logs -n ${NAMESPACE} -l app=${name} --tail=50"
    return 1
  fi
}

# ── Helper: helm upgrade --install with values ─────────────────────────────────
helm_install() {
  local release="$1"
  local chart="$2"
  local values_file="$3"
  shift 3

  if "$DRY_RUN"; then
    info "[DRY-RUN] helm upgrade --install ${release} ${chart} \\"
    info "          --namespace ${NAMESPACE} --version ${ELASTIC_VERSION} \\"
    info "          -f ${values_file} $*"
  else
    helm upgrade --install "${release}" "${chart}" \
      --namespace "${NAMESPACE}" \
      --version "${ELASTIC_VERSION}" \
      --values "${values_file}" \
      "$@"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. ELASTICSEARCH
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}── [1/3] Elasticsearch ──────────────────────────────${RESET}"
info "Installing Elasticsearch ${ELASTIC_VERSION}..."
info "  Memory: 4 Gi limit, 2 Gi heap | Storage: 20 Gi PVC"

helm_install "${ES_RELEASE}" elastic/elasticsearch \
  "${VALUES_DIR}/elasticsearch-values.yaml" \
  --set "fullnameOverride=${ES_RELEASE}"

# The StatefulSet name for the official chart is <release>-master
wait_for_ready StatefulSet "${ES_RELEASE}-master" 360

# Quick cluster health check
if ! "$DRY_RUN" && ! "$SKIP_WAIT"; then
  info "Checking Elasticsearch cluster health..."
  ES_POD=$(kubectl get pod -n "${NAMESPACE}" \
    -l "app=${ES_RELEASE}-master" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

  if [[ -n "${ES_POD}" ]]; then
    HEALTH=$(kubectl exec -n "${NAMESPACE}" "${ES_POD}" -- \
      curl -s "http://localhost:9200/_cluster/health?pretty" 2>/dev/null | \
      python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" \
      2>/dev/null || echo "unknown")
    if [[ "${HEALTH}" == "green" || "${HEALTH}" == "yellow" ]]; then
      success "Elasticsearch cluster health: ${HEALTH}"
    else
      warn "Elasticsearch cluster health: ${HEALTH} (may still be initialising)"
    fi
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# 2. KIBANA
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}── [2/3] Kibana ─────────────────────────────────────${RESET}"
info "Installing Kibana ${ELASTIC_VERSION}..."
info "  Memory: 768 Mi limit | NodePort: 30601"

helm_install "${KB_RELEASE}" elastic/kibana \
  "${VALUES_DIR}/kibana-values.yaml" \
  --set "elasticsearchHosts=http://${ES_RELEASE}-master:9200" \
  --set "fullnameOverride=${KB_RELEASE}"

wait_for_ready Deployment "${KB_RELEASE}" 300

# ══════════════════════════════════════════════════════════════════════════════
# 3. LOGSTASH
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}── [3/3] Logstash ───────────────────────────────────${RESET}"
info "Installing Logstash ${ELASTIC_VERSION}..."
info "  Memory: 1.5 Gi limit, 1 Gi heap | Beats input: 5044"

helm_install "${LS_RELEASE}" elastic/logstash \
  "${VALUES_DIR}/logstash-values.yaml" \
  --set "fullnameOverride=${LS_RELEASE}"

wait_for_ready StatefulSet "${LS_RELEASE}" 300

# ══════════════════════════════════════════════════════════════════════════════
# ACCESS URLS + SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation Complete                             ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""

if ! "$DRY_RUN"; then
  # Get Minikube IP (works with minikube; falls back to node IP)
  MINIKUBE_IP=$(minikube ip 2>/dev/null || \
    kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || \
    echo "<node-ip>")

  echo -e "${BOLD}Service endpoints:${RESET}"
  echo ""
  echo -e "  Kibana (UI)         ${GREEN}http://${MINIKUBE_IP}:30601${RESET}"
  echo -e "  Elasticsearch (API) ${GREEN}http://${MINIKUBE_IP}:$(kubectl get svc "${ES_RELEASE}-master" -n "${NAMESPACE}" -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null || echo "9200")${RESET}"
  echo -e "  Logstash (beats)    ${CYAN}${LS_RELEASE}.${NAMESPACE}.svc.cluster.local:5044${RESET} (cluster-internal)"
  echo ""

  echo -e "${BOLD}Pod status:${RESET}"
  kubectl get pods -n "${NAMESPACE}" \
    -l "app in (${ES_RELEASE}-master,${KB_RELEASE},${LS_RELEASE})" \
    --no-headers \
    -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[0].ready,STATUS:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount' \
    2>/dev/null || kubectl get pods -n "${NAMESPACE}" 2>/dev/null || true
  echo ""

  echo -e "${BOLD}PVC status:${RESET}"
  kubectl get pvc -n "${NAMESPACE}" 2>/dev/null || true
  echo ""

  echo -e "${BOLD}Next steps:${RESET}"
  echo ""
  echo -e "  1. Open Kibana: ${CYAN}http://${MINIKUBE_IP}:30601${RESET}"
  echo -e "     → Management → Stack Management → Index Patterns"
  echo -e "     → Create pattern: ${YELLOW}securecloud-*${RESET}  (time field: @timestamp)"
  echo ""
  echo -e "  2. Configure Filebeat to ship logs to Logstash:"
  echo -e "     ${CYAN}kubectl apply -f siem/filebeat/daemonset.yaml${RESET}"
  echo ""
  echo -e "  3. Install Falco to generate security alerts:"
  echo -e "     ${CYAN}helm upgrade --install falco falcosecurity/falco -n siem -f siem/falco/falco-values.yaml${RESET}"
  echo ""
  echo -e "  4. Verify indices are being populated:"
  echo -e "     ${CYAN}kubectl exec -n siem ${ES_RELEASE}-master-0 -- curl -s http://localhost:9200/_cat/indices?v${RESET}"
  echo ""

  echo -e "${BOLD}Useful commands:${RESET}"
  echo ""
  echo -e "  # Stream Logstash logs"
  echo -e "  kubectl logs -n ${NAMESPACE} -l app=${LS_RELEASE} -f"
  echo ""
  echo -e "  # ES cluster health"
  echo -e "  kubectl exec -n ${NAMESPACE} ${ES_RELEASE}-master-0 -- curl -s http://localhost:9200/_cluster/health?pretty"
  echo ""
  echo -e "  # Port-forward Elasticsearch for local API access"
  echo -e "  kubectl port-forward -n ${NAMESPACE} svc/${ES_RELEASE}-master 9200:9200"
  echo ""
  echo -e "  # Retrieve elastic password"
  echo -e "  kubectl get secret elastic-credentials -n ${NAMESPACE} -o jsonpath='{.data.password}' | base64 -d && echo"
  echo ""

else
  info "[DRY-RUN] Would print access URLs after installation."
fi

echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""
