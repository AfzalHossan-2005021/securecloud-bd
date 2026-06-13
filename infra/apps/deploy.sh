#!/usr/bin/env bash
# infra/apps/deploy.sh
#
# Build Docker images into Minikube's daemon and deploy the bKash demo stack.
# Idempotent — safe to re-run.
#
# Usage:
#   bash infra/apps/deploy.sh [--skip-build] [--namespace <ns>]
set -euo pipefail

NAMESPACE=${NAMESPACE:-apps}
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=true; shift ;;
    --namespace)  NAMESPACE="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ── 1. Ensure namespace exists ────────────────────────────────────────
if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  kubectl create namespace "${NAMESPACE}"
fi
kubectl label namespace "${NAMESPACE}" istio-injection=enabled --overwrite
success "Namespace '${NAMESPACE}' ready"

# ── 2. Build images into Minikube ────────────────────────────────────
if [[ "$SKIP_BUILD" == false ]]; then
  info "Pointing Docker at Minikube daemon"
  eval "$(minikube docker-env)"

  services=(frontend payment-api user-db)
  image_names=(
    securecloud/bkash-frontend:latest
    securecloud/bkash-payment-api:latest
    securecloud/bkash-user-db:latest
  )

  for i in "${!services[@]}"; do
    svc="${services[$i]}"
    img="${image_names[$i]}"
    info "Building ${img}"
    docker build \
      -f "${REPO_ROOT}/infra/apps/${svc}/Dockerfile" \
      -t "${img}" \
      "${REPO_ROOT}/infra/apps/${svc}"
    success "${img} built"
  done
fi

# ── 3. Create secrets (prompt if not present) ─────────────────────────
create_secret_if_missing() {
  local name="$1"; shift
  if kubectl get secret "${name}" -n "${NAMESPACE}" &>/dev/null; then
    warn "Secret '${name}' already exists — skipping"
    return
  fi
  info "Creating secret '${name}'"
  kubectl create secret generic "${name}" "$@" --namespace "${NAMESPACE}"
  success "Secret '${name}' created"
}

create_secret_if_missing user-db-secret \
  --from-literal=POSTGRES_USER=bkash_app \
  --from-literal=POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"

create_secret_if_missing payment-api-secret \
  --from-literal=DB_USER=bkash_app \
  --from-literal=DB_PASSWORD="$(kubectl get secret user-db-secret -n "${NAMESPACE}" \
      -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"

create_secret_if_missing frontend-secret \
  --from-literal=SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# ── 4. Apply manifests via kustomize ─────────────────────────────────
info "Applying Kubernetes manifests"
kubectl apply -k "${REPO_ROOT}/infra/apps/manifests/"
success "Manifests applied"

# ── 5. Wait for rollout ───────────────────────────────────────────────
info "Waiting for StatefulSet user-db"
kubectl rollout status statefulset/user-db -n "${NAMESPACE}" --timeout=120s

info "Waiting for Deployment payment-api"
kubectl rollout status deployment/payment-api -n "${NAMESPACE}" --timeout=120s

info "Waiting for Deployment frontend"
kubectl rollout status deployment/frontend -n "${NAMESPACE}" --timeout=120s

# ── 6. Print access URL ───────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║     bKash Demo — Deployment Complete         ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${RESET}"
echo ""
FRONTEND_URL=$(minikube service frontend-nodeport -n "${NAMESPACE}" --url 2>/dev/null || \
               echo "kubectl port-forward svc/frontend 8080:80 -n ${NAMESPACE}")
echo -e "  Frontend:    ${CYAN}${FRONTEND_URL}${RESET}"
echo -e "  Payment API: ${CYAN}http://payment-api.${NAMESPACE}.svc.cluster.local:8000/docs${RESET}"
echo ""
