#!/usr/bin/env bash
# Bootstrap script: start Minikube, install Istio + OPA Gatekeeper, apply manifests.
set -euo pipefail

MINIKUBE_CPUS=${MINIKUBE_CPUS:-4}
MINIKUBE_MEMORY=${MINIKUBE_MEMORY:-6144}
ISTIO_VERSION=${ISTIO_VERSION:-1.20.3}

echo "==> Starting Minikube (${MINIKUBE_CPUS} CPUs, ${MINIKUBE_MEMORY}MB RAM)"
minikube start \
  --cpus="${MINIKUBE_CPUS}" \
  --memory="${MINIKUBE_MEMORY}" \
  --driver=docker \
  --kubernetes-version=v1.28.0 \
  --addons=metrics-server

echo "==> Applying namespaces"
kubectl apply -f infra/namespaces/namespaces.yaml

echo "==> Installing Istio ${ISTIO_VERSION}"
curl -L https://istio.io/downloadIstio | ISTIO_VERSION="${ISTIO_VERSION}" sh -
export PATH="$PWD/istio-${ISTIO_VERSION}/bin:$PATH"
istioctl install --set profile=minimal -y
istioctl verify-install

echo "==> Applying Istio mTLS policies"
kubectl apply -f infra/istio/peer-authentication.yaml
kubectl apply -f infra/istio/destination-rules.yaml
kubectl apply -f infra/istio/authorization-policies.yaml

echo "==> Installing OPA Gatekeeper"
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update
helm upgrade --install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set replicas=1 \
  --set resources.requests.memory=256Mi

echo "==> Waiting for Gatekeeper webhook to be ready"
kubectl rollout status deployment/gatekeeper-controller-manager \
  -n gatekeeper-system --timeout=120s

echo "==> Applying OPA constraint templates and constraints"
kubectl apply -f infra/gatekeeper/constraint-template-privileged.yaml
kubectl apply -f infra/gatekeeper/constraint-template-hostpath.yaml
sleep 10   # wait for CRDs to register
kubectl apply -f infra/gatekeeper/constraint-privileged.yaml
kubectl apply -f infra/gatekeeper/constraint-hostpath.yaml

echo "==> Done. Run 'helm upgrade --install securecloud infra/helm/securecloud' next."
