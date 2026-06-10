# infra/

Kubernetes manifests and Helm charts for the SecureCloud-BD platform.

## Sub-directories

| Path | Purpose |
|------|---------|
| `namespaces/` | Namespace definitions for `securecloud`, `siem`, and `ml` (all with `istio-injection: enabled`) |
| `istio/` | PeerAuthentication (mTLS STRICT), DestinationRules, and AuthorizationPolicies |
| `gatekeeper/` | OPA Gatekeeper ConstraintTemplates and Constraints (no-privileged, no-hostpath) |
| `helm/securecloud/` | Helm chart that deploys the threat-scoring API and its model PVC |

## Bootstrap

```bash
# Start Minikube, install Istio, install OPA Gatekeeper, apply all manifests
bash infra/setup-minikube.sh
```

## Deploy the application chart

```bash
helm upgrade --install securecloud infra/helm/securecloud \
  --namespace securecloud --create-namespace
```

## Key design decisions

- **mTLS STRICT** — `PeerAuthentication` resources in every namespace reject plain-text traffic.
- **Default-deny** — each namespace carries a `deny-all` `AuthorizationPolicy`; explicit `ALLOW` rules are the only way in.
- **Resource limits** — all containers have `requests` and `limits` set to fit within a 6 GB Minikube allocation.
- **Non-root containers** — the threat-API pod runs as UID 1000 with `readOnlyRootFilesystem: true`.
