# infra/istio/ — Mutual TLS with Istio

## What is mTLS and why does it matter?

### One-way TLS (HTTPS) vs mutual TLS

Standard HTTPS uses **one-way TLS**: the client verifies the server's certificate
(so you know you are talking to the real bank), but the server does not verify
the client's identity at the transport layer.  The server trusts anyone who can
reach port 443.

**Mutual TLS (mTLS)** adds a second handshake direction: the *server* also
demands a certificate from the *client* and verifies it against a trusted CA
before allowing the connection to proceed.

```
One-way TLS                      Mutual TLS
────────────────                 ──────────────────────────────
Client ──→ verify server cert    Client ──→ verify server cert
Client ←── (trusted)             Client ←── verify client cert
[connection open]                [connection open — both authenticated]
```

In Istio, the CA is **istiod**, which runs inside the cluster and automatically
issues short-lived SPIFFE X.509 certificates (SVIDs) to every Envoy sidecar:

```
spiffe://<cluster-trust-domain>/ns/<namespace>/sa/<service-account>
e.g.
spiffe://cluster.local/ns/apps/sa/payment-api
```

---

## Why IP-based trust is insufficient in a Kubernetes cluster

### The problem with trusting IP addresses

Traditional network security assumes that if a packet arrives from a trusted IP
address, it came from a trusted host.  In Kubernetes, this assumption breaks in
at least four ways:

**1. Pod IP addresses are ephemeral.**
Every time a pod restarts it may receive a different IP.  A firewall rule
written as `allow 10.244.3.17/32` becomes stale the moment the pod is
rescheduled.  Istio identifies workloads by their SPIFFE identity — derived
from the namespace and service account, which are stable — not by IP.

**2. Any pod on the overlay network can spoof source IPs.**
The cluster overlay network (VXLAN, Geneve, etc.) operates at Layer 3.  A
compromised pod can forge its source IP within the overlay.  IPsec or mTLS
at the application layer is the only reliable defence.

**3. Containers share kernel namespaces on the same node.**
A container with host network access (`hostNetwork: true`) inherits the node's
IP and can impersonate any co-located pod from an IP perspective.  mTLS requires
a private key held in the sidecar's memory, which cannot be trivially copied
between containers.

**4. Multi-tenancy collapses namespace boundaries.**
In a shared cluster, `Namespace A` and `Namespace B` may have overlapping IP
ranges or share a node.  Network policies provide namespace isolation at L3/L4,
but cannot express "only pods with a valid certificate from namespace A's
service account may call this endpoint."  mTLS can.

### What mTLS provides instead

| Property | IP-based trust | mTLS |
|---|---|---|
| Identity proof | Source IP (spoofable) | Cryptographic certificate (unforgeable without private key) |
| Certificate authority | None | Istio CA (istiod), auto-rotated every 24h |
| Encrypted in transit | No (plain TCP) | Yes (TLS 1.3) |
| Survives pod restarts | No (IP changes) | Yes (identity tied to service account) |
| Visible to Falco | Partially | Full connection metadata via Envoy telemetry |

---

## How the two resources work together

### PeerAuthentication — the server-side rule

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: apps
spec:
  mtls:
    mode: STRICT
```

This tells the Envoy sidecar on the **receiving** pod: *reject any connection
that does not present a valid Istio SVID*.  A pod without a sidecar cannot
present an SVID and its connection will be dropped at the TLS handshake stage,
before any application data is exchanged.

**PERMISSIVE vs STRICT:**

| Mode | Accepts | Use case |
|------|---------|----------|
| `PERMISSIVE` | Plain-text AND mTLS | Migration period: let un-sidecarred pods still reach the service |
| `STRICT` | mTLS only | Production target: reject everything without a valid SVID |

Never leave `PERMISSIVE` in place once all pods have sidecars.  It creates a
gap that allows any pod — including an attacker's injected workload — to reach
secured endpoints without authentication.

### DestinationRule — the client-side rule

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: payment-api-mtls
  namespace: apps
spec:
  host: "payment-api.apps.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
```

This tells the Envoy sidecar on the **sending** pod: *when connecting to
`payment-api`, initiate a mutually-authenticated TLS handshake using the
SVID that istiod issued to me*.

Without this, a pod that has a sidecar injected might still send plain-text
(Envoy's passthrough default), and the server's `STRICT` PeerAuthentication
will reject it with a TLS handshake error — causing 503s that are confusing
to debug.

**Common misconfiguration:** applying PeerAuthentication without DestinationRules
and seeing `upstream connect error or disconnect/reset before headers. reset reason: connection failure`.
That error means the client sent plain-text to a STRICT server.

---

## Files in this directory

| File | Purpose |
|------|---------|
| `install-istio.sh` | Downloads `istioctl`, installs Istio (demo profile), enables sidecar injection, applies mTLS policies |
| `peer-authentication.yaml` | Server-side STRICT mTLS for all project namespaces + mesh-wide default in istio-system |
| `destination-rules.yaml` | Client-side ISTIO_MUTUAL for every named service, with connection pool and circuit-breaker settings |
| `authorization-policies.yaml` | Layer-7 RBAC: which SPIFFE identities may call which paths |
| `verify-mtls.sh` | Six-check verification script — see section below |

---

## Running the verification script

```bash
bash infra/istio/verify-mtls.sh
```

### What each check tests

| Check | Method | Passes when |
|-------|--------|-------------|
| 1 — Control plane | `kubectl get deployment istiod` | istiod has ≥1 ready replica |
| 2 — Injection labels | `kubectl get namespace` | `istio-injection=enabled` on all project namespaces |
| 3 — PeerAuthentication | `kubectl get peerauthentication` | All PAs are `STRICT`; no `PERMISSIVE` |
| 4 — DestinationRules | `kubectl get destinationrule` | All DRs specify `ISTIO_MUTUAL` |
| 5 — tls-check | `istioctl authn tls-check` | Status column is `OK`, server=`STRICT`, client=`ISTIO_MUTUAL` |
| 6 — SVID certificate | `istioctl proxy-config secret` | Sidecar holds a SPIFFE URI certificate |

### Interpreting the output table

```
 STATUS    SERVICE / PAIR                         TLS MODE        SVID      DETAIL
 ──────────────────────────────────────────────────────────────────────────────────
 ✓ PASS    apps (3 PAs)                           STRICT          ✓
 ✓ PASS    frontend → payment-api                 ISTIO_MUTUAL    ✓         server=STRICT
 ✗ FAIL    payment-api → user-db                  NONE            ✗         status=CONFLICT
 ⚠ WARN    monitoring (0 PAs)                     inherited       —         no explicit PA
 – SKIP    ml-engine/ml-infer:8081                —               —         pod not running
```

**STATUS meanings:**

| Status | Meaning |
|--------|---------|
| `✓ PASS` | The check passed with the expected configuration |
| `✗ FAIL` | A misconfiguration was detected; action required |
| `⚠ WARN` | Advisory — the system may work but violates a best practice |
| `– SKIP` | Check could not run (pod not deployed, tool missing, etc.) |

**tls-check STATUS values (column 5):**

| Value | Meaning | Fix |
|-------|---------|-----|
| `OK` | Both sides agreed on the TLS mode | None — working as intended |
| `CONFLICT` | Server expects mTLS; client is sending plain-text (or vice versa) | Apply DestinationRule with `ISTIO_MUTUAL` on the client side |
| `DR CONFLICT` | Two DestinationRules match the same host | Remove the duplicate or make the host more specific |
| `AUTO PASSTHROUGH` | Ingress gateway is bypassing TLS policies | Review gateway TLS mode |

### Common failure scenarios and fixes

**Scenario 1: 503 errors after applying PeerAuthentication**
```
upstream connect error or disconnect/reset before headers
```
Cause: STRICT PA is rejecting plain-text connections from pods that either
have no sidecar or have no DestinationRule forcing ISTIO_MUTUAL.

Fix:
```bash
# Check if all pods have sidecars (READY should show 2/2)
kubectl get pods -n apps

# If a pod shows 1/1 instead of 2/2, restart it to inject the sidecar
kubectl rollout restart deployment/payment-api -n apps

# Apply DestinationRules if missing
kubectl apply -f infra/istio/destination-rules.yaml
```

**Scenario 2: tls-check shows CONFLICT**
```bash
istioctl authn tls-check payment-api-xxxx.apps payment-api.apps.svc.cluster.local
# HOST:PORT  SERVICE  STATUS    SERVER  CLIENT
# ...        ...      CONFLICT  STRICT  DISABLE
```
Cause: DestinationRule is missing or set to `DISABLE`.
Fix: `kubectl apply -f infra/istio/destination-rules.yaml`

**Scenario 3: SVID check shows "no sidecar"**
Cause: The namespace did not have `istio-injection=enabled` when the pod was
created.  The label is present now, but existing pods are not retroactively
injected.

Fix:
```bash
kubectl label namespace apps istio-injection=enabled --overwrite
kubectl rollout restart deployment --all -n apps
```

**Scenario 4: istioctl shows `PERMISSIVE` instead of `STRICT`**
Cause: Either the PeerAuthentication was not applied, or a namespace-level policy
is being overridden by a pod-level `PERMISSIVE` policy.

Fix:
```bash
# List all PeerAuthentications and their modes
kubectl get peerauthentication -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,MODE:.spec.mtls.mode'

# Re-apply
kubectl apply -f infra/istio/peer-authentication.yaml
```

---

## Viewing Istio telemetry

### Kiali (service mesh topology)
```bash
istioctl dashboard kiali
```
Navigate to Graph → select all namespaces.  Green edges with a padlock icon
indicate active mTLS.  Red edges indicate plain-text or errors.

### Prometheus mTLS metrics
```
# Total requests secured by mTLS
sum(istio_requests_total{connection_security_policy="mutual_tls"}) by (destination_service)

# Any requests NOT using mTLS (should be 0 in a correctly configured cluster)
sum(istio_requests_total{connection_security_policy!="mutual_tls"}) by (source_app, destination_service)
```

### Envoy access log fields
When `STRICT` mTLS is working, every access log line from the Envoy sidecar
includes:
```
[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%" %RESPONSE_CODE%
  ... upstream_transport_failure_reason="" ...
  ... x-forwarded-client-cert: By=spiffe://cluster.local/ns/apps/sa/payment-api;
                                Hash=<sha256>;
                                Subject="";
                                URI=spiffe://cluster.local/ns/apps/sa/frontend
```

The `x-forwarded-client-cert` (XFCC) header is injected by the receiving Envoy
and contains the verified SPIFFE identity of the caller.  It is available to
the application as an HTTP header and can be used for application-level audit
logging.
