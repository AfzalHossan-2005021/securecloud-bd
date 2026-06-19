# SecureCloud-BD — Attack Simulation Framework

Structured Kali Linux–based attack scenarios against the Minikube lab cluster.
Every scenario is **self-contained**, writes machine-parseable results to
`attack-sim/results/`, and prints a clear DETECTED / BLOCKED / UNDETECTED
verdict after running.

> **⚠ SAFETY WARNING**
>
> These scripts generate genuine attack traffic.  Run them **only** against the
> dedicated SecureCloud-BD Minikube cluster on an isolated host or host-only
> network.  **Never run against shared infrastructure, cloud environments, or
> production clusters.**  The scripts require `kubectl` admin access to the
> cluster and will create, modify, and delete Kubernetes objects.

---

## Environment overview

```
┌────────────────────────────────────────────────────────────────────────┐
│  Host machine (Linux)                                                  │
│                                                                        │
│  ┌─────────────────────────┐    ┌────────────────────────────────────┐ │
│  │  Minikube cluster        │    │  Kali Linux VM                     │ │
│  │  (192.168.49.0/24)       │    │  (host-only network)               │ │
│  │                          │    │                                    │ │
│  │  Namespace: securecloud  │◄───│  nmap, hping3, hydra, kubectl      │ │
│  │  Namespace: siem         │    │  Python 3.10+, ansible             │ │
│  │  Namespace: ml           │    │                                    │ │
│  └─────────────────────────┘    └────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### Why Kali on the same host network as Minikube?

Minikube runs as a VM/container on the host with a dedicated internal network
(`192.168.49.0/24` by default).  NodePort services are reachable from the host
but not from an external VM unless it shares the same network segment.  The
Kali VM must be on the **host-only** adapter that bridges to the Minikube
network; alternatively, route traffic via the host with `minikube tunnel`.

---

## Prerequisites on the Kali VM

```bash
sudo apt-get update
sudo apt-get install -y \
    nmap hping3 hydra \
    python3 python3-requests python3-rich \
    curl netcat-traditional dnsutils jq

# kubectl (copy from host or install directly)
curl -LO "https://dl.k8s.io/release/$(curl -s \
    https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 755 kubectl /usr/local/bin/kubectl

# Copy kubeconfig from host
scp host-user@host-machine:~/.kube/config ~/.kube/config
# Verify
kubectl get nodes
```

---

## Finding cluster NodePorts

```bash
# Minikube IP (run on host or from Kali if routing is set up)
MINIKUBE_IP=$(minikube ip)          # e.g. 192.168.49.2

# All exposed NodePorts
kubectl get svc -A \
    -o=jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.ports[*].nodePort}{"\n"}{end}' \
    | column -t

# Quick one-liner for the threat-api NodePort
kubectl get svc securecloud-api -n securecloud \
    -o jsonpath='{.spec.ports[0].nodePort}'
```

---

## Directory layout

```
attack-sim/
├── README.md               This file
├── collect-results.py      Aggregate all results → JSON report
├── scenarios/
│   ├── 01-port-scan.sh         MITRE T1046 — Network Service Discovery
│   ├── 02-dos-flood.sh         MITRE T1498 — Network DoS
│   ├── 03-ssh-brute-force.sh   MITRE T1110.001 — Password Guessing
│   ├── 04-lateral-movement.sh  MITRE T1021 — Remote Services
│   └── 05-bkash-scenario.sh    Flagship kill-chain (5 stages)
├── manifests/
│   └── ssh-test-pod.yaml       Intentionally vulnerable SSH target
├── wordlists/
│   ├── ssh-users.txt           10 common SSH usernames
│   └── ssh-passwords.txt       20 common passwords (includes the test cred)
├── playbooks/                  Existing Ansible playbooks (see legacy README)
├── scripts/                    Existing helper scripts
└── results/                    ← scenario output lands here (gitignored)
```

---

## Running scenarios

Each script is self-contained.  Set two environment variables once, then run:

```bash
export MINIKUBE_IP=$(minikube ip)
export KUBECONFIG=~/.kube/config

# Individual scenarios
bash attack-sim/scenarios/01-port-scan.sh
bash attack-sim/scenarios/02-dos-flood.sh
bash attack-sim/scenarios/03-ssh-brute-force.sh
bash attack-sim/scenarios/04-lateral-movement.sh
bash attack-sim/scenarios/05-bkash-scenario.sh

# Aggregate results
python3 attack-sim/collect-results.py --results-dir attack-sim/results
```

### Environment variables (override defaults)

| Variable | Default | Description |
|----------|---------|-------------|
| `MINIKUBE_IP` | auto-detected | Cluster node IP |
| `API_NODEPORT` | auto-detected | SecureCloud threat-API NodePort |
| `SSH_NODEPORT` | auto-detected | SSH test pod NodePort |
| `NS` | `securecloud` | Primary application namespace |
| `SIEM_NS` | `siem` | SIEM namespace (for Falco log queries) |
| `PAYMENT_API_APP` | `securecloud-api` | Label `app=` for payment-api pod |
| `USER_DB_APP` | `user-db` | Label `app=` for user-db pod |

---

## Detection expectations per scenario

| Scenario | Tool / Rule | Expected result |
|----------|-------------|-----------------|
| 01 Port scan | Falco: `Unexpected outbound connection` | DETECTED ≤ 30 s |
| 02 DoS flood | Falco: `Outbound traffic burst` / Zeek weird | DETECTED ≤ 60 s |
| 03 SSH brute | Falco: `Detected SSH Brute Force` | DETECTED ≤ 10 s |
| 04 Lateral mv | NetworkPolicy (Istio/k8s) | Steps 2, 4 → BLOCKED |
| 05 bKash chain | Falco + NetworkPolicy | 4 / 5 steps blocked or detected |

---

## Falco logs

```bash
# Tail all Falco alerts in real time
kubectl logs -n siem -l app.kubernetes.io/name=falco -f \
    | grep --color -E 'Notice|Warning|Error'

# Count alerts since a specific ISO timestamp
kubectl logs -n siem -l app.kubernetes.io/name=falco \
    --since-time="2024-01-15T10:30:00Z" \
    | grep -c Notice
```

---

## Generating the aggregate report

```bash
python3 attack-sim/collect-results.py \
    --results-dir attack-sim/results \
    --output      attack-sim/report-$(date +%Y%m%d).json \
    --pretty

# Example output fields:
# {
#   "summary": {
#     "scenarios_run": 5,
#     "detection_rate_pct": 80.0,
#     "mean_time_to_detect_seconds": 18.3,
#     "network_policy_blocks": 3,
#     "falco_total_alerts": 9
#   },
#   "scenarios": { ... }
# }
```

---

## Cleanup

```bash
# Remove the SSH test pod after scenario 3
kubectl delete -f attack-sim/manifests/ssh-test-pod.yaml --ignore-not-found

# Remove all simulation results
rm -f attack-sim/results/*.txt attack-sim/results/*.json
```

---

## Responsible use checklist

- [ ] Cluster is the local Minikube lab (not a cloud cluster)
- [ ] Kali VM is on the host-only network only (no external internet for attack tools)
- [ ] You hold the `kubectl` admin credentials for this cluster
- [ ] SSH test pod is deleted within 30 minutes of scenario 3 completing
- [ ] Results files do not contain production credentials or IP addresses
- [ ] Simulation is run during a scheduled maintenance/test window
