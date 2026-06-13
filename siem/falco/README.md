# siem/falco/ — Runtime Security with Falco

Falco observes every Linux syscall made by every process in the cluster using a
kernel driver (kmod or eBPF).  When a sequence of syscalls matches a rule, Falco
emits a structured alert.  Falco Sidekick fans those alerts out to Elasticsearch
and a Slack webhook simultaneously.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kubernetes Node                                                     │
│                                                                      │
│   ┌──────────────┐   syscalls   ┌─────────────────────────────────┐│
│   │  Any pod     │ ───────────► │  Falco kernel driver            ││
│   │  (all ns)    │              │  (kmod: falco.ko /              ││
│   └──────────────┘              │   ebpf: falco.bpf.o)            ││
│                                 └──────────────┬────────────────────┘│
│                                                │ rule match           │
│                                                ▼                      │
│                                 ┌──────────────────────────────────┐ │
│                                 │  Falco daemon                    │ │
│                                 │  - falco_rules.yaml (built-in)   │ │
│                                 │  - securecloud_rules.yaml (ours) │ │
│                                 └───────────┬──────────────────────┘ │
└───────────────────────────────────────────── │ ────────────────────────┘
                                               │ HTTP POST :2801
                                               ▼
                              ┌────────────────────────────────┐
                              │  Falco Sidekick                │
                              │  (alert fanout router)         │
                              └─────────────┬──────────────────┘
                                            │
                      ┌─────────────────────┼───────────────────────┐
                      │                     │                       │
                      ▼                     ▼                       ▼
           ┌──────────────────┐  ┌─────────────────┐  ┌───────────────────┐
           │  Elasticsearch   │  │  Slack webhook  │  │  Sidekick UI      │
           │  falco-alerts-   │  │  (CRITICAL +    │  │  :2802            │
           │  YYYY.MM.dd      │  │   ERROR only)   │  │  (alert timeline) │
           └──────────────────┘  └─────────────────┘  └───────────────────┘
```

---

## Custom Rules

### Rule 1 — Shell Spawned Inside Container

| Field | Value |
|---|---|
| **Rule name** | `Shell Spawned Inside Container` |
| **Severity** | `WARNING` |
| **File** | `custom-rules.yaml` |

**What it detects:**
An `execve` syscall where the new process is a known shell binary (`bash`, `sh`,
`dash`, `zsh`, `ash`, `busybox`, etc.) running inside a container.

**Why shells are suspicious in containers:**
A correctly built container image has a single entrypoint process (e.g.
`uvicorn`, `gunicorn`, `postgres`).  The container filesystem may not even
include a shell binary.  When a shell appears, one of two things happened:

1. An operator ran `kubectl exec -it <pod> -- bash` for debugging.  This is
   benign but still worth auditing — every interactive session should be
   justified.

2. An attacker exploited a vulnerability (e.g. Log4Shell, SSRF leading to RCE)
   and used it to spawn a shell for exploration and lateral movement.

**MITRE ATT&CK mapping:**

| Technique ID | Name | How this rule detects it |
|---|---|---|
| **T1059** | Command and Scripting Interpreter | Direct: rule fires on `execve` of shell binary |
| **T1059.004** | Unix Shell | Specific sub-technique: bash/sh/zsh |
| **T1609** | Container Administration Command | Attacker using container exec for initial access |
| **T1204** | User Execution (indirect) | Operator exec confirms human in the loop |

**Expected alert volume:**
`LOW` — 1–5 alerts per deliberate debugging session.  Zero alerts in steady state.

**Tuning:**
Add namespaces or pod name patterns to `shell_spawn_allowed_namespaces` if a
specific workload legitimately spawns shells (e.g. a CI runner pod).  Do this
in `falco_rules.local.yaml`, not in this file, to keep overrides separated.

---

### Rule 2 — Sensitive File Read Inside Container

| Field | Value |
|---|---|
| **Rule name** | `Sensitive File Read Inside Container` |
| **Severity** | `ERROR` |
| **File** | `custom-rules.yaml` |

**What it detects:**
An `open`/`openat` syscall with `O_RDONLY` where the file descriptor resolves
to any of:

```
/etc/shadow           /etc/gshadow
/etc/passwd           /etc/group
/root/.ssh/id_rsa     /root/.ssh/id_ed25519
/root/.ssh/authorized_keys
/home/*/.ssh/*        (glob)
/proc/1/environ       (init environment — often contains injected secrets)
```

**Why these files matter:**

| File | Threat |
|---|---|
| `/etc/shadow` | Password hashes → offline dictionary attack (T1003.008) |
| `/etc/passwd` | Username enumeration, UID mapping |
| `~/.ssh/id_*` | Private keys for direct SSH authentication (T1552.001) |
| `/proc/1/environ` | Env vars of PID 1 include Kubernetes-injected `SECRET_KEY`, `DB_PASSWORD`, etc. |

**MITRE ATT&CK mapping:**

| Technique ID | Name | How this rule detects it |
|---|---|---|
| **T1552.001** | Unsecured Credentials: Credentials In Files | Reading SSH private keys |
| **T1003.008** | OS Credential Dumping: /etc/passwd and /etc/shadow | Reading shadow/passwd |
| **T1083** | File and Directory Discovery | Reading `/proc/1/environ` for recon |

**Expected alert volume:**
`VERY LOW` — near-zero in a healthy cluster.  Any alert here is high-fidelity.

**Common false positives:**
Container security scanners (Trivy, Grype) may read `/etc/passwd` during
vulnerability assessment.  Add the scanner's process name to
`sensitive_file_read_allowed_procs` if it runs inside a pod.

---

### Rule 3 — Unexpected External Connection from payment-api

| Field | Value |
|---|---|
| **Rule name** | `Unexpected External Connection from payment-api` |
| **Severity** | `ERROR` |
| **File** | `custom-rules.yaml` |

**What it detects:**
A `connect`/`sendto` syscall from a pod matching `payment-api-*` in the `apps`
namespace where the destination IP is not in RFC1918 private address space and
not in the `payment_api_allowed_external_ips` list.

**Why this rule is critical for a payment service:**
Payment API pods handle transaction data (account IDs, amounts, balances from
the `transactions` table in PostgreSQL).  The only legitimate outbound
connections are:

- `user-db.apps.svc.cluster.local:5432` — PostgreSQL (RFC1918)
- `kube-dns.kube-system.svc.cluster.local:53` — DNS (RFC1918)
- Prometheus scraper inbound (not outbound)

Any outbound connection to a public IP from this pod is a potential data
exfiltration or C2 event.

**MITRE ATT&CK mapping:**

| Technique ID | Name | How this rule detects it |
|---|---|---|
| **T1071** | Application Layer Protocol | C2 traffic masquerading as HTTP |
| **T1041** | Exfiltration Over C2 Channel | Financial data sent to attacker server |
| **T1048** | Exfiltration Over Alternative Protocol | Data exfil over DNS, ICMP, or raw TCP |
| **T1571** | Non-Standard Port | Connection to unusual port on external IP |

**Expected alert volume:**
`LOW` in a correctly configured cluster.  The network policy
`infra/network-policies/allow-api-to-db.yaml` already blocks this at L3/L4;
this Falco rule adds L7 visibility and alerts even if a network policy is
misconfigured or bypassed via a compromised CNI plugin.

**Adding legitimate external endpoints:**
```yaml
# In custom-rules.yaml, update the list:
- list: payment_api_allowed_external_ips
  items:
    - "203.0.113.50"   # production payment gateway (example)
```

---

### Rule 4 — Privilege Escalation via CAP_SYS_ADMIN

| Field | Value |
|---|---|
| **Rule name** | `Privilege Escalation via CAP_SYS_ADMIN` |
| **Severity** | `CRITICAL` |
| **File** | `custom-rules.yaml` |

**What it detects:**
A `capset` syscall inside a container where the new effective capability set
includes any of:

```
CAP_SYS_ADMIN    — mount, ioctl, ptrace, kernel module load
CAP_SYS_PTRACE   — ptrace any process
CAP_NET_ADMIN    — modify routing tables, iptables rules
CAP_SYS_MODULE   — load / unload kernel modules
```

**Why CAP_SYS_ADMIN is the most dangerous capability:**
`CAP_SYS_ADMIN` is effectively a superset of most other capabilities.  With it,
a process can:

1. **Mount the host filesystem:**
   ```bash
   mkdir /mnt/host && mount /dev/sda1 /mnt/host
   # Now has full read/write access to the node's disk
   ```

2. **Load a malicious kernel module:**
   ```bash
   insmod /tmp/rootkit.ko
   # Kernel code execution — full node compromise
   ```

3. **ptrace the kubelet:**
   ```bash
   # Extract the node's ServiceAccount token from kubelet memory
   # → compromise the entire cluster's control plane
   ```

4. **Escape via user namespaces + mount namespace:**
   A container with `CAP_SYS_ADMIN` can create a new user namespace and
   re-mount the host root, effectively escaping the container boundary.

All container deployments in this cluster use `securityContext.capabilities.drop: [ALL]`.
If this rule fires, either: (a) a security context was misconfigured, or
(b) an attacker exploited a kernel vulnerability to bypass the capability drop.

**MITRE ATT&CK mapping:**

| Technique ID | Name | How this rule detects it |
|---|---|---|
| **T1611** | Escape to Host | Capability acquisition is step 1 of most escape chains |
| **T1548** | Abuse Elevation Control Mechanism | Using setuid/capset to elevate |
| **T1068** | Exploitation for Privilege Escalation | Kernel exploit grants elevated capabilities |

**Expected alert volume:**
`VERY LOW` — should be zero.  Every alert is a P1 incident.

---

### Rule 5 — Namespace Escape via /proc Filesystem

| Field | Value |
|---|---|
| **Rule name** | `Namespace Escape Attempt via /proc Filesystem` |
| **Severity** | `CRITICAL` |
| **File** | `custom-rules.yaml` |

**What it detects:**
An `open`/`openat` syscall inside a container where the file descriptor path
matches:

```
/proc/1/root          → host root filesystem via init's mount namespace
/proc/1/mem           → host init process memory (credential extraction)
/proc/1/exe           → host init binary (identifies OS version for exploit selection)
/proc/self/root*      → container's own root (can be host root if mount ns not isolated)
/proc/*/root/etc/passwd → reading host's passwd via another process's mount ns
```

**The /proc/1/root escape technique in detail:**

Inside a container, `/proc/1/root` is a directory traversal to the root
filesystem of PID 1 in the container's PID namespace.  If the container is
running with `hostPID: true` (blocked by OPA Gatekeeper), PID 1 is the host's
init process — and `/proc/1/root` is the host's root filesystem.

Even without `hostPID`, a container with `CAP_SYS_ADMIN` can create a new PID
namespace where it becomes PID 1, then access `/proc/1/root` to read its own
root — but that root may be the host root if mount namespace isolation was
bypassed.

Classic CVE example: **CVE-2019-5736 (runc escape)**
The runc container runtime had a bug where an attacker could overwrite
`/proc/self/exe` (the runc binary) from inside a container during exec,
achieving arbitrary code execution on the host.

**MITRE ATT&CK mapping:**

| Technique ID | Name | How this rule detects it |
|---|---|---|
| **T1611** | Escape to Host | /proc/1/root access is a direct escape attempt |
| **T1083** | File and Directory Discovery | Reading host files for recon |
| **T1005** | Data from Local System | Reading sensitive host files via /proc |

**Expected alert volume:**
`VERY LOW` — zero in steady state.  The `attack-sim` namespace is excluded
because red-team exercises deliberately trigger this path.

---

## Deployment

```bash
# Install Falco with kernel module driver (default)
bash siem/falco/install-falco.sh

# Use eBPF driver instead
bash siem/falco/install-falco.sh --driver ebpf

# Verify rules loaded
kubectl exec -n siem \
  $(kubectl get pod -n siem -l app.kubernetes.io/name=falco -o name | head -1) \
  -- falco --list-rules 2>/dev/null | grep -E "Shell|Sensitive|payment|Privilege|Namespace"

# Live alert stream
kubectl logs -n siem -l app.kubernetes.io/name=falco -f | jq .
```

---

## Testing Each Rule

```bash
# Rule 1: Shell spawned
kubectl exec -n apps $(kubectl get pod -n apps -l app=frontend -o name | head -1) \
  -- bash -c 'id'

# Rule 2: Sensitive file read
kubectl exec -n apps $(kubectl get pod -n apps -l app=frontend -o name | head -1) \
  -- sh -c 'cat /etc/shadow 2>/dev/null || cat /etc/passwd'

# Rule 3: External connection from payment-api (simulated via curl)
kubectl exec -n apps $(kubectl get pod -n apps -l app=payment-api -o name | head -1) \
  -- sh -c 'curl -s --max-time 2 https://example.com || true'

# Rule 4: CAP_SYS_ADMIN (requires a pod that can actually acquire the cap — use attack-sim)
kubectl exec -n attack-sim <attacker-pod> \
  -- sh -c 'unshare -m /bin/bash'    # triggers capset in some kernel versions

# Rule 5: /proc/1/root access
kubectl exec -n apps $(kubectl get pod -n apps -l app=frontend -o name | head -1) \
  -- sh -c 'ls /proc/1/root/ 2>/dev/null || true'
```

---

## Kibana Queries for Falco Alerts

Once Sidekick routes alerts to Elasticsearch, use these queries in Kibana
(index pattern: `falco-alerts-*`):

```
# All CRITICAL alerts in the last 24 hours
priority: "Critical"

# Container escape attempts (Rules 4 and 5)
tags: "container_escape"

# payment-api specific alerts
output_fields.k8s.pod.name: "payment-api-*"

# Group by rule name (Visualize → Aggregation: Terms on rule.keyword)
# Group by priority  (Visualize → Aggregation: Terms on priority.keyword)
```

---

## Alert Volume Summary

| Rule | Severity | Expected Volume | Action |
|---|---|---|---|
| Shell Spawned | WARNING | Low (ops debugging) | Audit — confirm it was intentional |
| Sensitive File Read | ERROR | Very Low | Investigate immediately |
| External Connection from payment-api | ERROR | Low (possible false positives during startup) | Check dest IP; escalate if unknown |
| Privilege Escalation CAP_SYS_ADMIN | CRITICAL | Near-zero | P1 incident — contain pod |
| Namespace Escape /proc | CRITICAL | Near-zero | P1 incident — isolate node |

---

## Files in this Directory

| File | Purpose |
|---|---|
| `install-falco.sh` | Helm install of Falco (kmod/ebpf/modern_ebpf driver), custom rules ConfigMap, and Falco Sidekick |
| `custom-rules.yaml` | ConfigMap with 5 custom detection rules + supporting macros and lists |
| `falco-sidekick-values.yaml` | Sidekick Helm values: routes to Elasticsearch and Slack webhook |
| `falco-values.yaml` | Legacy standalone Falco values (superseded by install-falco.sh; kept for reference) |
