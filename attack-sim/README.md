# attack-sim/

Attack simulation framework for SecureCloud-BD.

**Purpose:** Generate labelled malicious traffic against the Minikube cluster so that
the ML pipeline has realistic positive examples and so that Falco rules can be validated
end-to-end.  All simulations run inside the cluster in an isolated attacker pod.

> **IMPORTANT:** Run these simulations **only** in the dedicated Minikube/k3s lab
> environment.  Never target production or shared infrastructure.

## Sub-directories

| Path | Contents |
|------|---------|
| `playbooks/` | Ansible playbooks — one per attack class |
| `scripts/` | Shell orchestration (`run_sim.sh`) and synthetic data generator |

## Attack playbooks

| Playbook | Simulates | Expected detections |
|----------|-----------|---------------------|
| `recon.yaml` | `kubectl` enumeration, nmap port scan, secret-read attempt | Falco: unexpected outbound; IForest: high S0 ratio |
| `lateral-movement.yaml` | `kubectl exec`, service-account token abuse, cross-namespace API calls | Falco: shell-in-container, privilege escalation |
| `data-exfiltration.yaml` | Large HTTP POST, DNS tunnelling (100 queries), TCP beaconing | AE: high reconstruction error on long-duration flows |

## Run all simulations

```bash
# Requires a running securecloud namespace with at least one pod
export PIVOT_POD=$(kubectl get pods -n securecloud -o jsonpath='{.items[0].metadata.name}')
export EXFIL_SERVER=10.0.0.99   # set to your lab listener IP
bash attack-sim/scripts/run_sim.sh
```

Results land in `attack-sim/results/` (gitignored).

## Generate synthetic labelled traffic (offline, no cluster needed)

```bash
python attack-sim/scripts/generate_traffic.py \
  --normal 50000 \
  --attack 5000 \
  --out    datasets/synthetic.csv
```

Produces a CSV with the canonical 20-feature schema plus a `label` column
(0 = normal, 1 = attack).  Useful for initial model training before real
dataset downloads are available.

## Attacker pod spec

`run_sim.sh` creates a `kali-rolling` pod labelled `simulation=true` in the
`securecloud` namespace, installs `ansible`, `nmap`, `curl`, `netcat`, and
`dnsutils`, runs all playbooks, copies results out, then deletes the pod.
The pod label can be used to scope Falco exclusion rules if needed during
baseline collection.
