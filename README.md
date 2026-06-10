# SecureCloud-BD

**ML-driven anomaly detection for Kubernetes-native cloud workloads.**

SecureCloud-BD is a research-grade security framework that fuses Isolation
Forest and an LSTM Autoencoder in a weighted ensemble to detect anomalous
network flows in real time, integrated with Istio mTLS, OPA Gatekeeper,
Falco, and an ELK SIEM — all running on a single 8-GB workstation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Kubernetes (Minikube / k3s)                                        │
│                                                                     │
│  ┌─────────────┐    Zeek      ┌──────────────────────────────────┐  │
│  │  Workloads  │ ──conn.log─▶│  SIEM (siem ns)                   │ │
│  │ (securecloud│              │  Filebeat → Logstash → ES → Kibana│ │
│  │    ns)      │◀──mTLS──────│                                   │ │
│  └──────┬──────┘              └──────────────┬───────────────────┘  │
│         │ flows                              │ Falco alerts         │
│         ▼                                    ▼                      │
│  ┌─────────────┐             ┌──────────────────────────────────┐   │
│  │ Threat API  │◀────────────│  ML Inference (ml ns)            │  │
│  │  (FastAPI)  │  /score     │  IForest×0.4 + LSTM-AE×0.6       │   │
│  └─────────────┘             └──────────────────────────────────┘   │
│                                                                     │
│  OPA Gatekeeper (admission)   Istio mTLS STRICT (all namespaces)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

**Prerequisites:** Docker, Minikube, Helm 3, Python 3.10+, kubectl

```bash
# 1. Bootstrap cluster (Istio + OPA Gatekeeper)
bash infra/setup-minikube.sh

# 2. Deploy ELK SIEM + Falco
kubectl apply -f siem/elasticsearch/secret.yaml
kubectl apply -f siem/elasticsearch/statefulset.yaml
kubectl apply -f siem/logstash/configmap.yaml
kubectl apply -f siem/logstash/deployment.yaml
kubectl apply -f siem/kibana/deployment.yaml
kubectl apply -f siem/filebeat/daemonset.yaml
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm upgrade --install falco falcosecurity/falco -n siem -f siem/falco/falco-values.yaml

# 3. Preprocess datasets (download UNSW-NB15 first)
python datasets/unsw_nb15/preprocess.py \
  --train path/to/UNSW_NB15_training-set.csv \
  --test  path/to/UNSW_NB15_testing-set.csv \
  --out   datasets/unsw_nb15/processed/

# 4. Train models
python ml/training/train.py \
  --data datasets/unsw_nb15/processed/train.parquet \
  --output ml/models/saved

# 5. Build & deploy threat API
eval $(minikube docker-env)
docker build -f api/Dockerfile -t securecloud/threat-api:latest .
helm upgrade --install securecloud infra/helm/securecloud

# 6. Run attack simulations
export PIVOT_POD=$(kubectl get pods -n securecloud -o jsonpath='{.items[0].metadata.name}')
bash attack-sim/scripts/run_sim.sh
```

## Repository Structure

| Directory | Contents |
|-----------|----------|
| `infra/` | Kubernetes manifests, Istio policies, OPA Gatekeeper, Helm chart |
| `ml/` | IsolationForest + LSTM Autoencoder + ensemble (Python package) |
| `api/` | FastAPI scoring service + Dockerfile |
| `siem/` | ELK stack configs, Filebeat DaemonSet, Falco rules |
| `attack-sim/` | Ansible playbooks (recon, lateral movement, exfil) + traffic generator |
| `datasets/` | UNSW-NB15 and CIC-IDS2017 preprocessing pipelines |
| `paper/` | IEEE-format LaTeX paper |

## ML Ensemble

| Component | Algorithm | Weight |
|-----------|-----------|--------|
| Isolation Forest | Structural anomaly (path length) | **0.4** |
| LSTM Autoencoder | Temporal anomaly (reconstruction error) | **0.6** |

Both models score in [0, 1]. A flow is flagged anomalous if the fused score ≥ 0.5.

## Testing

```bash
pytest ml/tests/ api/tests/ datasets/tests/ -v
```

## Datasets

- **UNSW-NB15**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **CIC-IDS2017**: https://www.unb.ca/cic/datasets/ids-2017.html

Raw dataset files are **not** included in this repository.

## License

MIT — see [LICENSE](LICENSE).
