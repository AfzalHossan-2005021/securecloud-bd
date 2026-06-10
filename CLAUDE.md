# SecureCloud-BD — CLAUDE.md

## Project Purpose
Research-grade Kubernetes security framework combining ML anomaly detection
(IsolationForest + LSTM Autoencoder ensemble) with defence-in-depth
infrastructure controls (Istio mTLS, OPA Gatekeeper, Falco, ELK SIEM).

## Directory Layout
```
securecloud-bd/
├── infra/          Kubernetes manifests + Helm chart (securecloud)
│   ├── namespaces/ Namespace definitions (securecloud, siem, ml)
│   ├── istio/      PeerAuthentication, DestinationRules, AuthorizationPolicies
│   ├── gatekeeper/ OPA ConstraintTemplates + Constraints
│   └── helm/securecloud/  Main Helm chart
├── ml/             Python ML package
│   ├── models/     IForestDetector, LSTMAutoencoder, ThreatEnsemble
│   ├── training/   train.py — CLI training script
│   ├── inference/  infer.py — batch scoring helper
│   └── tests/      pytest unit tests
├── api/            FastAPI threat-scoring service
│   ├── app/        main.py, schemas.py, model_loader.py
│   ├── tests/      API integration tests (mocked models)
│   └── Dockerfile
├── siem/           ELK + Filebeat + Falco
│   ├── elasticsearch/  StatefulSet + Secret
│   ├── logstash/   ConfigMap (pipeline conf) + Deployment
│   ├── kibana/     Deployment
│   ├── filebeat/   DaemonSet + RBAC
│   └── falco/      falco-values.yaml (Helm values with custom rules)
├── attack-sim/     Attack simulation
│   ├── playbooks/  Ansible: recon, lateral-movement, data-exfiltration
│   └── scripts/    generate_traffic.py, run_sim.sh
├── datasets/       Preprocessing pipelines
│   ├── unsw_nb15/  preprocess.py
│   └── cic_ids2017/ preprocess.py
└── paper/          LaTeX IEEE paper
    ├── main.tex
    ├── sections/   01_intro … 07_conclusion
    └── references.bib
```

## Key Design Decisions
- **Ensemble weights**: iForest × 0.4 + LSTM-AE × 0.6 (AE captures temporal patterns for slow attacks)
- **Feature schema**: 20 canonical features derived from Zeek conn.log (see `api/app/schemas.py:FEATURE_NAMES`)
- **mTLS**: STRICT across all three namespaces; no plaintext inter-pod traffic allowed
- **Default-deny**: every namespace has a `deny-all` AuthorizationPolicy; explicit allows only
- **Single-node constraint**: 8 GB RAM minimum; resource limits set conservatively in Helm values

## Running Locally

### 1. Bootstrap cluster
```bash
bash infra/setup-minikube.sh
```

### 2. Deploy SIEM
```bash
kubectl apply -f siem/elasticsearch/secret.yaml
kubectl apply -f siem/elasticsearch/statefulset.yaml
kubectl apply -f siem/logstash/configmap.yaml
kubectl apply -f siem/logstash/deployment.yaml
kubectl apply -f siem/kibana/deployment.yaml
kubectl apply -f siem/filebeat/daemonset.yaml
helm upgrade --install falco falcosecurity/falco -n siem -f siem/falco/falco-values.yaml
```

### 3. Train models
```bash
cd ml
pip install -r requirements.txt
# After preprocessing datasets:
python training/train.py --data ../datasets/unsw_nb15/processed/train.parquet \
                         --output models/saved --epochs 50
```

### 4. Build & deploy API
```bash
eval $(minikube docker-env)
docker build -f api/Dockerfile -t securecloud/threat-api:latest .
helm upgrade --install securecloud infra/helm/securecloud
```

### 5. Run attack simulation
```bash
export PIVOT_POD=<pod-name>
bash attack-sim/scripts/run_sim.sh
```

## Testing
```bash
# ML unit tests
cd ml && pytest tests/ -v

# API tests
cd api && pytest tests/ -v

# Dataset preprocessing tests
pytest datasets/tests/ -v
```

## Conventions
- Python 3.10+, TensorFlow 2.x, FastAPI, scikit-learn
- All K8s manifests go under `infra/` or `siem/` — no inline kubectl apply in Python
- Model weights: 0.4 (iForest) + 0.6 (AE) = 1.0; do not change without rerunning grid search
- Never commit Elasticsearch passwords to git; use kubectl create secret
- Falco rules file: `siem/falco/falco-values.yaml` under `customRules:`
