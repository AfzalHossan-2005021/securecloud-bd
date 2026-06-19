# Dataset Card: SecureCloud-BD k8s-Native Network Flow Dataset

**Version** 1.0 · **License** CC BY 4.0 · **Task** Binary anomaly detection (network intrusion)

---

## Summary

A labelled network-flow dataset collected from a single-node Minikube Kubernetes
cluster running the SecureCloud-BD three-service application stack (ML API,
Elasticsearch, Kibana). Traffic was captured with Zeek 6.x on the Minikube
bridge interface and parsed into the same 20-feature canonical schema used to
train the IsolationForest + LSTM-Autoencoder ensemble.

The dataset complements UNSW-NB15 and CIC-IDS2017 with Kubernetes-native traffic
patterns: control-plane heartbeats, inter-pod mTLS flows, Prometheus scrapes, and
realistic attack payloads executed by the `attack-sim/` framework.

---

## Collection Environment

| Parameter | Value |
|---|---|
| Host OS | Ubuntu 22.04 LTS (Kali Linux for attack VM) |
| Hypervisor | Minikube v1.32+ (Docker driver) |
| Kubernetes | v1.29+ |
| CNI | Kindnet (default Minikube) |
| Service mesh | Istio 1.20 (STRICT mTLS) |
| Capture tool | Zeek 6.x |
| Zeek policy | `ml/zeek/zeek-config/local.zeek` (JSON output) |
| Log format | JSONL conn.log (one record per completed flow) |
| Network interface | Minikube bridge (auto-detected via `ip route get`) |
| Normal traffic | k6 load generator → `/health`, `/score`, `/score/batch` |
| Normal duration | 60 minutes per session (configurable) |
| Attack traffic | `attack-sim/scenarios/01–05` on Kali Linux VM |

---

## Attack Scenarios

| # | Script | Label | Subcategory | MITRE ATT&CK | Severity |
|---|---|---|---|---|---|
| 1 | `01-port-scan.sh` | 1 | `portscan` | T1046 | MEDIUM |
| 2 | `02-dos-flood.sh` | 1 | `dos` | T1498.001 | HIGH |
| 3 | `03-ssh-brute-force.sh` | 1 | `brute_force` | T1110.001 | HIGH |
| 4 | `04-lateral-movement.sh` | 1 | `lateral_movement` | T1021 | HIGH |
| 5 | `05-bkash-scenario.sh` | 1 | `bkash_scenario` | T1609→T1552→T1021→T1041→T1003 | CRITICAL |

**Detection controls active during capture:** Falco 0.37+, OPA Gatekeeper,
Istio AuthorizationPolicies (default-deny), mTLS STRICT.

---

## Feature Schema

All 20 features are derived directly from Zeek `conn.log` fields.
The same schema is used in `api/app/schemas.py`, `datasets/unsw_nb15/preprocess.py`,
and `datasets/cic_ids2017/preprocess.py`.

| # | Feature | Zeek Field | Type | Description |
|---|---|---|---|---|
| 1 | `duration` | `duration` | float | Flow duration in seconds |
| 2 | `orig_bytes` | `orig_bytes` | float | Bytes sent by originator |
| 3 | `resp_bytes` | `resp_bytes` | float | Bytes sent by responder |
| 4 | `orig_pkts` | `orig_pkts` | float | Packets sent by originator |
| 5 | `resp_pkts` | `resp_pkts` | float | Packets sent by responder |
| 6 | `orig_ip_bytes` | `orig_ip_bytes` | float | IP-layer bytes from originator |
| 7 | `resp_ip_bytes` | `resp_ip_bytes` | float | IP-layer bytes from responder |
| 8 | `missed_bytes` | `missed_bytes` | float | Bytes not captured (gaps) |
| 9 | `proto_tcp` | `proto == "tcp"` | 0/1 | TCP protocol indicator |
| 10 | `proto_udp` | `proto == "udp"` | 0/1 | UDP protocol indicator |
| 11 | `proto_icmp` | `proto == "icmp"` | 0/1 | ICMP protocol indicator |
| 12 | `conn_state_S0` | `conn_state == "S0"` | 0/1 | SYN seen, no response |
| 13 | `conn_state_SF` | `conn_state == "SF"` | 0/1 | Normal connection close |
| 14 | `conn_state_REJ` | `conn_state == "REJ"` | 0/1 | Connection rejected |
| 15 | `conn_state_RSTO` | `conn_state == "RSTO"` | 0/1 | Originator RST |
| 16 | `service_http` | `service ∈ {http,https}` | 0/1 | HTTP/S application |
| 17 | `service_dns` | `service == "dns"` | 0/1 | DNS application |
| 18 | `service_ssl` | `service ∈ {ssl,tls}` | 0/1 | TLS/SSL application |
| 19 | `bytes_per_pkt_orig` | derived | float | `orig_bytes / orig_pkts` |
| 20 | `bytes_per_pkt_resp` | derived | float | `resp_bytes / resp_pkts` |

Features 1–8 are continuous; 9–18 are one-hot encoded; 19–20 are derived.
Missing or "-" Zeek fields are mapped to 0.0.

---

## Label Schema

| Column | Type | Values |
|---|---|---|
| `label` | int8 | 0 = normal, 1 = attack |
| `subcategory` | str | normal · portscan · dos · brute_force · lateral_movement · bkash_scenario |
| `source_file` | str | Original log filename (traceability) |

---

## Preprocessing

**Scaler:** MinMaxScaler fitted on **normal flows only** (`label == 0`).
This calibrates the [0, 1] range to benign traffic statistics. Attack flows may
produce values outside this range, which is intentional — the out-of-range signal
is informative for IsolationForest and the LSTM Autoencoder reconstruction loss.

This differs from `datasets/unsw_nb15/preprocess.py` and `datasets/cic_ids2017/preprocess.py`,
where the scaler is fitted on mixed (normal + attack) data.

The fitted scaler is saved to `datasets/processed/k8s-scaler.joblib` for reproducible
test-set scaling.

**Pipeline script:** `datasets/capture/build-k8s-dataset.py`

```bash
# Rebuild dataset from raw captures
python3 datasets/capture/build-k8s-dataset.py \
    --raw-dir  datasets/raw \
    --output   datasets/processed/k8s-native-dataset.parquet \
    --scaler   datasets/processed/k8s-scaler.joblib \
    --pretty
```

---

## Dataset Statistics (template — fill after running build script)

| Metric | Value |
|---|---|
| Total flows | _N_ |
| Normal flows | _N_ (_pct_%) |
| Attack flows | _N_ (_pct_%) |
| — portscan | _N_ |
| — dos | _N_ |
| — brute_force | _N_ |
| — lateral_movement | _N_ |
| — bkash_scenario | _N_ |
| Capture sessions (normal) | _N_ × 60 min |
| Capture sessions (attack) | 5 scenarios × 1 run |
| Parquet size | _N_ MB (Snappy compressed) |

---

## Known Limitations

1. **Single-node cluster.** All traffic flows through the same Minikube bridge.
   Real multi-node clusters generate cross-node VXLAN/Geneve traffic not present here.

2. **Simulated attacks only.** Attack flows were generated by controlled scripts,
   not adversarial humans. The timing and tooling signatures may not match
   real-world attacker behaviour.

3. **mTLS Zeek blind-spot.** Istio mTLS encrypts inter-pod payloads.
   Zeek sees the TLS handshake and connection metadata but not application-layer content.
   Features 16–18 (service one-hot) may be zero for encrypted flows.

4. **Traffic generator artifacts.** k6 and the curl fallback generate flows with
   regular inter-arrival times. Normal traffic from real users has higher burstiness
   (Hurst exponent > 0.5); the k6 baseline is more uniform.

5. **Missing conn.log fields.** Zeek omits `duration`, `orig_bytes`, and related
   fields for zero-length or incomplete flows (TCP SYN only, ICMP unreachable).
   These are mapped to 0.0 by the feature extractor, which may overlap with
   some attack patterns (e.g., SYN scan flows have `conn_state = S0` and `orig_bytes = 0`).

6. **Label coarseness.** `bkash_scenario` covers a 5-step kill chain;
   each individual step is not separately labelled at flow level.

7. **Scaler leakage risk (inter-session).** If attack traffic is captured before
   normal traffic, the scaler (fitted on normal flows) will be built from a smaller
   corpus. Always capture normal traffic before combining with attack captures.

---

## Usage with Training Script

```python
import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_parquet("datasets/processed/k8s-native-dataset.parquet")

FEATURE_COLS = [c for c in df.columns if c not in ("label", "subcategory", "source_file")]
X = df[FEATURE_COLS].values.astype("float32")
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Combine with UNSW-NB15 for joint training (feature schemas are identical)
train_unsw = pd.read_parquet("datasets/unsw_nb15/processed/train.parquet")
X_combined = np.vstack([X_train, train_unsw[FEATURE_COLS].values])
y_combined = np.concatenate([y_train, train_unsw["label"].values])
```

---

## Citation

If using this dataset in a publication, please cite:

```
@dataset{securecloud_bd_k8s_2026,
  title     = {SecureCloud-BD k8s-Native Network Flow Dataset},
  author    = {Hossan, Afzal},
  year      = {2026},
  note      = {Captured from Minikube single-node cluster with Zeek 6.x.
               Five MITRE ATT\&CK-mapped attack scenarios.},
  url       = {https://github.com/user/securecloud-bd}
}
```

---

## Reproduction Steps

```bash
# 1. Start the cluster and deploy services
bash infra/setup-minikube.sh
helm upgrade --install securecloud infra/helm/securecloud

# 2. Install Zeek on the host
bash ml/zeek/zeek-install.sh
sudo cp ml/zeek/zeek-config/local.zeek /opt/zeek/share/zeek/site/local.zeek

# 3. Capture normal traffic (60 min)
sudo CAPTURE_DURATION=3600 bash datasets/capture/capture-normal-traffic.sh

# 4. Capture attack traffic (all 5 scenarios)
sudo bash datasets/capture/capture-attack-traffic.sh

# 5. Build dataset
python3 datasets/capture/build-k8s-dataset.py --pretty

# 6. Verify
python3 -c "
import pandas as pd
df = pd.read_parquet('datasets/processed/k8s-native-dataset.parquet')
print(df.shape, df['subcategory'].value_counts().to_dict())
"
```
