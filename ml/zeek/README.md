# SecureCloud-BD — Zeek Integration

Real-time network telemetry pipeline:  
**Network interface → Zeek → Feature extractor → ML API → Elasticsearch → Kibana**

---

## Full Data Path

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NETWORK INTERFACE (eth0)                            │
│               All packets captured in promiscuous mode by Zeek              │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ZEEK (Network Security Monitor)                      │
│                                                                             │
│  Analyzers loaded by zeek-config/local.zeek:                                │
│    base/protocols/conn  →  conn.log  (primary ML input)                     │
│    base/protocols/dns   →  dns.log                                          │
│    base/protocols/http  →  http.log                                         │
│    base/protocols/ssl   →  ssl.log                                          │
│    base/misc/weird      →  weird.log                                        │
│    policy/tuning/json-logs  →  all logs written as JSONL                    │
│                                                                             │
│  Output directory: /opt/zeek/logs/current/                                  │
│  One JSON object per line; one line per completed TCP/UDP/ICMP flow.        │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                    /opt/zeek/logs/current/conn.log
                    (new lines appended as flows complete)
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              flow-to-features.py  (ml/zeek/flow-to-features.py)             │
│                                                                             │
│  • watchdog inotify observer tails conn.log in real time                    │
│  • Handles log rotation (Zeek rotates hourly via ZeekControl)               │
│  • For each completed flow, extracts 20 canonical features:                 │
│                                                                             │
│    duration          orig_bytes       resp_bytes      orig_pkts             │
│    resp_pkts         orig_ip_bytes    resp_ip_bytes   missed_bytes          │
│    proto_tcp         proto_udp        proto_icmp                            │
│    conn_state_S0     conn_state_SF    conn_state_REJ  conn_state_RSTO       │
│    service_http      service_dns      service_ssl                           │
│    bytes_per_pkt_orig               bytes_per_pkt_resp                      │
│                                                                             │
│  • POSTs {"features": [...20 floats...]} to POST /score                     │
│  • Retries up to 3× with exponential back-off on network errors             │
│  • Writes enriched JSONL entry to zeek-scored-flows.log                     │
└──────────────┬───────────────────────────────┬─────────────────────────────┘
               │                               │
               │  POST /score                  │  zeek-scored-flows.log
               ▼                               │
┌──────────────────────────────┐               │
│   SecureCloud-BD ML API      │               │
│   (api/main.py — FastAPI)    │               │
│                              │               │
│   IForest × 0.4              │               │
│   LSTM-AE × 0.6              │               │
│   ──────────────             │               │
│   ensemble_score             │               │
│   is_anomaly                 │               │
│   explanation { ... }        │               │
└──────────────────────────────┘               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│             scored-to-elastic.py  (ml/zeek/scored-to-elastic.py)            │
│                                                                             │
│  • watchdog observer tails zeek-scored-flows.log                            │
│  • Buffers up to 100 records OR 5 seconds (whichever comes first)           │
│  • Sends batches via Elasticsearch /_bulk API                               │
│  • Index pattern: ml-scores-YYYY.MM.DD                                      │
│  • Flattens _securecloud.* → ml.* for Kibana field discovery                │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │  POST /_bulk
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│            ELASTICSEARCH  (siem namespace, port 9200)                       │
│                                                                             │
│  Indices:  ml-scores-2024.01.15, ml-scores-2024.01.16, …                   │
│  Key fields: @timestamp, src_ip, dst_ip, proto, service,                   │
│              ml.ensemble_score, ml.is_anomaly, ml.explanation              │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              KIBANA  (siem namespace, port 5601)                            │
│                                                                             │
│  Index pattern:  ml-scores-*                                                │
│  Dashboards:                                                                │
│    • Anomaly Rate Over Time (TSVB / Lens)                                   │
│    • Top Anomalous Source IPs                                               │
│    • Score Distribution (iforest vs lstm vs ensemble)                       │
│    • Protocol / Service breakdown                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Component | Minimum version | Notes |
|-----------|-----------------|-------|
| Zeek LTS  | 6.x             | Installed by `zeek-install.sh` |
| Python    | 3.10            | `watchdog`, `requests` required |
| ML API    | —               | `api/main.py` must be running |
| Elasticsearch | 8.x         | `siem` namespace pod or local |

---

## Setup

### 1. Install Zeek

```bash
# Run as root on Ubuntu 20.04 / 22.04 / 24.04 or Debian 11/12
sudo bash ml/zeek/zeek-install.sh --iface eth0
```

The script:
- Adds the Zeek OBS apt repository
- Installs `zeek-lts` (6.x)
- Writes `node.cfg` with the specified interface
- Installs `zeek-config/local.zeek` → `/opt/zeek/share/zeek/site/local.zeek`
- Runs `zeekctl install`
- Installs Python dependencies (`watchdog`, `requests`)

### 2. Start Zeek

```bash
sudo zeekctl start
sudo zeekctl status          # should show "running"
tail -f /opt/zeek/logs/current/conn.log   # verify JSONL output
```

Expected conn.log line:
```json
{"ts":1705316400.123,"uid":"Cg1A...","id.orig_h":"192.168.1.10","id.orig_p":54321,"id.resp_h":"93.184.216.34","id.resp_p":80,"proto":"tcp","service":"http","duration":0.352,"orig_bytes":254,"resp_bytes":1200,"conn_state":"SF","missed_bytes":0,"orig_pkts":6,"orig_ip_bytes":562,"resp_pkts":5,"resp_ip_bytes":1508}
```

### 3. Start the ML API

```bash
# From the repo root
docker build -f api/Dockerfile -t securecloud/threat-api:latest .
docker run -p 8080:8080 -v $(pwd)/ml/models/saved:/models securecloud/threat-api:latest
# Or with kubectl / helm — see infra/helm/securecloud
```

### 4. Start the feature extractor

```bash
python3 ml/zeek/flow-to-features.py \
    --conn-log /opt/zeek/logs/current/conn.log \
    --api-url  http://localhost:8080/score \
    --output   zeek-scored-flows.log
```

Options:
| Flag | Default | Description |
|------|---------|-------------|
| `--conn-log` | `/opt/zeek/logs/current/conn.log` | Zeek conn.log path |
| `--api-url` | `http://localhost:8080/score` | ML API endpoint |
| `--output` | `zeek-scored-flows.log` | Scored flows output (JSONL) |
| `--api-timeout` | `5.0` | API request timeout (seconds) |
| `--api-retries` | `3` | Retry attempts on API errors |
| `--from-beginning` | off | Replay the current log file from position 0 |
| `--poll` | off | Use polling observer (for NFS / Docker volumes) |

### 5. Start the Elasticsearch shipper

```bash
python3 ml/zeek/scored-to-elastic.py \
    --input      zeek-scored-flows.log \
    --es-url     http://localhost:9200 \
    --es-user    elastic \
    --es-password changeme
```

Options:
| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `zeek-scored-flows.log` | Scored flows JSONL path |
| `--es-url` | `$ES_URL` or `http://localhost:9200` | Elasticsearch URL |
| `--es-user` | `$ES_USER` | Basic auth username |
| `--es-password` | `$ES_PASSWORD` | Basic auth password |
| `--index-prefix` | `ml-scores` | Index name prefix |
| `--batch-size` | `100` | Documents per bulk request |
| `--flush-interval` | `5.0` | Max seconds between flushes |
| `--from-beginning` | off | Ship the entire file, not just new entries |

---

## Elasticsearch Index

### Index pattern

`ml-scores-YYYY.MM.DD` (daily rotation)

### Key fields

| Field | Type | Description |
|-------|------|-------------|
| `@timestamp` | date | UTC timestamp from Zeek `ts` field |
| `uid` | keyword | Zeek connection UID |
| `src_ip` | ip | Originator IP address |
| `dst_ip` | ip | Responder IP address |
| `dst_port` | integer | Responder port |
| `proto` | keyword | `tcp` / `udp` / `icmp` |
| `service` | keyword | Application protocol (`http`, `dns`, `ssl`, …) |
| `conn_state` | keyword | Zeek connection state (`SF`, `S0`, `REJ`, …) |
| `ml.ensemble_score` | float | Weighted score ∈ [0, 1]; 1 = maximally anomalous |
| `ml.iforest_score` | float | IsolationForest sub-model score |
| `ml.lstm_score` | float | LSTM-AE sub-model score (normalised) |
| `ml.is_anomaly` | boolean | `true` when `ensemble_score ≥ 0.5` |
| `ml.explanation` | object | Per-model score contribution breakdown |

### Create index template (run once)

```bash
curl -u elastic:changeme -X PUT http://localhost:9200/_index_template/ml-scores \
  -H "Content-Type: application/json" -d '{
    "index_patterns": ["ml-scores-*"],
    "template": {
      "settings": { "number_of_replicas": 0 },
      "mappings": {
        "properties": {
          "@timestamp":         { "type": "date" },
          "src_ip":             { "type": "ip" },
          "dst_ip":             { "type": "ip" },
          "src_port":           { "type": "integer" },
          "dst_port":           { "type": "integer" },
          "duration":           { "type": "float" },
          "orig_bytes":         { "type": "long" },
          "resp_bytes":         { "type": "long" },
          "ml.ensemble_score":  { "type": "float" },
          "ml.iforest_score":   { "type": "float" },
          "ml.lstm_score":      { "type": "float" },
          "ml.is_anomaly":      { "type": "boolean" },
          "ml.api_latency_ms":  { "type": "float" },
          "ml.features": {
            "type": "dense_vector",
            "dims": 20,
            "index": false
          }
        }
      }
    }
  }'
```

---

## Kibana Setup

1. Open Kibana → **Stack Management → Data Views**
2. Create a data view: `ml-scores-*`, time field `@timestamp`
3. Open **Dashboards** and build panels:

| Panel | Visualisation | X-axis | Y-axis / Metric |
|-------|--------------|--------|-----------------|
| Anomaly rate over time | TSVB / Line | `@timestamp` | `% of ml.is_anomaly: true` |
| Score distribution | Histogram | `ml.ensemble_score` (0–1) | count |
| Top anomalous IPs | Data table | `src_ip` | top 10 by `ml.is_anomaly: true` |
| Protocol breakdown | Pie | `proto` | count |
| IForest vs LSTM-AE | Scatter | `ml.iforest_score` | `ml.lstm_score` |

---

## Troubleshooting

### conn.log not updating

```bash
sudo zeekctl status          # check Zeek is running
sudo zeekctl check           # validate configuration
sudo journalctl -u zeek -n 50
```

### flow-to-features.py: "Cannot reach API"

```bash
curl http://localhost:8080/health   # should return {"status":"ok",...}
```

### scored-to-elastic.py: bulk index errors

```bash
# Check ES cluster health
curl http://localhost:9200/_cluster/health?pretty
# Check recent indexing errors
curl http://localhost:9200/_cat/indices/ml-scores-*?v
```

### Log is in TSV format (not JSON)

`policy/tuning/json-logs` must be loaded in `local.zeek`.  
Verify and restart:
```bash
grep json-logs /opt/zeek/share/zeek/site/local.zeek
sudo zeekctl restart
```

### High API latency

The LSTM-AE sub-model runs inference per flow.  
For > 10 000 flows/second, deploy the API with `--workers 2` and a GPU node,  
or switch to the `/score/batch` endpoint in `flow-to-features.py`.

---

## Security Notes

- Zeek requires `CAP_NET_RAW` (or root) to capture packets.  
  On Linux: `sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek`
- `zeek-scored-flows.log` contains source/destination IPs and may be  
  privacy-sensitive. Restrict file permissions: `chmod 640`.
- Elasticsearch credentials: set `ES_USER` / `ES_PASSWORD` via environment  
  variables, never on the command line. See `api/kubernetes/configmap.yaml`  
  for the Kubernetes secret pattern.
- Never commit Elasticsearch passwords — use `kubectl create secret`.
