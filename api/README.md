# api/

FastAPI threat-scoring service — the real-time inference endpoint for SecureCloud-BD.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness / readiness — returns model version |
| `POST` | `/score` | Score a batch of network flows |
| `GET` | `/metrics` | Prometheus metrics (via `prometheus-fastapi-instrumentator`) |

### `POST /score` request body

```json
{
  "flows": [
    {
      "duration": 1.5,
      "orig_bytes": 500,
      "resp_bytes": 300,
      "orig_pkts": 5,
      "resp_pkts": 4,
      "orig_ip_bytes": 600,
      "resp_ip_bytes": 400,
      "missed_bytes": 0,
      "proto_tcp": 1,
      "bytes_per_pkt_orig": 100,
      "bytes_per_pkt_resp": 75
    }
  ]
}
```

All 20 feature fields are accepted; unspecified binary fields default to 0.

### `POST /score` response

```json
{
  "results": [{"score": 0.23, "is_anomaly": false}],
  "anomaly_count": 0,
  "anomaly_rate": 0.0,
  "model_version": "v1.0"
}
```

## Run locally (without Kubernetes)

```bash
pip install -r api/requirements.txt
pip install -r ml/requirements.txt

export MODEL_PATH=ml/models/saved
export IFOREST_WEIGHT=0.4
export AE_WEIGHT=0.6
export SCORE_THRESHOLD=0.5

uvicorn api.app.main:app --host 0.0.0.0 --port 8080 --reload
```

## Build Docker image

```bash
# Point Docker at Minikube's daemon so the image is available in-cluster
eval $(minikube docker-env)

docker build -f api/Dockerfile -t securecloud/threat-api:latest .
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PATH` | `/models` | Directory containing `iforest/` and `autoencoder/` |
| `IFOREST_WEIGHT` | `0.4` | IsolationForest ensemble weight |
| `AE_WEIGHT` | `0.6` | LSTM AE ensemble weight |
| `SCORE_THRESHOLD` | `0.5` | Binary classification threshold |
| `LOG_LEVEL` | `INFO` | Python logging level |

## Tests

```bash
pytest api/tests/ -v
```

Tests use mock models; no GPU or saved model files required.

## File layout

```
api/
├── app/
│   ├── main.py         FastAPI app, lifespan loader, route handlers
│   ├── schemas.py      Pydantic v2 request/response models
│   └── model_loader.py Singleton ensemble loader (cached after startup)
├── tests/
│   └── test_api.py
├── Dockerfile
└── requirements.txt
```
