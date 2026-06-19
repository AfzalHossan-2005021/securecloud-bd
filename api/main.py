"""
SecureCloud-BD Threat Scoring API — FastAPI application entry point.

Endpoints
---------
POST /score
    Score a single network flow; returns per-model breakdown + explanation.
POST /score/batch
    Score up to 10 000 flows.  Internally processed in chunks of 512 for
    bounded memory use.
GET /health
    Liveness probe; returns model load status and uptime.
GET /metrics
    Prometheus-format metrics page (text/plain).
GET /threshold
    Current detection thresholds for all sub-models.

Run locally
-----------
    uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

import numpy as np
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from .metrics import (
    get_metrics_text,
    record_request,
    record_scores,
    request_duration_ctx,
)
from .middleware import RequestIDMiddleware, StructuredLoggingMiddleware
from .models.loader import (
    get_ensemble,
    get_iforest,
    get_lstm,
    get_model_version,
    is_loaded,
    load_models,
)
from .schemas import (
    BatchScoreRequest,
    BatchScoreResponse,
    HealthResponse,
    ScoreRequest,
    ScoreResponse,
    ThresholdResponse,
)

log = logging.getLogger(__name__)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    # StructuredLoggingMiddleware already formats access lines as JSON;
    # use a minimal format here so application logs stay readable.
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
)

_STARTUP_TIME: float = 0.0
_BATCH_CHUNK   = 512   # rows per IForest batch call


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _STARTUP_TIME
    load_models()
    _STARTUP_TIME = time.monotonic()
    yield


app = FastAPI(
    title="SecureCloud-BD Threat API",
    version="1.0.0",
    description=(
        "Ensemble anomaly detection for Kubernetes workloads.  "
        "IsolationForest × 0.4 + LSTM-Autoencoder × 0.6."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Middleware is applied in LIFO order by Starlette — RequestID runs first,
# so the request_id is available when StructuredLogging emits its line.
app.add_middleware(StructuredLoggingMiddleware)
app.add_middleware(RequestIDMiddleware)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_models() -> None:
    """Raise 503 if the model singleton is not yet populated."""
    if not is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Models not loaded. The service is still starting up.",
        )


def _tile_sequence(feature_row: np.ndarray, timesteps: int) -> np.ndarray:
    """
    Construct a (timesteps, n_features) context window by tiling one row.

    Used when the caller does not supply a historical sequence.  Passing a
    constant window to the LSTM-AE measures how anomalous that *single* flow
    is when treated as a stationary signal — a conservative underestimate.
    """
    return np.tile(feature_row, (timesteps, 1))


def _score_one(
    X: np.ndarray,       # shape (1, N_FEATURES)
    X_seq: np.ndarray,   # shape (k, N_FEATURES), k ≥ timesteps
    request_id: str | None,
) -> ScoreResponse:
    """Compute all three model scores and explanation for a single flow."""
    ensemble = get_ensemble()
    iforest  = get_iforest()
    lstm     = get_lstm()

    timesteps = lstm.timesteps
    if X_seq.shape[0] < timesteps:
        X_seq = _tile_sequence(X[0], timesteps)

    if_score   = float(iforest.predict_score(X)[0])
    ae_error   = float(lstm.reconstruction_error(X_seq)[-1])
    lstm_score = float(np.clip(ae_error / (2.0 * lstm.threshold_), 0.0, 1.0))
    ens_score  = float(
        ensemble.iforest_weight * if_score
        + ensemble.lstm_weight  * lstm_score
    )
    is_anomaly = ens_score >= ensemble.threshold
    explanation = dict(ensemble.explain_prediction(X, X_seq))

    return ScoreResponse(
        iforest_score=round(if_score, 6),
        lstm_score=round(lstm_score, 6),
        ensemble_score=round(ens_score, 6),
        is_anomaly=is_anomaly,
        explanation=explanation,
        request_id=request_id,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/score",
    response_model=ScoreResponse,
    tags=["inference"],
    summary="Score a single network flow",
)
async def score(body: ScoreRequest, request: Request) -> ScoreResponse:
    """
    Score one pre-scaled network flow and return a detailed per-model breakdown.

    **`features`** must be exactly 20 floats in the order defined by
    `FEATURE_NAMES` in `api/schemas.py`.

    **`sequence`** (optional) — a list of prior timestep feature vectors for
    the LSTM-AE sub-model.  If omitted, the current flow is tiled to fill the
    LSTM context window, which gives a conservative reconstruction-error
    estimate for isolated flows.
    """
    _require_models()
    rid = getattr(request.state, "request_id", None)

    with request_duration_ctx("POST /score"):
        X = np.array([body.features], dtype=np.float32)
        if body.sequence is not None:
            X_seq = np.array(body.sequence, dtype=np.float32)
        else:
            X_seq = _tile_sequence(X[0], get_lstm().timesteps)

        result = _score_one(X, X_seq, rid)

    record_request("POST", "/score", 200)
    record_scores(1, int(result.is_anomaly))
    return result


@app.post(
    "/score/batch",
    response_model=BatchScoreResponse,
    tags=["inference"],
    summary="Score a batch of network flows",
)
async def score_batch(body: BatchScoreRequest, request: Request) -> BatchScoreResponse:
    """
    Score up to **10 000** flows in a single call.

    The IForest sub-model scores entire 512-row chunks in one vectorised call.
    The LSTM-AE sub-model is invoked per row because each flow may carry a
    distinct sequence context.  For throughput-sensitive workloads, prefer
    providing sequences so the LSTM-AE has correct temporal context.

    The `request_id` field in every result row is set to the same value as
    the batch request's `X-Request-ID` header.
    """
    _require_models()
    rid = getattr(request.state, "request_id", None)
    lstm      = get_lstm()
    iforest   = get_iforest()
    ensemble  = get_ensemble()
    timesteps = lstm.timesteps

    t0: float = time.perf_counter()
    results: list[ScoreResponse] = []
    reqs = body.requests

    with request_duration_ctx("POST /score/batch"):
        for chunk_start in range(0, len(reqs), _BATCH_CHUNK):
            chunk   = reqs[chunk_start : chunk_start + _BATCH_CHUNK]
            X_chunk = np.array([r.features for r in chunk], dtype=np.float32)

            # Batch IForest scores for the whole chunk — one vectorised call.
            if_scores_chunk = iforest.predict_score(X_chunk)

            for i, req in enumerate(chunk):
                if req.sequence is not None:
                    X_seq = np.array(req.sequence, dtype=np.float32)
                    if X_seq.shape[0] < timesteps:
                        X_seq = _tile_sequence(X_chunk[i], timesteps)
                else:
                    X_seq = _tile_sequence(X_chunk[i], timesteps)

                ae_error   = float(lstm.reconstruction_error(X_seq)[-1])
                lstm_score = float(
                    np.clip(ae_error / (2.0 * lstm.threshold_), 0.0, 1.0)
                )
                if_score  = float(if_scores_chunk[i])
                ens_score = float(
                    ensemble.iforest_weight * if_score
                    + ensemble.lstm_weight  * lstm_score
                )
                is_anomaly  = ens_score >= ensemble.threshold
                X_row       = X_chunk[i : i + 1]
                explanation = dict(ensemble.explain_prediction(X_row, X_seq))

                results.append(
                    ScoreResponse(
                        iforest_score=round(if_score, 6),
                        lstm_score=round(lstm_score, 6),
                        ensemble_score=round(ens_score, 6),
                        is_anomaly=is_anomaly,
                        explanation=explanation,
                        request_id=rid,
                    )
                )

    n_anomaly   = sum(1 for r in results if r.is_anomaly)
    elapsed_ms  = round((time.perf_counter() - t0) * 1000, 2)

    record_request("POST", "/score/batch", 200)
    record_scores(len(results), n_anomaly)

    return BatchScoreResponse(
        results=results,
        count=len(results),
        anomaly_count=n_anomaly,
        batch_latency_ms=elapsed_ms,
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["ops"],
    summary="Liveness probe — model load status and uptime",
)
async def health() -> HealthResponse:
    """
    Always returns HTTP 200 regardless of model state.

    Kubernetes liveness probes should target this endpoint.  Use the
    `status` field (`"ok"` vs `"degraded"`) for readiness gating in
    orchestration layers.
    """
    loaded = is_loaded()
    record_request("GET", "/health", 200)
    return HealthResponse(
        status="ok" if loaded else "degraded",
        model_version=get_model_version(),
        uptime_seconds=round(time.monotonic() - _STARTUP_TIME, 1),
        iforest_loaded=loaded,
        lstm_loaded=loaded,
    )


@app.get(
    "/metrics",
    response_class=PlainTextResponse,
    tags=["ops"],
    summary="Prometheus metrics page",
)
async def metrics_endpoint() -> str:
    """
    Exposes four metrics in Prometheus text exposition format:

    - ``securecloud_requests_total`` — request counter (method, endpoint, status)
    - ``securecloud_request_duration_seconds`` — latency histogram (endpoint)
    - ``securecloud_flows_scored_total`` — total flows scored
    - ``securecloud_anomalies_detected_total`` — total anomalies detected
    """
    record_request("GET", "/metrics", 200)
    return get_metrics_text()


@app.get(
    "/threshold",
    response_model=ThresholdResponse,
    tags=["ops"],
    summary="Current detection thresholds for all sub-models",
)
async def threshold_endpoint() -> ThresholdResponse:
    """
    Returns the live detection thresholds being used by the loaded models.

    The LSTM-AE threshold is set during training via ``set_threshold()``
    (mean + 2σ of reconstruction errors on normal validation flows) and is
    therefore dataset-specific.  The IForest threshold is fixed at 0.5 of
    the normalised score range.
    """
    _require_models()
    lstm     = get_lstm()
    ens      = get_ensemble()
    record_request("GET", "/threshold", 200)
    return ThresholdResponse(
        iforest_threshold=0.5,
        lstm_threshold=round(float(lstm.threshold_), 8),
        ensemble_threshold=float(ens.threshold),
        iforest_weight=ens.iforest_weight,
        lstm_weight=ens.lstm_weight,
    )
