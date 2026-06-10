"""SecureCloud-BD threat-scoring API."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import numpy as np
from fastapi import FastAPI, HTTPException, status
from prometheus_fastapi_instrumentator import Instrumentator

from .model_loader import load_ensemble, get_ensemble, get_model_version, is_loaded
from .schemas import ScoreRequest, ScoreResponse, FlowScore, HealthResponse

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_ensemble()
    yield


app = FastAPI(
    title="SecureCloud-BD Threat API",
    version="0.1.0",
    description="Ensemble ML threat scoring (IsolationForest + LSTM Autoencoder)",
    lifespan=lifespan,
)

Instrumentator().instrument(app).expose(app)


@app.get("/health", response_model=HealthResponse, tags=["ops"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok" if is_loaded() else "degraded",
        model_loaded=is_loaded(),
        model_version=get_model_version(),
    )


@app.post("/score", response_model=ScoreResponse, tags=["inference"])
def score(request: ScoreRequest) -> ScoreResponse:
    if not is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Models not loaded",
        )
    X = np.array(
        [flow.to_array() for flow in request.flows],
        dtype=np.float32,
    )
    ensemble = get_ensemble()
    scores = ensemble.score(X)
    labels = ensemble.predict(X)

    results = [
        FlowScore(score=float(s), is_anomaly=bool(a))
        for s, a in zip(scores, labels)
    ]
    return ScoreResponse(
        results=results,
        anomaly_count=int(labels.sum()),
        anomaly_rate=float(labels.mean()),
        model_version=get_model_version(),
    )
