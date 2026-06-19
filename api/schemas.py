"""
Pydantic v2 request/response schemas for the SecureCloud-BD Threat API.

All request schemas validate at the boundary; internal code can assume
values are finite, non-negative where marked, and the feature vector
is exactly ``N_FEATURES`` elements long.
"""
from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Annotated

# ---------------------------------------------------------------------------
# Feature contract
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]
N_FEATURES: int = len(FEATURE_NAMES)   # 20


# ---------------------------------------------------------------------------
# Reusable field types
# ---------------------------------------------------------------------------

FeatureVector = Annotated[
    list[float],
    Field(
        min_length=N_FEATURES,
        max_length=N_FEATURES,
        description=(
            f"Exactly {N_FEATURES} pre-scaled numeric features in the order: "
            + ", ".join(FEATURE_NAMES)
        ),
    ),
]

SequenceMatrix = Annotated[
    list[FeatureVector],
    Field(
        min_length=1,
        description=(
            "Historical context window for the LSTM-AE sub-model. "
            "Each inner list is one timestep's feature vector. "
            "If omitted, the API tiles `features` to create a minimal window."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Scoring — request
# ---------------------------------------------------------------------------

class ScoreRequest(BaseModel):
    """Single-flow scoring request."""

    features: FeatureVector
    sequence: SequenceMatrix | None = Field(
        default=None,
        description="Optional historical window (≥1 timesteps × 20 features). "
                    "Omit to let the API auto-generate a tiled window.",
    )

    @field_validator("features")
    @classmethod
    def features_must_be_finite(cls, v: list[float]) -> list[float]:
        if any(not math.isfinite(x) for x in v):
            raise ValueError("all feature values must be finite (no NaN / Inf)")
        return v

    @field_validator("sequence")
    @classmethod
    def sequence_rows_must_be_finite(
        cls, v: list[list[float]] | None
    ) -> list[list[float]] | None:
        if v is None:
            return v
        for row_idx, row in enumerate(v):
            if any(not math.isfinite(x) for x in row):
                raise ValueError(
                    f"sequence[{row_idx}] contains non-finite values"
                )
        return v


class BatchScoreRequest(BaseModel):
    """Batch scoring request — up to 10 000 flows per call."""

    requests: Annotated[
        list[ScoreRequest],
        Field(min_length=1, max_length=10_000),
    ]


# ---------------------------------------------------------------------------
# Scoring — response
# ---------------------------------------------------------------------------

class ScoreResponse(BaseModel):
    """Per-flow scoring result with per-model breakdown."""

    iforest_score: float = Field(
        ge=0.0, le=1.0,
        description="IForest anomaly score in [0, 1]; 1 = maximally anomalous.",
    )
    lstm_score: float = Field(
        ge=0.0, le=1.0,
        description="Normalised LSTM-AE score in [0, 1].",
    )
    ensemble_score: float = Field(
        ge=0.0, le=1.0,
        description="Weighted ensemble score: IForest×0.4 + LSTM-AE×0.6.",
    )
    is_anomaly: bool = Field(
        description="True when ensemble_score ≥ ensemble threshold.",
    )
    explanation: dict[str, Any] = Field(
        description="Score contribution breakdown from EnsembleDetector.explain_prediction().",
    )
    request_id: str | None = Field(
        default=None,
        description="Echo of the X-Request-ID header, if present.",
    )


class BatchScoreResponse(BaseModel):
    """Batch scoring result."""

    results: list[ScoreResponse]
    count: int = Field(description="Total flows scored in this batch.")
    anomaly_count: int = Field(description="Number of flows flagged as anomalies.")
    batch_latency_ms: float = Field(description="End-to-end server processing time in ms.")


# ---------------------------------------------------------------------------
# Ops endpoints
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Service liveness and model status."""

    status: str = Field(
        description='"ok" when models are loaded, "degraded" otherwise.',
    )
    model_version: str = Field(
        description="Version string read from models/version.txt, or 'dev'.",
    )
    uptime_seconds: float = Field(description="Seconds since server startup.")
    iforest_loaded: bool
    lstm_loaded: bool


class ThresholdResponse(BaseModel):
    """Current detection thresholds for all sub-models."""

    iforest_threshold: float = Field(
        description="IForest decision threshold (fixed at 0.5 of normalised score).",
    )
    lstm_threshold: float = Field(
        description="LSTM-AE reconstruction error threshold (mean+2σ from validation normals).",
    )
    ensemble_threshold: float = Field(
        description="Ensemble weighted-score decision threshold.",
    )
    iforest_weight: float = Field(description="IForest component weight in ensemble.")
    lstm_weight: float = Field(description="LSTM-AE component weight in ensemble.")
