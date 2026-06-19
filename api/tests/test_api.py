"""
Integration tests for the SecureCloud-BD Threat API.

All tests mock the model loader so no trained model artefacts are needed.
The test client runs the full ASGI stack (middleware, routing, validation)
against in-process mocked inference.

Run with:
    cd securecloud-bd
    pytest api/tests/test_api.py -v
"""
from __future__ import annotations

import math
from typing import Any
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

N_FEATURES = 20
TIMESTEPS  = 10

_VALID_FEATURES: list[float] = [
    1.5,   # duration
    500.0, # orig_bytes
    300.0, # resp_bytes
    5.0,   # orig_pkts
    4.0,   # resp_pkts
    600.0, # orig_ip_bytes
    400.0, # resp_ip_bytes
    0.0,   # missed_bytes
    1.0,   # proto_tcp
    0.0,   # proto_udp
    0.0,   # proto_icmp
    0.0,   # conn_state_S0
    1.0,   # conn_state_SF
    0.0,   # conn_state_REJ
    0.0,   # conn_state_RSTO
    1.0,   # service_http
    0.0,   # service_dns
    0.0,   # service_ssl
    100.0, # bytes_per_pkt_orig
    75.0,  # bytes_per_pkt_resp
]

assert len(_VALID_FEATURES) == N_FEATURES, "test fixture has wrong feature count"

_VALID_SEQUENCE: list[list[float]] = [_VALID_FEATURES] * TIMESTEPS

_EXPLAIN_STUB: dict[str, Any] = {
    "iforest_score"         : 0.3,
    "iforest_contribution"  : 0.12,
    "lstm_raw_error"        : 0.025,
    "lstm_score_normalized" : 0.25,
    "lstm_contribution"     : 0.15,
    "ensemble_score"        : 0.27,
    "iforest_weight"        : 0.4,
    "lstm_weight"           : 0.6,
    "lstm_threshold"        : 0.05,
    "is_anomaly"            : False,
    "decision"              : "NORMAL",
}

_ANOMALY_EXPLAIN_STUB: dict[str, Any] = {
    **_EXPLAIN_STUB,
    "iforest_score"         : 0.8,
    "iforest_contribution"  : 0.32,
    "lstm_raw_error"        : 0.12,
    "lstm_score_normalized" : 1.2,
    "lstm_contribution"     : 0.72,
    "ensemble_score"        : 1.04,
    "is_anomaly"            : True,
    "decision"              : "ANOMALY",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_mock_iforest(score: float = 0.3) -> MagicMock:
    m = MagicMock(name="IForestAnomalyDetector")
    m.predict_score.return_value = np.array([score], dtype=np.float32)
    return m


def _make_mock_lstm(
    error: float = 0.025,
    threshold: float = 0.05,
) -> MagicMock:
    m = MagicMock(name="LSTMAnomalyDetector")
    m.timesteps  = TIMESTEPS
    m.threshold_ = threshold
    # reconstruction_error returns one value per input row; pad with extras
    m.reconstruction_error.return_value = np.full(TIMESTEPS, error, dtype=np.float32)
    return m


def _make_mock_ensemble(
    if_score: float = 0.3,
    lstm_score: float = 0.25,
    anomaly: bool = False,
) -> MagicMock:
    ens_score = 0.4 * if_score + 0.6 * lstm_score
    explain   = _ANOMALY_EXPLAIN_STUB if anomaly else _EXPLAIN_STUB

    m = MagicMock(name="EnsembleDetector")
    m.iforest_weight = 0.4
    m.lstm_weight    = 0.6
    m.threshold      = 0.5
    m.predict_score.return_value  = np.array([ens_score], dtype=np.float32)
    m.predict_label.return_value  = np.array([int(anomaly)], dtype=int)
    m.explain_prediction.return_value = explain
    return m


@pytest.fixture(scope="module")
def client():
    """
    TestClient with all model-loader functions mocked out.

    Uses ``scope="module"`` so the FastAPI lifespan runs once per test module
    (faster) rather than once per test function.
    """
    mock_iforest  = _make_mock_iforest()
    mock_lstm     = _make_mock_lstm()
    mock_ensemble = _make_mock_ensemble()

    patches = [
        patch("api.models.loader.load_models"),
        patch("api.models.loader.is_loaded",          return_value=True),
        patch("api.models.loader.get_iforest",        return_value=mock_iforest),
        patch("api.models.loader.get_lstm",           return_value=mock_lstm),
        patch("api.models.loader.get_ensemble",       return_value=mock_ensemble),
        patch("api.models.loader.get_model_version",  return_value="test-v1"),
    ]

    with (
        patches[0],
        patches[1],
        patches[2],
        patches[3],
        patches[4],
        patches[5],
    ):
        from api.main import app
        with TestClient(app) as c:
            yield c


@pytest.fixture()
def unloaded_client():
    """TestClient where ``is_loaded()`` returns False — simulates startup."""
    patches = [
        patch("api.models.loader.load_models"),
        patch("api.models.loader.is_loaded", return_value=False),
        patch("api.models.loader.get_model_version", return_value="unloaded"),
    ]
    with patches[0], patches[1], patches[2]:
        from api.main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_status_ok(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_returns_model_version(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert data["model_version"] == "test-v1"

    def test_uptime_is_non_negative(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert data["uptime_seconds"] >= 0.0

    def test_both_flags_true_when_loaded(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert data["iforest_loaded"] is True
        assert data["lstm_loaded"]    is True

    def test_degraded_when_not_loaded(self, unloaded_client: TestClient) -> None:
        r = unloaded_client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "degraded"

    def test_x_request_id_header_echoed(self, client: TestClient) -> None:
        r = client.get("/health", headers={"X-Request-ID": "my-id-42"})
        assert r.headers.get("x-request-id") == "my-id-42"

    def test_x_request_id_generated_when_absent(self, client: TestClient) -> None:
        r = client.get("/health")
        rid = r.headers.get("x-request-id", "")
        assert len(rid) == 36   # UUID4 string length


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_returns_200(self, client: TestClient) -> None:
        r = client.get("/metrics")
        assert r.status_code == 200

    def test_content_type_is_text(self, client: TestClient) -> None:
        r = client.get("/metrics")
        assert r.headers["content-type"].startswith("text/plain")

    def test_contains_request_counter(self, client: TestClient) -> None:
        # Issue a /health request to populate the counter before checking
        client.get("/health")
        body = client.get("/metrics").text
        assert "securecloud_requests_total" in body

    def test_contains_duration_histogram(self, client: TestClient) -> None:
        body = client.get("/metrics").text
        assert "securecloud_request_duration_seconds" in body


# ---------------------------------------------------------------------------
# GET /threshold
# ---------------------------------------------------------------------------

class TestThreshold:
    def test_returns_expected_fields(self, client: TestClient) -> None:
        r = client.get("/threshold")
        assert r.status_code == 200
        data = r.json()
        assert "iforest_threshold"  in data
        assert "lstm_threshold"     in data
        assert "ensemble_threshold" in data
        assert "iforest_weight"     in data
        assert "lstm_weight"        in data

    def test_iforest_threshold_is_half(self, client: TestClient) -> None:
        data = client.get("/threshold").json()
        assert data["iforest_threshold"] == pytest.approx(0.5)

    def test_weights_sum_to_one(self, client: TestClient) -> None:
        data = client.get("/threshold").json()
        assert data["iforest_weight"] + data["lstm_weight"] == pytest.approx(1.0)

    def test_503_when_models_not_loaded(self, unloaded_client: TestClient) -> None:
        r = unloaded_client.get("/threshold")
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# POST /score — happy path
# ---------------------------------------------------------------------------

class TestScore:
    def test_valid_request_returns_200(self, client: TestClient) -> None:
        r = client.post("/score", json={"features": _VALID_FEATURES})
        assert r.status_code == 200

    def test_response_has_all_fields(self, client: TestClient) -> None:
        data = client.post("/score", json={"features": _VALID_FEATURES}).json()
        assert "iforest_score"   in data
        assert "lstm_score"      in data
        assert "ensemble_score"  in data
        assert "is_anomaly"      in data
        assert "explanation"     in data

    def test_scores_are_bounded(self, client: TestClient) -> None:
        data = client.post("/score", json={"features": _VALID_FEATURES}).json()
        for key in ("iforest_score", "lstm_score", "ensemble_score"):
            assert 0.0 <= data[key] <= 1.0, f"{key} out of [0,1]"

    def test_with_explicit_sequence(self, client: TestClient) -> None:
        body = {"features": _VALID_FEATURES, "sequence": _VALID_SEQUENCE}
        r    = client.post("/score", json=body)
        assert r.status_code == 200

    def test_request_id_echoed_in_response(self, client: TestClient) -> None:
        r = client.post(
            "/score",
            json={"features": _VALID_FEATURES},
            headers={"X-Request-ID": "flow-123"},
        )
        assert r.json().get("request_id") == "flow-123"
        assert r.headers.get("x-request-id") == "flow-123"

    def test_explanation_contains_decision(self, client: TestClient) -> None:
        data = client.post("/score", json={"features": _VALID_FEATURES}).json()
        assert "decision" in data["explanation"]
        assert data["explanation"]["decision"] in ("NORMAL", "ANOMALY")

    def test_503_when_models_not_loaded(self, unloaded_client: TestClient) -> None:
        r = unloaded_client.post("/score", json={"features": _VALID_FEATURES})
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# POST /score — validation errors
# ---------------------------------------------------------------------------

class TestScoreValidation:
    def test_too_few_features_rejected(self, client: TestClient) -> None:
        r = client.post("/score", json={"features": _VALID_FEATURES[:10]})
        assert r.status_code == 422

    def test_too_many_features_rejected(self, client: TestClient) -> None:
        r = client.post("/score", json={"features": _VALID_FEATURES + [0.0]})
        assert r.status_code == 422

    def test_nan_in_features_rejected(self, client: TestClient) -> None:
        bad = list(_VALID_FEATURES)
        bad[0] = float("nan")
        r = client.post("/score", json={"features": bad})
        assert r.status_code == 422

    def test_inf_in_features_rejected(self, client: TestClient) -> None:
        bad = list(_VALID_FEATURES)
        bad[1] = float("inf")
        r = client.post("/score", json={"features": bad})
        assert r.status_code == 422

    def test_missing_features_field_rejected(self, client: TestClient) -> None:
        r = client.post("/score", json={"sequence": _VALID_SEQUENCE})
        assert r.status_code == 422

    def test_empty_sequence_rejected(self, client: TestClient) -> None:
        body = {"features": _VALID_FEATURES, "sequence": []}
        r = client.post("/score", json=body)
        assert r.status_code == 422

    def test_nan_in_sequence_row_rejected(self, client: TestClient) -> None:
        bad_seq = [list(_VALID_FEATURES)] * TIMESTEPS
        bad_seq[3][2] = float("nan")
        body = {"features": _VALID_FEATURES, "sequence": bad_seq}
        r = client.post("/score", json=body)
        assert r.status_code == 422

    def test_sequence_row_wrong_length_rejected(self, client: TestClient) -> None:
        bad_seq = [_VALID_FEATURES[:10]] * TIMESTEPS    # 10 features, not 20
        body = {"features": _VALID_FEATURES, "sequence": bad_seq}
        r = client.post("/score", json=body)
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /score/batch
# ---------------------------------------------------------------------------

class TestBatchScore:
    def _batch_body(self, n: int, **kwargs) -> dict:
        req = {"features": _VALID_FEATURES, **kwargs}
        return {"requests": [req] * n}

    def test_single_item_batch(self, client: TestClient) -> None:
        r = client.post("/score/batch", json=self._batch_body(1))
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert len(data["results"]) == 1

    def test_multi_item_batch(self, client: TestClient) -> None:
        n = 5
        r = client.post("/score/batch", json=self._batch_body(n))
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == n
        assert len(data["results"]) == n

    def test_anomaly_count_is_subset(self, client: TestClient) -> None:
        n    = 4
        data = client.post("/score/batch", json=self._batch_body(n)).json()
        assert 0 <= data["anomaly_count"] <= n

    def test_batch_latency_ms_positive(self, client: TestClient) -> None:
        data = client.post("/score/batch", json=self._batch_body(3)).json()
        assert data["batch_latency_ms"] > 0.0

    def test_empty_requests_rejected(self, client: TestClient) -> None:
        r = client.post("/score/batch", json={"requests": []})
        assert r.status_code == 422

    def test_with_sequences(self, client: TestClient) -> None:
        body = self._batch_body(2, sequence=_VALID_SEQUENCE)
        r    = client.post("/score/batch", json=body)
        assert r.status_code == 200
        assert r.json()["count"] == 2

    def test_503_when_models_not_loaded(self, unloaded_client: TestClient) -> None:
        r = unloaded_client.post("/score/batch", json=self._batch_body(1))
        assert r.status_code == 503

    def test_results_scores_bounded(self, client: TestClient) -> None:
        data = client.post("/score/batch", json=self._batch_body(3)).json()
        for row in data["results"]:
            for key in ("iforest_score", "lstm_score", "ensemble_score"):
                assert 0.0 <= row[key] <= 1.0, f"result[{key}] out of [0,1]"

    def test_chunking_large_batch(self, client: TestClient) -> None:
        """550 flows should work: two chunks (512 + 38) both processed."""
        n    = 550
        data = client.post("/score/batch", json=self._batch_body(n)).json()
        assert data["count"] == n

    def test_mixed_with_and_without_sequences(self, client: TestClient) -> None:
        body = {
            "requests": [
                {"features": _VALID_FEATURES, "sequence": _VALID_SEQUENCE},
                {"features": _VALID_FEATURES},
                {"features": _VALID_FEATURES, "sequence": _VALID_SEQUENCE},
            ]
        }
        data = client.post("/score/batch", json=body).json()
        assert data["count"] == 3


# ---------------------------------------------------------------------------
# Anomalous-flow fixture test
# ---------------------------------------------------------------------------

class TestAnomalyDetection:
    @pytest.fixture()
    def anomaly_client(self):
        """Client whose mock ensemble flags every flow as anomalous."""
        mock_if   = _make_mock_iforest(score=0.9)
        mock_lstm = _make_mock_lstm(error=0.12, threshold=0.05)
        mock_ens  = _make_mock_ensemble(if_score=0.9, lstm_score=1.0, anomaly=True)
        # Patch ensemble score to exceed threshold
        mock_ens.predict_score.return_value = np.array([0.94], dtype=np.float32)

        patches = [
            patch("api.models.loader.load_models"),
            patch("api.models.loader.is_loaded",         return_value=True),
            patch("api.models.loader.get_iforest",       return_value=mock_if),
            patch("api.models.loader.get_lstm",          return_value=mock_lstm),
            patch("api.models.loader.get_ensemble",      return_value=mock_ens),
            patch("api.models.loader.get_model_version", return_value="test-v1"),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            from api.main import app
            with TestClient(app) as c:
                yield c

    def test_anomalous_flow_flagged(self, anomaly_client: TestClient) -> None:
        data = anomaly_client.post(
            "/score", json={"features": _VALID_FEATURES}
        ).json()
        assert data["is_anomaly"] is True
        assert data["explanation"]["decision"] == "ANOMALY"

    def test_batch_anomaly_count_all_anomalous(
        self, anomaly_client: TestClient
    ) -> None:
        body = {"requests": [{"features": _VALID_FEATURES}] * 3}
        data = anomaly_client.post("/score/batch", json=body).json()
        assert data["anomaly_count"] == 3
