"""Integration tests for the FastAPI scoring endpoint using mock models."""
from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


@pytest.fixture
def client():
    """Return a TestClient with the model loader mocked out."""
    mock_ensemble = MagicMock()
    mock_ensemble.score.return_value = np.array([0.2, 0.8])
    mock_ensemble.predict.return_value = np.array([0, 1])

    with (
        patch("api.app.model_loader.load_ensemble"),
        patch("api.app.model_loader.get_ensemble", return_value=mock_ensemble),
        patch("api.app.model_loader.is_loaded", return_value=True),
        patch("api.app.model_loader.get_model_version", return_value="test-v0"),
    ):
        from api.app.main import app
        yield TestClient(app)


SAMPLE_FLOW = {
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
    "bytes_per_pkt_resp": 75,
}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True


def test_score_basic(client):
    payload = {"flows": [SAMPLE_FLOW, SAMPLE_FLOW]}
    r = client.post("/score", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert len(data["results"]) == 2
    assert data["anomaly_count"] == 1
    assert abs(data["anomaly_rate"] - 0.5) < 1e-6


def test_score_empty_flows_rejected(client):
    r = client.post("/score", json={"flows": []})
    assert r.status_code == 422


def test_negative_bytes_rejected(client):
    bad_flow = dict(SAMPLE_FLOW, orig_bytes=-1)
    r = client.post("/score", json={"flows": [bad_flow]})
    assert r.status_code == 422
