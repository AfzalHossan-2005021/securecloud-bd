"""Unit tests for IForest, LSTM-AE, and ensemble."""
import numpy as np
import pytest
import tempfile
from pathlib import Path

from ml.models import IForestDetector, LSTMAutoencoder, ThreatEnsemble, EnsembleConfig

N_SAMPLES = 200
N_FEATURES = 20
TIMESTEPS = 5

RNG = np.random.default_rng(0)


@pytest.fixture
def normal_data():
    return RNG.normal(0, 1, (N_SAMPLES, N_FEATURES)).astype(np.float32)


@pytest.fixture
def anomaly_data():
    return RNG.normal(10, 1, (20, N_FEATURES)).astype(np.float32)


class TestIForestDetector:
    def test_fit_score_shape(self, normal_data):
        det = IForestDetector(n_estimators=50, contamination=0.05)
        det.fit(normal_data)
        scores = det.score(normal_data)
        assert scores.shape == (N_SAMPLES,)

    def test_scores_in_range(self, normal_data):
        det = IForestDetector(n_estimators=50).fit(normal_data)
        scores = det.score(normal_data)
        assert scores.min() >= 0.0 and scores.max() <= 1.0

    def test_anomalies_score_higher(self, normal_data, anomaly_data):
        det = IForestDetector(n_estimators=100, contamination=0.05).fit(normal_data)
        normal_mean = det.score(normal_data).mean()
        anomaly_mean = det.score(anomaly_data).mean()
        assert anomaly_mean > normal_mean

    def test_save_load_roundtrip(self, normal_data):
        det = IForestDetector(n_estimators=50).fit(normal_data)
        with tempfile.TemporaryDirectory() as tmp:
            det.save(Path(tmp) / "if")
            det2 = IForestDetector.load(Path(tmp) / "if")
        np.testing.assert_allclose(
            det.score(normal_data[:10]),
            det2.score(normal_data[:10]),
            rtol=1e-5,
        )


class TestLSTMAutoencoder:
    def test_fit_score_shape(self, normal_data):
        ae = LSTMAutoencoder(timesteps=TIMESTEPS, n_features=N_FEATURES)
        ae.fit(normal_data, epochs=2, verbose=0)
        scores = ae.score(normal_data)
        assert scores.shape == (N_SAMPLES,)

    def test_scores_in_range(self, normal_data):
        ae = LSTMAutoencoder(timesteps=TIMESTEPS, n_features=N_FEATURES)
        ae.fit(normal_data, epochs=2, verbose=0)
        scores = ae.score(normal_data)
        assert scores.min() >= 0.0 and scores.max() <= 1.0

    def test_save_load_roundtrip(self, normal_data):
        ae = LSTMAutoencoder(timesteps=TIMESTEPS, n_features=N_FEATURES)
        ae.fit(normal_data, epochs=2, verbose=0)
        with tempfile.TemporaryDirectory() as tmp:
            ae.save(Path(tmp) / "ae")
            ae2 = LSTMAutoencoder.load(Path(tmp) / "ae")
        s1 = ae.score(normal_data)
        s2 = ae2.score(normal_data)
        np.testing.assert_allclose(s1, s2, rtol=1e-4)


class TestThreatEnsemble:
    def test_weights_validation(self):
        with pytest.raises(ValueError):
            EnsembleConfig(iforest_weight=0.3, autoencoder_weight=0.3)

    def test_fused_score_range(self, normal_data):
        det = IForestDetector(n_estimators=50).fit(normal_data)
        ae = LSTMAutoencoder(timesteps=TIMESTEPS, n_features=N_FEATURES)
        ae.fit(normal_data, epochs=2, verbose=0)
        ens = ThreatEnsemble().attach(det, ae)
        scores = ens.score(normal_data)
        assert scores.min() >= 0.0 and scores.max() <= 1.0
