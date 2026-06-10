"""Isolation Forest anomaly detector."""
from __future__ import annotations

import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class IForestDetector:
    """Wraps IsolationForest with a [0,1] anomaly score (higher = more anomalous)."""

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.05,
        max_samples: str | int = "auto",
        random_state: int = 42,
    ) -> None:
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, X: np.ndarray) -> "IForestDetector":
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores in [0, 1]; 1 = most anomalous."""
        if not self._fitted:
            raise RuntimeError("Call fit() before score()")
        Xs = self.scaler.transform(X)
        # decision_function returns negative scores (more negative = more anomalous)
        raw = self.model.decision_function(Xs)
        # Normalise to [0,1] via min-max across the batch
        lo, hi = raw.min(), raw.max()
        if hi == lo:
            return np.zeros(len(raw))
        normalised = (raw - hi) / (lo - hi)  # flip: low raw → high score
        return np.clip(normalised, 0.0, 1.0)

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Return 1 for anomaly, 0 for normal."""
        return (self.score(X) >= threshold).astype(int)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path / "iforest.joblib")
        joblib.dump(self.scaler, path / "iforest_scaler.joblib")

    @classmethod
    def load(cls, path: str | Path) -> "IForestDetector":
        path = Path(path)
        obj = cls.__new__(cls)
        obj.model = joblib.load(path / "iforest.joblib")
        obj.scaler = joblib.load(path / "iforest_scaler.joblib")
        obj._fitted = True
        return obj
