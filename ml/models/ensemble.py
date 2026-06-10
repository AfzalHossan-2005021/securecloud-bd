"""Weighted ensemble: IsolationForest × 0.4 + LSTM Autoencoder × 0.6."""
from __future__ import annotations

import numpy as np
from dataclasses import dataclass, field
from pathlib import Path

from .iforest_model import IForestDetector
from .autoencoder_model import LSTMAutoencoder


@dataclass
class EnsembleConfig:
    iforest_weight: float = 0.4
    autoencoder_weight: float = 0.6
    threshold: float = 0.5

    def __post_init__(self) -> None:
        total = self.iforest_weight + self.autoencoder_weight
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Weights must sum to 1.0, got {total}"
            )


class ThreatEnsemble:
    """Fuses IForest and LSTM-AE scores into a single threat score."""

    def __init__(self, config: EnsembleConfig | None = None) -> None:
        self.config = config or EnsembleConfig()
        self.iforest: IForestDetector | None = None
        self.autoencoder: LSTMAutoencoder | None = None

    def attach(
        self,
        iforest: IForestDetector,
        autoencoder: LSTMAutoencoder,
    ) -> "ThreatEnsemble":
        self.iforest = iforest
        self.autoencoder = autoencoder
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return fused anomaly score in [0, 1] for each row."""
        if self.iforest is None or self.autoencoder is None:
            raise RuntimeError("Attach models via .attach() before scoring")
        s_if = self.iforest.score(X)
        s_ae = self.autoencoder.score(X)
        # Both arrays must be same length; AE pads short sequences already
        min_len = min(len(s_if), len(s_ae))
        fused = (
            self.config.iforest_weight * s_if[:min_len]
            + self.config.autoencoder_weight * s_ae[:min_len]
        )
        return fused

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return 1 = anomaly, 0 = normal."""
        return (self.score(X) >= self.config.threshold).astype(int)

    def score_single(self, x: np.ndarray) -> float:
        """Score a single feature vector (1-D array). Returns float."""
        X = x.reshape(1, -1)
        scores = self.score(X)
        return float(scores[0])

    @classmethod
    def load(
        cls,
        model_dir: str | Path,
        config: EnsembleConfig | None = None,
    ) -> "ThreatEnsemble":
        model_dir = Path(model_dir)
        iforest = IForestDetector.load(model_dir / "iforest")
        autoencoder = LSTMAutoencoder.load(model_dir / "autoencoder")
        obj = cls(config=config)
        obj.attach(iforest, autoencoder)
        return obj
