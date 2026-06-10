"""Load saved ensemble and score a feature batch (used by the API)."""
from __future__ import annotations

import numpy as np
from pathlib import Path
from functools import lru_cache

from ml.models import ThreatEnsemble, EnsembleConfig


@lru_cache(maxsize=1)
def get_ensemble(
    model_dir: str,
    iforest_weight: float = 0.4,
    ae_weight: float = 0.6,
    threshold: float = 0.5,
) -> ThreatEnsemble:
    config = EnsembleConfig(
        iforest_weight=iforest_weight,
        autoencoder_weight=ae_weight,
        threshold=threshold,
    )
    return ThreatEnsemble.load(model_dir, config=config)


def score_batch(
    features: np.ndarray,
    model_dir: str,
    iforest_weight: float = 0.4,
    ae_weight: float = 0.6,
    threshold: float = 0.5,
) -> dict:
    ensemble = get_ensemble(
        model_dir,
        iforest_weight=iforest_weight,
        ae_weight=ae_weight,
        threshold=threshold,
    )
    scores = ensemble.score(features)
    labels = ensemble.predict(features)
    return {
        "scores": scores.tolist(),
        "labels": labels.tolist(),
        "anomaly_count": int(labels.sum()),
        "anomaly_rate": float(labels.mean()),
    }
