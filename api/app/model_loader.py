"""Singleton model loader; caches ensemble across requests."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)

# Allow running the API standalone without installing ml as a package
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.models import ThreatEnsemble, EnsembleConfig  # noqa: E402

_ensemble: ThreatEnsemble | None = None
_model_version = "unloaded"


def load_ensemble() -> None:
    global _ensemble, _model_version
    model_path = os.environ.get("MODEL_PATH", "/models")
    iforest_w = float(os.environ.get("IFOREST_WEIGHT", "0.4"))
    ae_w = float(os.environ.get("AE_WEIGHT", "0.6"))
    threshold = float(os.environ.get("SCORE_THRESHOLD", "0.5"))

    log.info("Loading ensemble from %s", model_path)
    config = EnsembleConfig(
        iforest_weight=iforest_w,
        autoencoder_weight=ae_w,
        threshold=threshold,
    )
    _ensemble = ThreatEnsemble.load(model_path, config=config)

    version_file = Path(model_path) / "version.txt"
    _model_version = version_file.read_text().strip() if version_file.exists() else "dev"
    log.info("Ensemble loaded (version=%s)", _model_version)


def get_ensemble() -> ThreatEnsemble:
    if _ensemble is None:
        raise RuntimeError("Models not loaded — call load_ensemble() at startup")
    return _ensemble


def get_model_version() -> str:
    return _model_version


def is_loaded() -> bool:
    return _ensemble is not None
