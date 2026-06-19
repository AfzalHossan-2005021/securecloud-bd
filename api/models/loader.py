"""
Thread-safe singleton model loader for the SecureCloud-BD Threat API.

Models are loaded once at startup into module-level singletons.  A SIGUSR1
signal triggers a hot-reload in a daemon background thread so the serving
thread is never blocked.

Environment variables
---------------------
MODEL_DIR
    Root directory that contains model artefacts.  Default: ``/models``.
IFOREST_MODEL_PATH
    Absolute path to the IForest joblib file.
    Default: ``{MODEL_DIR}/iforest_best.joblib``.
LSTM_MODEL_PATH
    Absolute path to the LSTM-AE save directory.
    Default: ``{MODEL_DIR}/lstm_ae_best``.
IFOREST_WEIGHT
    IForest ensemble weight.  Must satisfy ``IFOREST_WEIGHT + LSTM_WEIGHT = 1``.
    Default: ``0.4``.
LSTM_WEIGHT
    LSTM-AE ensemble weight.  Default: ``0.6``.
ENSEMBLE_THRESHOLD
    Ensemble score decision threshold.  Default: ``0.5``.

SIGUSR1 reload
--------------
On POSIX systems only.  Send ``kill -USR1 <pid>`` to trigger a background
reload.  If the reload fails, the previous models continue serving.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Repo-root path injection so 'ml' is importable without pip-installing it
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.models.isolation_forest import IForestAnomalyDetector   # noqa: E402
from ml.models.lstm_autoencoder import LSTMAnomalyDetector       # noqa: E402
from ml.models.ensemble import EnsembleDetector                  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

_lock: threading.Lock = threading.Lock()

_iforest:  IForestAnomalyDetector | None = None
_lstm:     LSTMAnomalyDetector    | None = None
_ensemble: EnsembleDetector       | None = None
_model_version: str = "unloaded"


# ---------------------------------------------------------------------------
# Load / reload
# ---------------------------------------------------------------------------

def load_models(
    models_dir: str | Path | None = None,
    *,
    _is_reload: bool = False,
) -> None:
    """
    Load IForest + LSTM-AE + Ensemble into module-level singletons.

    Parameters
    ----------
    models_dir : path, optional
        Override ``MODEL_DIR`` env var.
    _is_reload : bool
        When ``True`` (SIGUSR1 path), a failed load is logged but silenced so
        the previous models continue serving.  When ``False`` (startup path),
        exceptions propagate immediately so the container fails fast.
    """
    global _iforest, _lstm, _ensemble, _model_version

    if models_dir is None:
        models_dir = Path(os.environ.get("MODEL_DIR", "/models"))
    models_dir = Path(models_dir)

    iforest_path = Path(
        os.environ.get("IFOREST_MODEL_PATH",
                       str(models_dir / "iforest_best.joblib"))
    )
    lstm_path = Path(
        os.environ.get("LSTM_MODEL_PATH", str(models_dir / "lstm_ae_best"))
    )
    iforest_weight = float(os.environ.get("IFOREST_WEIGHT", "0.4"))
    lstm_weight    = float(os.environ.get("LSTM_WEIGHT",    "0.6"))
    threshold      = float(os.environ.get("ENSEMBLE_THRESHOLD", "0.5"))

    log.info(
        "Loading models from %s  (iforest_w=%.1f lstm_w=%.1f threshold=%.2f)",
        models_dir, iforest_weight, lstm_weight, threshold,
    )

    try:
        new_iforest  = IForestAnomalyDetector.load(iforest_path)
        new_lstm     = LSTMAnomalyDetector.load(lstm_path)
        new_ensemble = EnsembleDetector(
            iforest_model=new_iforest,
            lstm_model=new_lstm,
            iforest_weight=iforest_weight,
            lstm_weight=lstm_weight,
            threshold=threshold,
        )

        version_file = models_dir / "version.txt"
        version = (
            version_file.read_text(encoding="utf-8").strip()
            if version_file.exists() else "dev"
        )

        with _lock:
            _iforest       = new_iforest
            _lstm          = new_lstm
            _ensemble      = new_ensemble
            _model_version = version

        log.info("Models ready (version=%s)", version)

    except Exception:
        if _is_reload:
            log.exception(
                "Model reload failed — previous models continue serving"
            )
            return
        raise


def _reload_handler(signum: int, frame: object) -> None:
    """SIGUSR1 handler: trigger a non-blocking background model reload."""
    log.info("SIGUSR1 received — scheduling model reload")
    threading.Thread(
        target=load_models,
        kwargs={"_is_reload": True},
        daemon=True,
        name="model-reload",
    ).start()


# Register SIGUSR1 on POSIX; silently skip on Windows.
if hasattr(signal, "SIGUSR1"):
    signal.signal(signal.SIGUSR1, _reload_handler)


# ---------------------------------------------------------------------------
# Accessors (called from endpoints)
# ---------------------------------------------------------------------------

def get_iforest() -> IForestAnomalyDetector:
    """Return the loaded IForest model, raising ``RuntimeError`` if absent."""
    with _lock:
        if _iforest is None:
            raise RuntimeError("IForest model not loaded — startup incomplete")
        return _iforest


def get_lstm() -> LSTMAnomalyDetector:
    """Return the loaded LSTM-AE model, raising ``RuntimeError`` if absent."""
    with _lock:
        if _lstm is None:
            raise RuntimeError("LSTM-AE model not loaded — startup incomplete")
        return _lstm


def get_ensemble() -> EnsembleDetector:
    """Return the loaded ensemble, raising ``RuntimeError`` if absent."""
    with _lock:
        if _ensemble is None:
            raise RuntimeError("Ensemble not loaded — startup incomplete")
        return _ensemble


def get_model_version() -> str:
    """Return the version string from ``models/version.txt``."""
    return _model_version


def is_loaded() -> bool:
    """Return ``True`` when all three models are ready to serve."""
    return _ensemble is not None
