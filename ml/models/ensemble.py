"""
Ensemble anomaly detectors for SecureCloud-BD.

Two ensemble classes are defined here:

``ThreatEnsemble``
    Original class; uses ``IForestDetector`` + ``LSTMAutoencoder`` (old API).
    Kept for backward compatibility with ``train.py`` and the FastAPI service.

``EnsembleDetector``
    Production class; uses ``IForestAnomalyDetector`` + ``LSTMAnomalyDetector``
    (new API with training-distribution score normalisation, principled
    threshold, and evaluation support).  This is the class used in
    ``ml/experiments/evaluate_ensemble.py``.

Ensemble weights: iForest × 0.4 + LSTM-AE × 0.6 (fixed by grid search;
see CLAUDE.md — do not change without re-running the search).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TypedDict

import numpy as np
from dataclasses import dataclass
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .iforest_model import IForestDetector
from .autoencoder_model import LSTMAutoencoder
from .isolation_forest import IForestAnomalyDetector
from .lstm_autoencoder import LSTMAnomalyDetector

log = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# EnsembleDetector — new API
# ---------------------------------------------------------------------------

class _EvalBreakdown(TypedDict):
    """Per-model metric slice inside EnsembleDetector.evaluate() output."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: np.ndarray


class EnsembleMetrics(TypedDict):
    """Return type of ``EnsembleDetector.evaluate()``."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: np.ndarray
    iforest: _EvalBreakdown
    lstm: _EvalBreakdown


class ExplainResult(TypedDict):
    """Return type of ``EnsembleDetector.explain_prediction()``."""
    iforest_score: float
    iforest_contribution: float
    lstm_raw_error: float
    lstm_score_normalized: float
    lstm_contribution: float
    ensemble_score: float
    iforest_weight: float
    lstm_weight: float
    lstm_threshold: float
    is_anomaly: bool
    decision: str


class EnsembleDetector:
    """
    Weighted ensemble of ``IForestAnomalyDetector`` and ``LSTMAnomalyDetector``.

    Fuses anomaly scores from both models using a fixed linear combination::

        ensemble_score = iforest_weight × if_score
                       + lstm_weight    × lstm_score_normalized

    where ``if_score ∈ [0, 1]`` comes from
    ``IForestAnomalyDetector.predict_score()`` (already normalised to the
    training distribution) and ``lstm_score_normalized ∈ [0, 1]`` is derived
    from the raw reconstruction error via::

        lstm_score_normalized = clip(error / (2 × threshold_), 0, 1)

    This mapping ensures ``error = 0 → score = 0``,
    ``error = threshold → score = 0.5``, and
    ``error ≥ 2 × threshold → score = 1``.
    It is interpretable and free of additional hyperparameters.

    Parameters
    ----------
    iforest_model : IForestAnomalyDetector
        A *fitted* isolation forest detector.
    lstm_model : LSTMAnomalyDetector
        A *fitted* LSTM autoencoder with ``threshold_`` set via
        ``set_threshold()``.
    iforest_weight : float
        Weight for the IForest score component.  Must satisfy
        ``iforest_weight + lstm_weight == 1.0``.  Default: 0.4.
    lstm_weight : float
        Weight for the LSTM-AE score component.  Default: 0.6.
    threshold : float
        Ensemble-level decision threshold.  Rows with
        ``ensemble_score >= threshold`` are labelled as anomalies.
        Default: 0.5.

    Raises
    ------
    ValueError
        If weights do not sum to 1.0, or if either sub-model is not fitted.

    Examples
    --------
    >>> ens = EnsembleDetector(iforest, lstm_ae)
    >>> scores = ens.predict_score(X_test, X_test)
    >>> labels = ens.predict_label(X_test, X_test)
    >>> metrics = ens.evaluate(X_test, X_test, y_test)
    >>> ens.save("ml/models/saved/ensemble")
    """

    _CONFIG_FILE = "ensemble_config.json"
    _IFOREST_SUBDIR = "iforest"
    _LSTM_SUBDIR = "lstm_ae"

    def __init__(
        self,
        iforest_model: IForestAnomalyDetector,
        lstm_model: LSTMAnomalyDetector,
        iforest_weight: float = 0.4,
        lstm_weight: float = 0.6,
        threshold: float = 0.5,
    ) -> None:
        if abs(iforest_weight + lstm_weight - 1.0) > 1e-6:
            raise ValueError(
                f"iforest_weight + lstm_weight must equal 1.0, "
                f"got {iforest_weight + lstm_weight}"
            )
        if iforest_model.model_ is None:
            raise ValueError("iforest_model is not fitted — call fit() first.")
        if lstm_model.threshold_ is None:
            raise ValueError(
                "lstm_model has no threshold — call set_threshold() after fit()."
            )

        self.iforest_model = iforest_model
        self.lstm_model = lstm_model
        self.iforest_weight = iforest_weight
        self.lstm_weight = lstm_weight
        self.threshold = threshold

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lstm_normalize(self, errors: np.ndarray) -> np.ndarray:
        """
        Map raw LSTM-AE reconstruction errors to [0, 1].

        Uses ``clip(error / (2 × threshold_), 0, 1)`` so that:

        * ``error = 0``            → score = 0.0 (perfectly normal)
        * ``error = threshold_``   → score = 0.5 (at detection boundary)
        * ``error ≥ 2×threshold_`` → score = 1.0 (maximally anomalous)

        Parameters
        ----------
        errors : np.ndarray, shape (n,)
            Raw per-row reconstruction errors from
            ``LSTMAnomalyDetector.reconstruction_error()``.

        Returns
        -------
        np.ndarray, shape (n,), dtype float32
        """
        denom = 2.0 * self.lstm_model.threshold_
        if denom < 1e-12:
            return np.zeros_like(errors, dtype=np.float32)
        return np.clip(errors / denom, 0.0, 1.0).astype(np.float32)

    def _fused_scores(
        self,
        X_tabular: np.ndarray,
        X_sequences: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute IForest scores, normalised LSTM-AE scores, and fused scores.

        Parameters
        ----------
        X_tabular : np.ndarray, shape (n, n_features)
            Feature matrix passed to IForestAnomalyDetector.
        X_sequences : np.ndarray, shape (n, n_features)
            Feature matrix passed to LSTMAnomalyDetector (windowed internally).

        Returns
        -------
        if_scores : np.ndarray, shape (n,), float32
        lstm_scores : np.ndarray, shape (n,), float32  (normalised)
        ensemble_scores : np.ndarray, shape (n,), float32
        """
        if_scores   = self.iforest_model.predict_score(X_tabular)
        ae_errors   = self.lstm_model.reconstruction_error(X_sequences)
        lstm_scores = self._lstm_normalize(ae_errors)
        ensemble    = (
            self.iforest_weight * if_scores
            + self.lstm_weight  * lstm_scores
        ).astype(np.float32)
        return if_scores, lstm_scores, ensemble

    # ------------------------------------------------------------------
    # Scoring and prediction
    # ------------------------------------------------------------------

    def predict_score(
        self,
        X_tabular: np.ndarray,
        X_sequences: np.ndarray,
    ) -> np.ndarray:
        """
        Return the weighted ensemble anomaly score for each row.

        Parameters
        ----------
        X_tabular : np.ndarray, shape (n, n_features)
            Pre-scaled feature matrix for the IForest sub-model.
        X_sequences : np.ndarray, shape (n, n_features)
            Pre-scaled feature matrix for the LSTM-AE sub-model.
            Typically the same array as *X_tabular*; named separately to
            make the data-flow explicit.

        Returns
        -------
        np.ndarray, shape (n,), dtype float32
            Ensemble anomaly scores in [0, 1].  1 = maximally anomalous.
        """
        _, _, ensemble = self._fused_scores(X_tabular, X_sequences)
        return ensemble

    def predict_label(
        self,
        X_tabular: np.ndarray,
        X_sequences: np.ndarray,
        threshold: float | None = None,
    ) -> np.ndarray:
        """
        Return binary anomaly labels.

        Parameters
        ----------
        X_tabular : np.ndarray, shape (n, n_features)
        X_sequences : np.ndarray, shape (n, n_features)
        threshold : float, optional
            Override the instance-level ``self.threshold``.  Default: None
            (uses ``self.threshold``).

        Returns
        -------
        np.ndarray, shape (n,), dtype int
            1 = anomaly, 0 = normal.
        """
        t = threshold if threshold is not None else self.threshold
        return (self.predict_score(X_tabular, X_sequences) >= t).astype(int)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _metrics_from_scores(
        scores: np.ndarray,
        labels: np.ndarray,
        y_true: np.ndarray,
    ) -> _EvalBreakdown:
        """
        Compute the standard metric set from pre-computed scores and labels.

        Parameters
        ----------
        scores : np.ndarray, shape (n,)
            Continuous anomaly scores (used for ROC-AUC).
        labels : np.ndarray, shape (n,)
            Binary predicted labels.
        y_true : np.ndarray, shape (n,)
            Ground-truth binary labels.

        Returns
        -------
        _EvalBreakdown
        """
        try:
            roc_auc = float(roc_auc_score(y_true, scores))
        except ValueError:
            log.warning("roc_auc_score undefined — only one class in y_true")
            roc_auc = float("nan")

        return _EvalBreakdown(
            accuracy=float(accuracy_score(y_true, labels)),
            precision=float(precision_score(y_true, labels, zero_division=0)),
            recall=float(recall_score(y_true, labels, zero_division=0)),
            f1=float(f1_score(y_true, labels, zero_division=0)),
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_true, labels),
        )

    def evaluate(
        self,
        X_tabular: np.ndarray,
        X_sequences: np.ndarray,
        y_test: np.ndarray,
    ) -> EnsembleMetrics:
        """
        Compute classification metrics for the ensemble **and** each sub-model.

        The ensemble is evaluated at ``self.threshold``.  Sub-models are
        evaluated at their own natural thresholds:

        * IForest: ``threshold = 0.5`` (the midpoint of its [0,1] score range)
        * LSTM-AE: ``lstm_model.threshold_`` (the mean+2σ value from
          ``set_threshold()``)

        Parameters
        ----------
        X_tabular : np.ndarray, shape (n, n_features)
        X_sequences : np.ndarray, shape (n, n_features)
        y_test : np.ndarray, shape (n,)
            Ground-truth binary labels (0 = normal, 1 = attack).

        Returns
        -------
        EnsembleMetrics
            Top-level keys ``accuracy``, ``precision``, ``recall``, ``f1``,
            ``roc_auc``, ``confusion_matrix`` are for the ensemble.
            Keys ``iforest`` and ``lstm`` each hold a ``_EvalBreakdown``
            dict with the same metric keys for the corresponding sub-model.
        """
        y_test = np.asarray(y_test, dtype=int)
        if_scores, lstm_scores, ens_scores = self._fused_scores(
            X_tabular, X_sequences
        )

        # ── Ensemble ──────────────────────────────────────────────────────────
        ens_labels = (ens_scores >= self.threshold).astype(int)
        ens_metrics = self._metrics_from_scores(ens_scores, ens_labels, y_test)

        # ── IForest sub-model (threshold = 0.5) ───────────────────────────────
        if_labels = (if_scores >= 0.5).astype(int)
        if_breakdown = self._metrics_from_scores(if_scores, if_labels, y_test)

        # ── LSTM-AE sub-model (natural threshold from set_threshold()) ────────
        ae_errors  = self.lstm_model.reconstruction_error(X_sequences)
        lstm_labels = (ae_errors >= self.lstm_model.threshold_).astype(int)
        lstm_breakdown = self._metrics_from_scores(lstm_scores, lstm_labels, y_test)

        return EnsembleMetrics(
            accuracy=ens_metrics["accuracy"],
            precision=ens_metrics["precision"],
            recall=ens_metrics["recall"],
            f1=ens_metrics["f1"],
            roc_auc=ens_metrics["roc_auc"],
            confusion_matrix=ens_metrics["confusion_matrix"],
            iforest=if_breakdown,
            lstm=lstm_breakdown,
        )

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def explain_prediction(
        self,
        X_single_tabular: np.ndarray,
        X_single_seq: np.ndarray,
    ) -> ExplainResult:
        """
        Return a score-contribution breakdown for a single network flow.

        Designed for real-time dashboard display: shows how much each model
        contributed to the final ensemble score and which component drove
        the alert (if any).

        Parameters
        ----------
        X_single_tabular : np.ndarray
            A single flow's feature vector, shape ``(1, n_features)`` or
            ``(n_features,)``.  Passed to the IForest sub-model.
        X_single_seq : np.ndarray
            A window of ``≥ timesteps`` consecutive flows ending at the flow
            of interest, shape ``(k, n_features)`` where
            ``k ≥ lstm_model.timesteps``.  The LSTM-AE uses the last window
            for reconstruction.  To explain a single isolated flow, repeat
            it ``timesteps`` times::

                X_single_seq = np.repeat(X_single_tabular, timesteps, axis=0)

        Returns
        -------
        ExplainResult
            Dictionary with the following keys:

            ``iforest_score``          – IForest anomaly score in [0, 1].
            ``iforest_contribution``   – ``iforest_weight × iforest_score``.
            ``lstm_raw_error``         – Raw reconstruction MSE.
            ``lstm_score_normalized``  – Normalised LSTM score in [0, 1].
            ``lstm_contribution``      – ``lstm_weight × lstm_score_normalized``.
            ``ensemble_score``         – Final weighted sum.
            ``iforest_weight``         – Weight of the IForest component.
            ``lstm_weight``            – Weight of the LSTM-AE component.
            ``lstm_threshold``         – The LSTM detection threshold (mean+2σ).
            ``is_anomaly``             – ``ensemble_score >= self.threshold``.
            ``decision``               – ``"ANOMALY"`` or ``"NORMAL"``.
        """
        xt = np.atleast_2d(X_single_tabular).astype(np.float32)
        xs = np.atleast_2d(X_single_seq).astype(np.float32)

        # IForest: score the single row
        if_score = float(self.iforest_model.predict_score(xt)[0])

        # LSTM-AE: get the last row's reconstruction error (xs may be a window)
        ae_errors = self.lstm_model.reconstruction_error(xs)
        lstm_raw  = float(ae_errors[-1])   # error for the last (most recent) row
        lstm_norm = float(self._lstm_normalize(np.array([lstm_raw]))[0])

        ensemble_score = self.iforest_weight * if_score + self.lstm_weight * lstm_norm
        is_anomaly = ensemble_score >= self.threshold

        return ExplainResult(
            iforest_score=round(if_score, 6),
            iforest_contribution=round(self.iforest_weight * if_score, 6),
            lstm_raw_error=round(lstm_raw, 8),
            lstm_score_normalized=round(lstm_norm, 6),
            lstm_contribution=round(self.lstm_weight * lstm_norm, 6),
            ensemble_score=round(ensemble_score, 6),
            iforest_weight=self.iforest_weight,
            lstm_weight=self.lstm_weight,
            lstm_threshold=round(self.lstm_model.threshold_, 8),
            is_anomaly=is_anomaly,
            decision="ANOMALY" if is_anomaly else "NORMAL",
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """
        Save the ensemble configuration and both sub-models to *path*.

        Directory layout::

            {path}/
            ├── ensemble_config.json   # weights, threshold, relative sub-model paths
            ├── iforest/               # IForestAnomalyDetector save directory
            │   └── model.joblib
            └── lstm_ae/               # LSTMAnomalyDetector save directory
                ├── lstm_ae.keras
                └── lstm_ae_meta.json

        The sub-model paths stored in ``ensemble_config.json`` are
        **relative to** *path*, so the ensemble directory is portable.

        Parameters
        ----------
        path : str | Path
            Destination directory.  Created if it does not exist.
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        iforest_rel = self._IFOREST_SUBDIR
        lstm_rel    = self._LSTM_SUBDIR

        self.iforest_model.save(path / iforest_rel / "model.joblib")
        self.lstm_model.save(path / lstm_rel)

        config = {
            "iforest_weight": self.iforest_weight,
            "lstm_weight"   : self.lstm_weight,
            "threshold"     : self.threshold,
            "iforest_path"  : f"{iforest_rel}/model.joblib",
            "lstm_path"     : lstm_rel,
        }
        cfg_path = path / self._CONFIG_FILE
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)

        log.info(
            "EnsembleDetector saved → %s  "
            "(if_w=%.1f, lstm_w=%.1f, threshold=%.2f)",
            path, self.iforest_weight, self.lstm_weight, self.threshold,
        )

    @classmethod
    def load(cls, path: str | Path) -> "EnsembleDetector":
        """
        Load an ensemble previously saved with ``save()``.

        Parameters
        ----------
        path : str | Path
            Directory containing ``ensemble_config.json``.

        Returns
        -------
        EnsembleDetector
            Fully initialised instance with both sub-models loaded.

        Raises
        ------
        FileNotFoundError
            If *path* or ``ensemble_config.json`` does not exist.
        """
        path = Path(path)
        cfg_path = path / cls._CONFIG_FILE
        if not cfg_path.exists():
            raise FileNotFoundError(
                f"ensemble_config.json not found in {path}. "
                "Has this directory been created by EnsembleDetector.save()?"
            )

        with open(cfg_path, encoding="utf-8") as fh:
            config = json.load(fh)

        iforest = IForestAnomalyDetector.load(path / config["iforest_path"])
        lstm    = LSTMAnomalyDetector.load(path / config["lstm_path"])

        log.info("EnsembleDetector loaded from %s", path)
        return cls(
            iforest_model=iforest,
            lstm_model=lstm,
            iforest_weight=config["iforest_weight"],
            lstm_weight=config["lstm_weight"],
            threshold=config["threshold"],
        )

    def __repr__(self) -> str:
        return (
            f"EnsembleDetector("
            f"iforest_w={self.iforest_weight}, "
            f"lstm_w={self.lstm_weight}, "
            f"threshold={self.threshold})"
        )
