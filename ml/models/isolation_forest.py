"""
Production-ready Isolation Forest anomaly detector for SecureCloud-BD.

This module provides ``IForestAnomalyDetector``, which supersedes the earlier
``IForestDetector`` in ``iforest_model.py`` in three ways:

1. **No internal scaler** — feature scaling is the responsibility of
   ``FeatureEngineeringPipeline``.  Applying StandardScaler inside the model
   after RobustScaler in the pipeline would silently double-scale inputs.

2. **Training-distribution normalisation** — ``predict_score()`` maps raw
   ``IsolationForest.score_samples()`` values to [0, 1] using the min/max
   observed on the *training set*, not per-batch min-max.  This means the
   same flow always receives the same anomaly score regardless of what other
   flows are evaluated alongside it — a hard requirement for threshold-based
   alerting in the SIEM.

3. **Supervised evaluation** — ``evaluate()`` computes accuracy, precision,
   recall, F1, ROC-AUC, and a confusion matrix against ground-truth binary
   labels.  Required for the grid-search experiment in
   ``ml/experiments/train_iforest.py``.

Relationship to iforest_model.py
---------------------------------
``IForestDetector`` is still used by ``ThreatEnsemble`` and the existing
``train.py`` script.  ``IForestAnomalyDetector`` is the standalone model used
for evaluation experiments and can be promoted to the ensemble in a future
refactor once ``ThreatEnsemble.attach()`` is updated.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TypedDict

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

log = logging.getLogger(__name__)


class EvalMetrics(TypedDict):
    """Return type of ``IForestAnomalyDetector.evaluate()``."""

    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: np.ndarray


class IForestAnomalyDetector:
    """
    Isolation Forest wrapper with stable [0, 1] anomaly scores and evaluation.

    The model is trained on **normal traffic only** (unsupervised setting).
    Anomaly scores are normalised using the score distribution observed on the
    training set so that a given flow always receives the same score regardless
    of batch composition.

    Parameters
    ----------
    n_estimators : int
        Number of base estimators (trees) in the forest.  Higher values give
        more stable scores at the cost of memory and training time.
        Default: 200.
    contamination : float
        Expected fraction of anomalies in the *training* data.  UNSW-NB15
        training splits that are pre-filtered to label=0 should have
        contamination ≈ 0 (no anomalies), but a small value prevents sklearn
        from raising when fitting on what it sees as a 0-contamination dataset.
        Default: 0.10.
    random_state : int
        Seed for reproducibility.  Default: 42.

    Attributes set after ``fit()``
    --------------------------------
    model_ : sklearn.ensemble.IsolationForest
        Fitted forest.
    n_features_in_ : int
        Number of features seen during fit.
    train_time_s_ : float
        Wall-clock seconds consumed by ``fit()``.
    _score_min_ : float
        Minimum ``score_samples()`` value on the training set (most anomalous
        training point).  Used as the lower anchor for normalisation.
    _score_max_ : float
        Maximum ``score_samples()`` value on the training set (most normal
        training point).  Used as the upper anchor for normalisation.

    Examples
    --------
    >>> from ml.models.isolation_forest import IForestAnomalyDetector
    >>> detector = IForestAnomalyDetector(n_estimators=200, contamination=0.05)
    >>> detector.fit(X_train_normal)          # normal rows only
    >>> scores = detector.predict_score(X)    # shape (n,), dtype float32
    >>> labels = detector.predict_label(X)    # shape (n,), dtype int
    >>> metrics = detector.evaluate(X_test, y_test)
    >>> detector.save("ml/models/saved/iforest_best.joblib")
    """

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.10,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state

        # Fitted-state attributes — set by fit(), prefixed with underscore
        # to follow sklearn convention for mutable fitted state.
        self.model_: IsolationForest | None = None
        self._score_min_: float | None = None
        self._score_max_: float | None = None
        self.n_features_in_: int | None = None
        self.train_time_s_: float | None = None

    # ------------------------------------------------------------------
    # Fitting
    # ------------------------------------------------------------------

    def fit(self, X_train: np.ndarray) -> "IForestAnomalyDetector":
        """
        Train the Isolation Forest on *X_train*.

        The model should be trained on **normal traffic rows only**
        (``label == 0``).  Passing labelled attack rows biases the forest
        toward treating attacks as the norm and dramatically degrades recall.

        After fitting, ``_score_min_`` and ``_score_max_`` are computed from
        the training set and stored as normalisation anchors.

        Parameters
        ----------
        X_train : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix (output of ``FeatureEngineeringPipeline``).
            Must contain no NaN or infinite values.

        Returns
        -------
        self
            Fitted instance (allows method chaining).

        Raises
        ------
        ValueError
            If *X_train* is empty or contains NaN / infinite values.
        """
        X_train = np.asarray(X_train, dtype=np.float32)
        self._validate_array(X_train, "X_train")

        log.info(
            "IForestAnomalyDetector.fit — n_estimators=%d, contamination=%.3f,"
            " n_samples=%d, n_features=%d",
            self.n_estimators, self.contamination,
            X_train.shape[0], X_train.shape[1],
        )

        self.model_ = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1,
        )

        t0 = time.perf_counter()
        self.model_.fit(X_train)
        self.train_time_s_ = time.perf_counter() - t0

        # Anchor normalisation to training-set score distribution.
        # score_samples() returns higher values for normal points.
        train_scores = self.model_.score_samples(X_train)
        self._score_min_ = float(train_scores.min())
        self._score_max_ = float(train_scores.max())
        self.n_features_in_ = X_train.shape[1]

        log.info(
            "Training complete in %.2fs — score range on train: [%.4f, %.4f]",
            self.train_time_s_, self._score_min_, self._score_max_,
        )
        return self

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def predict_score(self, X: np.ndarray) -> np.ndarray:
        """
        Return a continuous anomaly score in [0, 1] for each row.

        A score of **1.0 means maximally anomalous**; 0.0 means normal.

        The mapping is:

        .. code-block:: text

            score = clip((score_max - raw) / (score_max - score_min), 0, 1)

        where ``score_max`` and ``score_min`` are the extremes of
        ``IsolationForest.score_samples()`` on the *training* set.
        Using training-set anchors (rather than per-batch min-max) ensures
        that a given flow always receives the same score regardless of what
        other flows it is evaluated alongside — a hard requirement for a SIEM
        alert threshold.

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix.

        Returns
        -------
        np.ndarray, shape (n_samples,), dtype float32
            Anomaly scores in [0, 1].

        Raises
        ------
        RuntimeError
            If called before ``fit()``.
        """
        self._check_fitted()
        X = np.asarray(X, dtype=np.float32)
        self._validate_array(X, "X")

        raw = self.model_.score_samples(X)  # higher = more normal

        denom = self._score_max_ - self._score_min_
        if denom < 1e-10:
            # Degenerate case: all training scores identical
            return np.zeros(len(raw), dtype=np.float32)

        # Flip the scale: high raw (normal) → low anomaly score
        scores = (self._score_max_ - raw) / denom
        return np.clip(scores, 0.0, 1.0).astype(np.float32)

    def predict_label(
        self,
        X: np.ndarray,
        threshold: float = 0.5,
    ) -> np.ndarray:
        """
        Return binary anomaly labels for each row.

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix.
        threshold : float
            Anomaly score threshold in (0, 1).  Rows with
            ``predict_score(X) >= threshold`` are labelled 1 (anomaly).
            Default: 0.5.

        Returns
        -------
        np.ndarray, shape (n_samples,), dtype int
            1 = anomaly, 0 = normal.
        """
        return (self.predict_score(X) >= threshold).astype(int)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        threshold: float = 0.5,
    ) -> EvalMetrics:
        """
        Compute classification metrics against ground-truth binary labels.

        This method evaluates the anomaly detector **as a binary classifier**
        using a fixed decision threshold.  It is intended for model selection
        (grid search) and final test-set reporting; it must not be used to
        tune the threshold (that would require a separate held-out set).

        Parameters
        ----------
        X_test : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix.
        y_test : np.ndarray, shape (n_samples,)
            Ground-truth binary labels (0 = normal, 1 = attack).
        threshold : float
            Score threshold for converting anomaly scores to binary labels.
            Default: 0.5.

        Returns
        -------
        EvalMetrics
            Dictionary with the following keys:

            ``accuracy``
                Fraction of correctly classified flows.
            ``precision``
                Precision on the positive (attack) class.
            ``recall``
                Recall on the positive (attack) class.
                In a security context this is the most important metric —
                a low recall means missed attacks.
            ``f1``
                Harmonic mean of precision and recall.
            ``roc_auc``
                Area under the ROC curve; independent of threshold choice.
            ``confusion_matrix``
                ``np.ndarray`` of shape (2, 2):
                ``[[TN, FP], [FN, TP]]``.
        """
        self._check_fitted()
        scores = self.predict_score(X_test)
        labels = (scores >= threshold).astype(int)
        y_test = np.asarray(y_test, dtype=int)

        try:
            roc_auc = float(roc_auc_score(y_test, scores))
        except ValueError:
            # Raised when only one class is present in y_test
            log.warning("roc_auc_score undefined — only one class present in y_test")
            roc_auc = float("nan")

        return EvalMetrics(
            accuracy=float(accuracy_score(y_test, labels)),
            precision=float(precision_score(y_test, labels, zero_division=0)),
            recall=float(recall_score(y_test, labels, zero_division=0)),
            f1=float(f1_score(y_test, labels, zero_division=0)),
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_test, labels),
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """
        Serialise the fitted detector to a single ``.joblib`` file.

        Parameters
        ----------
        path : str | Path
            Destination path.  If *path* has no ``.joblib`` suffix it is
            appended automatically.  Parent directories are created if they
            do not exist.

        Raises
        ------
        RuntimeError
            If called before ``fit()``.
        """
        self._check_fitted()
        path = Path(path)
        if path.suffix != ".joblib":
            path = path.with_suffix(".joblib")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        log.info("IForestAnomalyDetector saved → %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "IForestAnomalyDetector":
        """
        Deserialise a detector previously saved with ``save()``.

        Parameters
        ----------
        path : str | Path
            Path to the ``.joblib`` file.

        Returns
        -------
        IForestAnomalyDetector
            Fitted instance.

        Raises
        ------
        TypeError
            If the loaded object is not an ``IForestAnomalyDetector``.
        FileNotFoundError
            If *path* does not exist.
        """
        path = Path(path)
        if not path.exists() and not path.suffix:
            path = path.with_suffix(".joblib")
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(
                f"Expected {cls.__name__}, got {type(obj).__name__}"
            )
        log.info("IForestAnomalyDetector loaded from %s", path)
        return obj

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        fitted = self.model_ is not None
        return (
            f"IForestAnomalyDetector("
            f"n_estimators={self.n_estimators}, "
            f"contamination={self.contamination}, "
            f"random_state={self.random_state}, "
            f"fitted={fitted})"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_fitted(self) -> None:
        """
        Raise ``RuntimeError`` if the detector has not been fitted yet.

        Raises
        ------
        RuntimeError
            If ``fit()`` has not been called.
        """
        if self.model_ is None:
            raise RuntimeError(
                f"{self.__class__.__name__} is not fitted. "
                "Call fit(X_train) before predict_score() / evaluate() / save()."
            )

    @staticmethod
    def _validate_array(X: np.ndarray, name: str) -> None:
        """
        Assert that *X* is a non-empty 2-D array free of NaN and infinities.

        Parameters
        ----------
        X : np.ndarray
            Array to validate.
        name : str
            Variable name used in error messages.

        Raises
        ------
        ValueError
            If *X* is empty, not 2-D, or contains NaN / infinite values.
        """
        if X.ndim != 2:
            raise ValueError(f"{name} must be 2-D, got shape {X.shape}")
        if X.size == 0:
            raise ValueError(f"{name} must not be empty")
        if not np.isfinite(X).all():
            n_bad = (~np.isfinite(X)).sum()
            raise ValueError(
                f"{name} contains {n_bad} non-finite value(s) (NaN or Inf). "
                "Run FeatureEngineeringPipeline first."
            )
