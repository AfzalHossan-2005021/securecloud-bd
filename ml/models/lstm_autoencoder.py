"""
LSTM Autoencoder anomaly detector for SecureCloud-BD.

This module provides ``LSTMAnomalyDetector``, which supersedes the earlier
``LSTMAutoencoder`` in ``autoencoder_model.py`` in three ways:

1. **Deeper architecture** — 3-layer encoder (64→32→latent_dim) and 3-layer
   decoder (latent_dim→32→64→output), compared to the 2-layer variant in
   the original.  The additional layer captures more complex temporal patterns
   in slow-burn attacks (Reconnaissance, Backdoors) that unfold over many
   consecutive flows.

2. **No internal scaler** — feature scaling belongs to
   ``FeatureEngineeringPipeline``.  The original ``LSTMAutoencoder`` held a
   ``MinMaxScaler`` internally, which conflicted with ``RobustScaler`` in the
   preprocessing pipeline.

3. **Principled threshold** — ``set_threshold(X_val_normal)`` sets the
   decision boundary at ``mean(errors) + 2 × std(errors)`` computed on
   validation normal traffic.  Under a Gaussian reconstruction-error
   distribution this retains ~97.7 % of normal flows as non-anomalous.
   The original used a fixed percentile on training errors, which is biased
   by training noise and does not generalise as well.

Relationship to autoencoder_model.py
--------------------------------------
``LSTMAutoencoder`` is still referenced by ``ThreatEnsemble`` and
``train.py``.  ``LSTMAnomalyDetector`` is the standalone model used for
evaluation experiments and should replace ``LSTMAutoencoder`` in a future
refactor of ``ThreatEnsemble``.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TypedDict

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

import tensorflow as tf
from tensorflow import keras
from keras import layers

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared return type (mirrors EvalMetrics in isolation_forest.py)
# ---------------------------------------------------------------------------

class EvalMetrics(TypedDict):
    """Return type of ``LSTMAnomalyDetector.evaluate()``."""

    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: np.ndarray


# ---------------------------------------------------------------------------
# Model class
# ---------------------------------------------------------------------------

class LSTMAnomalyDetector:
    """
    Seq2seq LSTM Autoencoder for unsupervised network-flow anomaly detection.

    The model learns to reconstruct sequences of normal traffic flows.  At
    inference time, flows that deviate from learned normal behaviour incur
    high reconstruction error and are flagged as anomalies.

    Architecture
    ------------
    Input: ``(batch, timesteps, n_features)``

    Encoder::

        LSTM(4·latent_dim, return_sequences=True)
        Dropout(0.2)
        LSTM(2·latent_dim, return_sequences=True)
        LSTM(latent_dim,   return_sequences=False)   ← bottleneck

    Bridge::

        RepeatVector(timesteps)

    Decoder::

        LSTM(latent_dim,   return_sequences=True)
        LSTM(2·latent_dim, return_sequences=True)
        LSTM(4·latent_dim, return_sequences=True)
        TimeDistributed(Dense(n_features))           ← reconstruction

    With the default ``latent_dim=16`` this gives layer widths 64→32→16 in
    the encoder and 16→32→64 in the decoder, matching the sizes in the
    user specification exactly.

    Parameters
    ----------
    timesteps : int
        Sliding-window length.  Must be ≥ 2.  Default: 10.
    n_features : int
        Number of input features (width of the feature matrix produced by
        ``FeatureEngineeringPipeline``).  **Required** — no default.
    latent_dim : int
        Bottleneck dimensionality.  Encoder layer widths are
        ``4·latent_dim``, ``2·latent_dim``, ``latent_dim``; decoder mirrors
        this.  Smaller values compress more aggressively.  Default: 16.
    learning_rate : float
        Adam optimiser learning rate.  Default: 0.001.

    Attributes set after ``fit()``
    --------------------------------
    keras_model_ : keras.Model
        Compiled Keras model.  Available immediately after ``__init__``.
    history_ : dict
        Training history from ``keras_model_.fit()``; keys are
        ``"loss"`` and ``"val_loss"``.
    epochs_trained_ : int
        Actual number of training epochs (≤ *epochs* due to EarlyStopping).
    train_time_s_ : float
        Wall-clock training time in seconds.
    threshold_ : float | None
        Decision threshold; set by ``set_threshold()`` after ``fit()``.

    Examples
    --------
    >>> detector = LSTMAnomalyDetector(n_features=40)
    >>> detector.fit(X_train_normal, epochs=50, batch_size=256)
    >>> detector.set_threshold(X_val_normal)
    >>> labels = detector.predict_label(X_test)
    >>> metrics = detector.evaluate(X_test, y_test)
    >>> detector.save("ml/models/saved/lstm_ae_best")
    """

    def __init__(
        self,
        timesteps: int = 10,
        n_features: int = None,
        latent_dim: int = 16,
        learning_rate: float = 1e-3,
    ) -> None:
        if n_features is None:
            raise TypeError(
                "LSTMAnomalyDetector requires n_features. "
                "Pass the output width of FeatureEngineeringPipeline."
            )
        if timesteps < 2:
            raise ValueError(f"timesteps must be ≥ 2, got {timesteps}")

        self.timesteps = timesteps
        self.n_features = n_features
        self.latent_dim = latent_dim
        self.learning_rate = learning_rate

        # Fitted-state attributes
        self.history_: dict | None = None
        self.epochs_trained_: int | None = None
        self.train_time_s_: float | None = None
        self.threshold_: float | None = None

        self.keras_model_: keras.Model = self.build_model()

    # ------------------------------------------------------------------
    # Architecture
    # ------------------------------------------------------------------

    def build_model(self) -> keras.Model:
        """
        Construct and compile the LSTM autoencoder.

        Layer widths are derived from ``latent_dim``:

        * Encoder outer / decoder outer: ``4 × latent_dim``  (= 64 when latent_dim=16)
        * Encoder middle / decoder middle: ``2 × latent_dim`` (= 32 when latent_dim=16)
        * Bottleneck: ``latent_dim``                          (= 16 when latent_dim=16)

        Returns
        -------
        keras.Model
            Compiled model with MSE loss and Adam optimiser.
        """
        d1 = 4 * self.latent_dim   # outer  (64 at default latent_dim=16)
        d2 = 2 * self.latent_dim   # middle (32 at default latent_dim=16)
        d3 = self.latent_dim       # bottleneck

        inp = keras.Input(shape=(self.timesteps, self.n_features), name="input")

        # ── Encoder ───────────────────────────────────────────────────
        x = layers.LSTM(d1, return_sequences=True,  name="enc_lstm1")(inp)
        x = layers.Dropout(0.2,                     name="enc_drop")(x)
        x = layers.LSTM(d2, return_sequences=True,  name="enc_lstm2")(x)
        x = layers.LSTM(d3, return_sequences=False, name="enc_lstm3")(x)

        # ── Bridge ────────────────────────────────────────────────────
        x = layers.RepeatVector(self.timesteps, name="repeat")(x)

        # ── Decoder ───────────────────────────────────────────────────
        x = layers.LSTM(d3, return_sequences=True, name="dec_lstm1")(x)
        x = layers.LSTM(d2, return_sequences=True, name="dec_lstm2")(x)
        x = layers.LSTM(d1, return_sequences=True, name="dec_lstm3")(x)
        out = layers.TimeDistributed(
            layers.Dense(self.n_features), name="output"
        )(x)

        model = keras.Model(inp, out, name="lstm_anomaly_detector")
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss="mse",
        )
        log.debug(
            "Built LSTM-AE: timesteps=%d  n_features=%d  latent_dim=%d"
            "  layers=%d→%d→%d (encoder)",
            self.timesteps, self.n_features, self.latent_dim, d1, d2, d3,
        )
        return model

    # ------------------------------------------------------------------
    # Sequence preparation
    # ------------------------------------------------------------------

    def prepare_sequences(self, X: np.ndarray) -> np.ndarray:
        """
        Create overlapping sliding-window sequences from a flat feature matrix.

        Slides a window of length ``timesteps`` one row at a time, producing
        ``n - timesteps + 1`` non-overlapping windows where *n* is the number
        of input rows.

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, n_features)
            Flat (2-D) pre-scaled feature matrix.  Must have at least
            ``timesteps`` rows.

        Returns
        -------
        np.ndarray, shape (n_samples - timesteps + 1, timesteps, n_features)
            3-D tensor of overlapping windows.

        Raises
        ------
        ValueError
            If *X* has fewer than ``timesteps`` rows or is not 2-D.
        """
        X = np.asarray(X, dtype=np.float32)
        if X.ndim != 2:
            raise ValueError(
                f"prepare_sequences expects a 2-D array, got shape {X.shape}"
            )
        n = X.shape[0]
        if n < self.timesteps:
            raise ValueError(
                f"Need at least {self.timesteps} rows to form one sequence; "
                f"got {n}."
            )
        n_windows = n - self.timesteps + 1
        # stride_tricks avoids O(n*t) copy for large datasets
        shape   = (n_windows, self.timesteps, X.shape[1])
        strides = (X.strides[0], X.strides[0], X.strides[1])
        seqs = np.lib.stride_tricks.as_strided(X, shape=shape, strides=strides)
        return np.array(seqs, dtype=np.float32)   # make a contiguous copy

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(
        self,
        X_train_normal: np.ndarray,
        epochs: int = 50,
        batch_size: int = 256,
        validation_split: float = 0.1,
        verbose: int = 0,
    ) -> "LSTMAnomalyDetector":
        """
        Train the autoencoder on **normal traffic only**.

        The autoencoder learns to reconstruct normal flows; after training,
        anomalous flows produce higher reconstruction error than normal ones.
        ``set_threshold()`` must be called separately after ``fit()`` to set
        the detection boundary.

        Parameters
        ----------
        X_train_normal : np.ndarray, shape (n_normal, n_features)
            Pre-scaled normal-traffic feature rows (``label == 0``).
            Must contain no NaN or infinite values.
        epochs : int
            Maximum number of training epochs.  EarlyStopping will stop
            earlier if validation loss stops improving.  Default: 50.
        batch_size : int
            Mini-batch size.  256 works well on 8 GB RAM; reduce to 128 if
            OOM errors occur.  Default: 256.
        validation_split : float
            Fraction of training sequences held out for EarlyStopping
            monitoring (Keras internal split — not the labelled val set).
            Default: 0.1.
        verbose : int
            Keras verbosity level (0 = silent, 1 = progress bar,
            2 = one line per epoch).  Default: 0.

        Returns
        -------
        self
            Fitted instance (allows method chaining).

        Raises
        ------
        ValueError
            If *X_train_normal* is empty, not 2-D, or contains non-finite
            values, or if it has fewer than ``timesteps`` rows.
        """
        X_train_normal = np.asarray(X_train_normal, dtype=np.float32)
        self._validate_2d_finite(X_train_normal, "X_train_normal")

        seqs = self.prepare_sequences(X_train_normal)
        log.info(
            "LSTMAnomalyDetector.fit — latent_dim=%d  lr=%.5f"
            "  n_normal=%d  n_sequences=%d  n_features=%d",
            self.latent_dim, self.learning_rate,
            len(X_train_normal), len(seqs), self.n_features,
        )

        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=5,
                restore_best_weights=True,
                verbose=0,
            )
        ]

        t0 = time.perf_counter()
        history = self.keras_model_.fit(
            seqs,
            seqs,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=callbacks,
            verbose=verbose,
            shuffle=False,   # preserve temporal order within each epoch
        )
        self.train_time_s_ = time.perf_counter() - t0

        self.history_ = history.history
        self.epochs_trained_ = len(history.history["loss"])

        final_loss     = history.history["loss"][-1]
        final_val_loss = history.history.get("val_loss", [float("nan")])[-1]

        log.info(
            "Training complete in %.1fs — %d epochs"
            "  train_loss=%.6f  val_loss=%.6f",
            self.train_time_s_, self.epochs_trained_,
            final_loss, final_val_loss,
        )
        return self

    # ------------------------------------------------------------------
    # Reconstruction error
    # ------------------------------------------------------------------

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """
        Compute per-sample MSE reconstruction error.

        Internally slides the window over *X*, reconstructs each window with
        the autoencoder, and computes the mean squared error per window.
        The resulting per-window errors are aligned back to the original
        per-row shape: the first ``timesteps - 1`` rows are assigned the
        error of the first window (since they do not appear as the *last*
        step of any window).

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix.

        Returns
        -------
        np.ndarray, shape (n_samples,), dtype float32
            Per-row reconstruction error.  Higher values indicate greater
            deviation from the learned normal distribution.

        Raises
        ------
        RuntimeError
            If called before ``fit()``.
        ValueError
            If *X* has fewer than ``timesteps`` rows.
        """
        self._check_fitted()
        X = np.asarray(X, dtype=np.float32)
        self._validate_2d_finite(X, "X")

        seqs  = self.prepare_sequences(X)           # (n-t+1, t, f)
        preds = self.keras_model_.predict(seqs, verbose=0, batch_size=512)
        # MSE averaged over timestep and feature axes → one error per window
        errors = np.mean((seqs - preds) ** 2, axis=(1, 2)).astype(np.float32)

        # Align to original rows: first window covers rows 0 … t-1.
        # Rows 0 … t-2 have no window whose *last* step is that row, so they
        # inherit the first window's error.
        pad    = np.full(self.timesteps - 1, errors[0], dtype=np.float32)
        return np.concatenate([pad, errors])

    # ------------------------------------------------------------------
    # Threshold
    # ------------------------------------------------------------------

    def set_threshold(self, X_val_normal: np.ndarray) -> float:
        """
        Set the anomaly detection threshold from validation normal traffic.

        The threshold is ``mean(errors) + 2 × std(errors)`` computed on the
        reconstruction errors of *X_val_normal*.  Under a Gaussian error
        distribution this keeps ~97.7 % of normal flows below threshold
        (false-positive rate ≈ 2.3 %).  The threshold is stored as
        ``self.threshold_`` and used by ``predict_label()`` and
        ``evaluate()``.

        This method must be called **after** ``fit()`` and with
        **normal-traffic rows only** — passing attack rows would lower the
        threshold and degrade recall.

        Parameters
        ----------
        X_val_normal : np.ndarray, shape (n_val_normal, n_features)
            Pre-scaled normal-traffic rows from the validation split
            (``X_val[y_val == 0]``).

        Returns
        -------
        float
            The computed threshold value (also stored as ``self.threshold_``).

        Raises
        ------
        RuntimeError
            If called before ``fit()``.
        ValueError
            If *X_val_normal* has fewer than ``timesteps`` rows.
        """
        self._check_fitted()
        X_val_normal = np.asarray(X_val_normal, dtype=np.float32)
        self._validate_2d_finite(X_val_normal, "X_val_normal")

        errors = self.reconstruction_error(X_val_normal)
        self.threshold_ = float(errors.mean() + 2.0 * errors.std())

        log.info(
            "Threshold set — mean_err=%.6f  std_err=%.6f  threshold=%.6f"
            "  (mean + 2σ on %d validation normal rows)",
            float(errors.mean()), float(errors.std()),
            self.threshold_, len(X_val_normal),
        )
        return self.threshold_

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        """
        Return binary anomaly labels using the fitted threshold.

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix.

        Returns
        -------
        np.ndarray, shape (n_samples,), dtype int
            1 = anomaly (reconstruction error ≥ threshold), 0 = normal.

        Raises
        ------
        RuntimeError
            If ``set_threshold()`` has not been called yet.
        """
        if self.threshold_ is None:
            raise RuntimeError(
                "No threshold set. Call set_threshold(X_val_normal) "
                "after fit() before predict_label()."
            )
        return (self.reconstruction_error(X) >= self.threshold_).astype(int)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> EvalMetrics:
        """
        Compute classification metrics against ground-truth binary labels.

        Uses ``self.threshold_`` for binary label assignment and raw
        reconstruction errors as continuous scores for ROC-AUC.

        Parameters
        ----------
        X_test : np.ndarray, shape (n_samples, n_features)
            Pre-scaled feature matrix (normal + attack rows).
        y_test : np.ndarray, shape (n_samples,)
            Ground-truth binary labels (0 = normal, 1 = attack).

        Returns
        -------
        EvalMetrics
            Dictionary with keys ``accuracy``, ``precision``, ``recall``,
            ``f1``, ``roc_auc``, and ``confusion_matrix`` (ndarray, shape
            (2, 2), layout ``[[TN, FP], [FN, TP]]``).

        Raises
        ------
        RuntimeError
            If ``set_threshold()`` has not been called yet.
        """
        if self.threshold_ is None:
            raise RuntimeError(
                "No threshold set. Call set_threshold(X_val_normal) "
                "after fit() before evaluate()."
            )

        errors = self.reconstruction_error(X_test)   # higher = more anomalous
        labels = (errors >= self.threshold_).astype(int)
        y_test = np.asarray(y_test, dtype=int)

        try:
            roc_auc = float(roc_auc_score(y_test, errors))
        except ValueError:
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
        Save the Keras model and metadata to *path*.

        Two files are written inside *path* (which is treated as a directory):

        ``lstm_ae.keras``
            Full Keras SavedModel (architecture + weights + optimiser state).
        ``lstm_ae_meta.json``
            JSON with scalar metadata: ``timesteps``, ``n_features``,
            ``latent_dim``, ``learning_rate``, ``threshold`` (may be null),
            ``epochs_trained`` (may be null), ``train_time_s`` (may be null).

        Parameters
        ----------
        path : str | Path
            Destination directory.  Created if it does not exist.

        Raises
        ------
        RuntimeError
            If called before ``fit()``.
        """
        self._check_fitted()
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        model_path = path / "lstm_ae.keras"
        meta_path  = path / "lstm_ae_meta.json"

        self.keras_model_.save(model_path)

        meta = {
            "timesteps"    : self.timesteps,
            "n_features"   : self.n_features,
            "latent_dim"   : self.latent_dim,
            "learning_rate": self.learning_rate,
            "threshold"    : self.threshold_,
            "epochs_trained": self.epochs_trained_,
            "train_time_s" : self.train_time_s_,
        }
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

        log.info(
            "LSTMAnomalyDetector saved → %s  (threshold=%.6f)",
            path, self.threshold_ if self.threshold_ is not None else float("nan"),
        )

    @classmethod
    def load(cls, path: str | Path) -> "LSTMAnomalyDetector":
        """
        Load a detector previously saved with ``save()``.

        Parameters
        ----------
        path : str | Path
            Directory containing ``lstm_ae.keras`` and ``lstm_ae_meta.json``.

        Returns
        -------
        LSTMAnomalyDetector
            Fitted instance with threshold restored.

        Raises
        ------
        FileNotFoundError
            If *path* or either required file does not exist.
        """
        path = Path(path)
        model_path = path / "lstm_ae.keras"
        meta_path  = path / "lstm_ae_meta.json"

        for p in (model_path, meta_path):
            if not p.exists():
                raise FileNotFoundError(f"Expected file not found: {p}")

        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)

        # Bypass __init__ to avoid re-building the model architecture.
        obj = cls.__new__(cls)
        obj.timesteps      = meta["timesteps"]
        obj.n_features     = meta["n_features"]
        obj.latent_dim     = meta["latent_dim"]
        obj.learning_rate  = meta["learning_rate"]
        obj.threshold_     = meta.get("threshold")
        obj.epochs_trained_= meta.get("epochs_trained")
        obj.train_time_s_  = meta.get("train_time_s")
        obj.history_       = None

        obj.keras_model_ = keras.models.load_model(model_path)

        log.info(
            "LSTMAnomalyDetector loaded from %s  (threshold=%s)",
            path, obj.threshold_,
        )
        return obj

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        fitted    = self.epochs_trained_ is not None
        threshold = f"{self.threshold_:.6f}" if self.threshold_ is not None else "None"
        return (
            f"LSTMAnomalyDetector("
            f"timesteps={self.timesteps}, "
            f"n_features={self.n_features}, "
            f"latent_dim={self.latent_dim}, "
            f"lr={self.learning_rate}, "
            f"fitted={fitted}, "
            f"threshold={threshold})"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_fitted(self) -> None:
        """
        Raise ``RuntimeError`` if ``fit()`` has not been called.

        Raises
        ------
        RuntimeError
        """
        if self.epochs_trained_ is None:
            raise RuntimeError(
                f"{self.__class__.__name__} is not fitted. "
                "Call fit(X_train_normal) first."
            )

    @staticmethod
    def _validate_2d_finite(X: np.ndarray, name: str) -> None:
        """
        Assert *X* is a non-empty 2-D finite array.

        Parameters
        ----------
        X : np.ndarray
        name : str
            Variable name for error messages.

        Raises
        ------
        ValueError
        """
        if X.ndim != 2:
            raise ValueError(
                f"{name} must be 2-D, got shape {X.shape}"
            )
        if X.size == 0:
            raise ValueError(f"{name} must not be empty")
        if not np.isfinite(X).all():
            n_bad = (~np.isfinite(X)).sum()
            raise ValueError(
                f"{name} contains {n_bad} non-finite value(s). "
                "Run FeatureEngineeringPipeline first."
            )
