"""LSTM Autoencoder for sequential network-flow anomaly detection."""
from __future__ import annotations

import numpy as np
from pathlib import Path
from sklearn.preprocessing import MinMaxScaler
import joblib

import tensorflow as tf
from tensorflow import keras
from keras import layers, Model


def build_lstm_autoencoder(
    timesteps: int,
    n_features: int,
    latent_dim: int = 32,
    dropout: float = 0.1,
) -> Model:
    """Build a seq2seq LSTM autoencoder.

    Input shape: (batch, timesteps, n_features)
    """
    inputs = keras.Input(shape=(timesteps, n_features), name="input")

    # Encoder
    x = layers.LSTM(64, return_sequences=True, name="enc_lstm1")(inputs)
    x = layers.Dropout(dropout)(x)
    encoded = layers.LSTM(latent_dim, return_sequences=False, name="enc_lstm2")(x)

    # Repeat vector bridges encoder → decoder
    x = layers.RepeatVector(timesteps, name="repeat")(encoded)

    # Decoder
    x = layers.LSTM(latent_dim, return_sequences=True, name="dec_lstm1")(x)
    x = layers.Dropout(dropout)(x)
    x = layers.LSTM(64, return_sequences=True, name="dec_lstm2")(x)
    outputs = layers.TimeDistributed(layers.Dense(n_features), name="output")(x)

    model = Model(inputs, outputs, name="lstm_autoencoder")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="mse",
    )
    return model


class LSTMAutoencoder:
    """Trains, scores, saves, and loads the LSTM autoencoder."""

    def __init__(
        self,
        timesteps: int = 10,
        n_features: int = 20,
        latent_dim: int = 32,
        dropout: float = 0.1,
        threshold_percentile: float = 95.0,
    ) -> None:
        self.timesteps = timesteps
        self.n_features = n_features
        self.threshold_percentile = threshold_percentile
        self.scaler = MinMaxScaler()
        self.model = build_lstm_autoencoder(timesteps, n_features, latent_dim, dropout)
        self._threshold: float | None = None
        self._fitted = False

    # ------------------------------------------------------------------
    # Data helpers
    # ------------------------------------------------------------------
    def _make_sequences(self, X: np.ndarray) -> np.ndarray:
        """Slide a window of length `timesteps` over rows of X."""
        n = len(X) - self.timesteps + 1
        if n <= 0:
            raise ValueError(
                f"Need at least {self.timesteps} rows; got {len(X)}"
            )
        return np.stack([X[i : i + self.timesteps] for i in range(n)])

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(
        self,
        X: np.ndarray,
        epochs: int = 50,
        batch_size: int = 64,
        validation_split: float = 0.1,
        verbose: int = 0,
    ) -> "LSTMAutoencoder":
        Xs = self.scaler.fit_transform(X)
        seqs = self._make_sequences(Xs)

        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor="val_loss", patience=5, restore_best_weights=True
            )
        ]
        self.model.fit(
            seqs,
            seqs,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=callbacks,
            verbose=verbose,
        )

        # Set threshold from training reconstruction errors
        recon_errors = self._reconstruction_errors(seqs)
        self._threshold = float(
            np.percentile(recon_errors, self.threshold_percentile)
        )
        self._fitted = True
        return self

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def _reconstruction_errors(self, seqs: np.ndarray) -> np.ndarray:
        preds = self.model.predict(seqs, verbose=0)
        return np.mean(np.power(seqs - preds, 2), axis=(1, 2))

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores in [0, 1] for each row of X.

        Rows in the first (timesteps-1) positions inherit the score of the
        first full window.
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before score()")
        Xs = self.scaler.transform(X)
        seqs = self._make_sequences(Xs)
        errors = self._reconstruction_errors(seqs)

        # Align errors back to original row indices (first window covers rows 0..t-1)
        padded = np.concatenate(
            [np.full(self.timesteps - 1, errors[0]), errors]
        )
        # Normalise by threshold so score ≥ 1 means anomalous
        norm = padded / (self._threshold + 1e-8)
        return np.clip(norm / (norm.max() + 1e-8), 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return 1 for anomaly, 0 for normal (uses fitted threshold)."""
        if self._threshold is None:
            raise RuntimeError("Model not fitted; no threshold available")
        Xs = self.scaler.transform(X)
        seqs = self._make_sequences(Xs)
        errors = self._reconstruction_errors(seqs)
        padded = np.concatenate(
            [np.full(self.timesteps - 1, errors[0]), errors]
        )
        return (padded > self._threshold).astype(int)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        self.model.save(path / "autoencoder.keras")
        joblib.dump(self.scaler, path / "ae_scaler.joblib")
        joblib.dump(
            {
                "timesteps": self.timesteps,
                "n_features": self.n_features,
                "threshold": self._threshold,
                "threshold_percentile": self.threshold_percentile,
            },
            path / "ae_meta.joblib",
        )

    @classmethod
    def load(cls, path: str | Path) -> "LSTMAutoencoder":
        path = Path(path)
        meta = joblib.load(path / "ae_meta.joblib")
        obj = cls.__new__(cls)
        obj.timesteps = meta["timesteps"]
        obj.n_features = meta["n_features"]
        obj.threshold_percentile = meta["threshold_percentile"]
        obj._threshold = meta["threshold"]
        obj.scaler = joblib.load(path / "ae_scaler.joblib")
        obj.model = keras.models.load_model(path / "autoencoder.keras")
        obj._fitted = True
        return obj
