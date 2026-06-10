"""Train IsolationForest + LSTM Autoencoder, then save ensemble to disk."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure ml package is importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.models import IForestDetector, LSTMAutoencoder, EnsembleConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]


def load_features(csv_path: str | Path) -> np.ndarray:
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")
    return df[FEATURE_COLS].fillna(0).values.astype(np.float32)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SecureCloud-BD ML models")
    parser.add_argument("--data", required=True, help="Path to preprocessed CSV")
    parser.add_argument("--output", default="models/saved", help="Output directory")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--timesteps", type=int, default=10)
    parser.add_argument("--iforest-weight", type=float, default=0.4)
    parser.add_argument("--ae-weight", type=float, default=0.6)
    args = parser.parse_args()

    out_dir = Path(args.output)
    log.info("Loading features from %s", args.data)
    X = load_features(args.data)
    log.info("Dataset shape: %s", X.shape)

    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)

    # --- Isolation Forest ---
    log.info("Training IsolationForest (contamination=%.3f)", args.contamination)
    iforest = IForestDetector(contamination=args.contamination)
    iforest.fit(X_train)
    iforest.save(out_dir / "iforest")
    log.info("IForest saved → %s/iforest", out_dir)

    # --- LSTM Autoencoder ---
    log.info(
        "Training LSTM Autoencoder (epochs=%d, timesteps=%d)",
        args.epochs, args.timesteps,
    )
    ae = LSTMAutoencoder(
        timesteps=args.timesteps,
        n_features=X_train.shape[1],
    )
    ae.fit(X_train, epochs=args.epochs, batch_size=args.batch_size, verbose=1)
    ae.save(out_dir / "autoencoder")
    log.info("Autoencoder saved → %s/autoencoder", out_dir)

    # --- Quick evaluation on test set ---
    config = EnsembleConfig(
        iforest_weight=args.iforest_weight,
        autoencoder_weight=args.ae_weight,
    )
    if_scores = iforest.score(X_test)
    ae_scores = ae.score(X_test)
    n = min(len(if_scores), len(ae_scores))
    fused = config.iforest_weight * if_scores[:n] + config.ae_weight * ae_scores[:n]

    log.info(
        "Test set fused score — mean: %.4f  p95: %.4f  max: %.4f",
        fused.mean(), np.percentile(fused, 95), fused.max(),
    )
    log.info("Done. Models written to %s", out_dir)


if __name__ == "__main__":
    main()
