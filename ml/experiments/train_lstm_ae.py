"""
LSTM Autoencoder grid search and evaluation for SecureCloud-BD.

Mirrors ``ml/experiments/train_iforest.py`` in structure; refer to that
script for narrative context on the overall experiment design.

Workflow
--------
1. Load pre-processed train / val / test parquet splits from
   ``ml/data/processed/``.
2. Filter the training split to **normal traffic only** (``label == 0``).
3. Run a 3×3 grid search over ``latent_dim`` × ``learning_rate``.
   Each configuration is:

   a. Trained with ``fit(X_train_normal)``
   b. Thresholded with ``set_threshold(X_val_normal)`` — the threshold is
      derived from validation *normal* rows only to avoid contamination.
   c. Evaluated on the full validation split (all labels).

4. Select the configuration with the highest **validation F1 score**.
5. Evaluate the best model on the held-out test set.
6. Save all 9 results to ``ml/experiments/results/lstm_ae_grid_search.csv``.
7. Serialise the best model to ``ml/models/saved/lstm_ae_best/``.

Compute note
------------
Each LSTM training run can take 5–20 minutes on CPU depending on dataset
size and ``latent_dim``.  The full 9-configuration grid can therefore take
45–180 minutes on a CPU-only machine.  With a GPU the entire grid typically
completes in under 20 minutes.

EarlyStopping (patience=5) usually terminates well before the maximum epoch
count; the ``epochs_trained`` column in the CSV shows the actual count.

Usage
-----
::

    # From the repo root:
    python ml/experiments/train_lstm_ae.py

    # With custom paths and fewer epochs (useful for quick smoke-test):
    python ml/experiments/train_lstm_ae.py \\
        --data-dir   ml/data/processed \\
        --out-dir    ml/models/saved \\
        --results-dir ml/experiments/results \\
        --max-epochs 10 \\
        --batch-size 256 \\
        --seed 42
"""
from __future__ import annotations

import argparse
import csv
import logging
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

import tensorflow as tf

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from ml.models.lstm_autoencoder import LSTMAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Silence TensorFlow's own INFO / WARNING logs — our logger provides context.
tf.get_logger().setLevel("ERROR")

# ---------------------------------------------------------------------------
# Grid search parameter space
# ---------------------------------------------------------------------------

LATENT_DIM_GRID: list[int]   = [8, 16, 32]
LEARNING_RATE_GRID: list[float] = [1e-3, 5e-4, 1e-4]

TIMESTEPS: int  = 10     # window size; must match the value used during preprocessing
BATCH_SIZE: int = 256

# CSV column order for the results file.
RESULT_COLUMNS: list[str] = [
    "rank",
    "latent_dim",
    "learning_rate",
    "epochs_trained",
    "train_time_s",
    "n_train_normal",
    "threshold",
    "val_accuracy",
    "val_precision",
    "val_recall",
    "val_f1",
    "val_roc_auc",
    "val_tn",
    "val_fp",
    "val_fn",
    "val_tp",
]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_split(path: Path) -> tuple[np.ndarray, np.ndarray]:
    """
    Load a parquet split into a feature matrix and label vector.

    Parameters
    ----------
    path : Path
        Path to a ``.parquet`` file written by ``train_test_split.py``.
        Must contain a ``label`` column and one or more feature columns.

    Returns
    -------
    X : np.ndarray, shape (n_samples, n_features), dtype float32
    y : np.ndarray, shape (n_samples,), dtype int

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    KeyError
        If the ``label`` column is absent.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Split file not found: {path}\n"
            "Run: python ml/preprocessing/train_test_split.py"
        )
    df = pd.read_parquet(path, engine="pyarrow")
    if "label" not in df.columns:
        raise KeyError(f"'label' column missing from {path}")
    y = df["label"].to_numpy(dtype=int)
    X = df.drop(columns=["label"]).to_numpy(dtype=np.float32)
    return X, y


# ---------------------------------------------------------------------------
# Grid search
# ---------------------------------------------------------------------------

def run_grid_search(
    X_train_normal: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    max_epochs: int,
    batch_size: int,
    seed: int,
) -> tuple[list[dict[str, Any]], LSTMAnomalyDetector, dict[str, Any]]:
    """
    Evaluate every combination of ``LATENT_DIM_GRID`` × ``LEARNING_RATE_GRID``.

    For each configuration the pipeline is:

    1. ``fit(X_train_normal)`` — train on normal traffic.
    2. ``set_threshold(X_val_normal)`` — threshold from validation normal rows.
    3. ``evaluate(X_val, y_val)`` — score on all validation rows.

    Parameters
    ----------
    X_train_normal : np.ndarray, shape (n_normal, n_features)
        Normal-traffic rows from the training split.
    X_val : np.ndarray, shape (n_val, n_features)
        Full validation split (normal + attack rows).
    y_val : np.ndarray, shape (n_val,)
        Validation ground-truth labels.
    max_epochs : int
        Maximum training epochs per configuration (EarlyStopping may stop
        earlier).
    batch_size : int
        Mini-batch size for Keras training.
    seed : int
        Random seed.  Passed to TF global seed for reproducibility.

    Returns
    -------
    results : list[dict]
        One dict per configuration, sorted by ``val_f1`` descending.
    best_model : LSTMAnomalyDetector
        The fitted detector with the highest validation F1.
    best_row : dict
        The entry from *results* corresponding to the best model.
    """
    tf.random.set_seed(seed)

    n_features     = X_train_normal.shape[1]
    n_configs      = len(LATENT_DIM_GRID) * len(LEARNING_RATE_GRID)
    X_val_normal   = X_val[y_val == 0]

    log.info(
        "Starting grid search: %d configs  (%d latent_dim × %d lr values)",
        n_configs, len(LATENT_DIM_GRID), len(LEARNING_RATE_GRID),
    )
    log.info("  latent_dim   : %s", LATENT_DIM_GRID)
    log.info("  learning_rate: %s", LEARNING_RATE_GRID)
    log.info("  n_features   : %d", n_features)
    log.info("  timesteps    : %d", TIMESTEPS)
    log.info("  max_epochs   : %d (EarlyStopping patience=5)", max_epochs)
    log.info("  train normal : %d rows", len(X_train_normal))
    log.info("  val total    : %d rows  (%d normal)", len(X_val), len(X_val_normal))
    log.info("")

    results: list[dict[str, Any]] = []
    best_f1    = -1.0
    best_model: LSTMAnomalyDetector | None = None
    best_row: dict[str, Any] = {}
    config_idx = 0

    for latent_dim in LATENT_DIM_GRID:
        for lr in LEARNING_RATE_GRID:
            config_idx += 1
            log.info(
                "[%d/%d] latent_dim=%d  lr=%.1e",
                config_idx, n_configs, latent_dim, lr,
            )

            detector = LSTMAnomalyDetector(
                timesteps=TIMESTEPS,
                n_features=n_features,
                latent_dim=latent_dim,
                learning_rate=lr,
            )

            # ── Train ────────────────────────────────────────────────────
            detector.fit(
                X_train_normal,
                epochs=max_epochs,
                batch_size=batch_size,
                validation_split=0.1,
                verbose=0,
            )

            # ── Set threshold from validation normal rows ─────────────────
            detector.set_threshold(X_val_normal)

            # ── Evaluate on full validation split ─────────────────────────
            val_metrics = detector.evaluate(X_val, y_val)
            cm = val_metrics["confusion_matrix"]

            row: dict[str, Any] = {
                "latent_dim"    : latent_dim,
                "learning_rate" : lr,
                "epochs_trained": detector.epochs_trained_,
                "train_time_s"  : round(detector.train_time_s_, 2),
                "n_train_normal": len(X_train_normal),
                "threshold"     : round(detector.threshold_, 8),
                "val_accuracy"  : round(val_metrics["accuracy"],  4),
                "val_precision" : round(val_metrics["precision"], 4),
                "val_recall"    : round(val_metrics["recall"],    4),
                "val_f1"        : round(val_metrics["f1"],        4),
                "val_roc_auc"   : round(val_metrics["roc_auc"],   4),
                "val_tn"        : int(cm[0, 0]),
                "val_fp"        : int(cm[0, 1]),
                "val_fn"        : int(cm[1, 0]),
                "val_tp"        : int(cm[1, 1]),
            }
            results.append(row)

            log.info(
                "        prec=%.4f  rec=%.4f  f1=%.4f  auc=%.4f"
                "  epochs=%d  time=%.1fs  thr=%.6f",
                val_metrics["precision"], val_metrics["recall"],
                val_metrics["f1"],        val_metrics["roc_auc"],
                detector.epochs_trained_, detector.train_time_s_,
                detector.threshold_,
            )

            if val_metrics["f1"] > best_f1:
                best_f1    = val_metrics["f1"]
                best_model = detector
                best_row   = row

    # Sort by F1 descending and assign rank.
    results.sort(key=lambda r: r["val_f1"], reverse=True)
    for i, r in enumerate(results, start=1):
        r["rank"] = i

    log.info("")
    log.info(
        "Best config: latent_dim=%d  lr=%.1e  val_f1=%.4f",
        best_row["latent_dim"], best_row["learning_rate"], best_row["val_f1"],
    )
    return results, best_model, best_row


# ---------------------------------------------------------------------------
# Results persistence
# ---------------------------------------------------------------------------

def save_results_csv(results: list[dict[str, Any]], path: Path) -> None:
    """
    Write grid search results to a CSV file (overwrites any existing file).

    Parameters
    ----------
    results : list[dict]
        Rows from ``run_grid_search()``, already sorted and ranked.
    path : Path
        Destination ``.csv`` file.  Parent directory is created if absent.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=RESULT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    log.info("Grid search results saved → %s", path)


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

def _print_metrics(label: str, metrics: dict[str, Any], threshold: float) -> None:
    """
    Print a formatted metrics summary to stdout.

    Parameters
    ----------
    label : str
        Header label (e.g. ``"Validation"``).
    metrics : dict
        Output of ``LSTMAnomalyDetector.evaluate()``.
    threshold : float
        Threshold value used to binarise labels.
    """
    cm = metrics["confusion_matrix"]
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    print()
    print(f"  ── {label} Metrics (threshold={threshold:.6f}) ──")
    print(f"     Accuracy  : {metrics['accuracy']:.4f}")
    print(f"     Precision : {metrics['precision']:.4f}")
    print(f"     Recall    : {metrics['recall']:.4f}")
    print(f"     F1        : {metrics['f1']:.4f}")
    print(f"     ROC-AUC   : {metrics['roc_auc']:.4f}")
    print(f"     Confusion matrix:")
    print(f"       TN={tn:>7,}   FP={fp:>7,}")
    print(f"       FN={fn:>7,}   TP={tp:>7,}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(args: argparse.Namespace) -> None:
    """
    Entry point for the LSTM AE grid search experiment.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments (see ``parse_args()``).
    """
    data_dir    = Path(args.data_dir)
    out_dir     = Path(args.out_dir)
    results_dir = Path(args.results_dir)

    # ── Load splits ─────────────────────────────────────────────────────────
    log.info("Loading data splits from %s", data_dir)
    t_load = time.perf_counter()

    X_train, y_train = load_split(data_dir / "train.parquet")
    X_val,   y_val   = load_split(data_dir / "val.parquet")
    X_test,  y_test  = load_split(data_dir / "test.parquet")

    log.info("  train : %d rows  (%d features)", *X_train.shape)
    log.info("  val   : %d rows", len(X_val))
    log.info("  test  : %d rows", len(X_test))
    log.info("  loaded in %.2fs", time.perf_counter() - t_load)

    # ── Filter training set to normal traffic only ───────────────────────────
    normal_mask      = y_train == 0
    X_train_normal   = X_train[normal_mask]
    n_attacks_dropped = int((~normal_mask).sum())

    log.info("")
    log.info(
        "Training filter — normal: %d  attack (dropped): %d  (%.1f%% of train)",
        len(X_train_normal), n_attacks_dropped,
        n_attacks_dropped / len(y_train) * 100,
    )

    # Warn if there are not enough rows to form a sequence.
    if len(X_train_normal) < TIMESTEPS:
        log.error(
            "Only %d normal training rows; need at least %d (TIMESTEPS).",
            len(X_train_normal), TIMESTEPS,
        )
        sys.exit(1)

    # ── Grid search ──────────────────────────────────────────────────────────
    print()
    print("=" * 66)
    print("  SecureCloud-BD — LSTM Autoencoder Grid Search")
    print("=" * 66)

    t_gs = time.perf_counter()
    results, best_model, best_row = run_grid_search(
        X_train_normal,
        X_val, y_val,
        max_epochs=args.max_epochs,
        batch_size=args.batch_size,
        seed=args.seed,
    )
    log.info("Grid search complete in %.1fs", time.perf_counter() - t_gs)

    # ── Save CSV ─────────────────────────────────────────────────────────────
    csv_path = results_dir / "lstm_ae_grid_search.csv"
    save_results_csv(results, csv_path)

    # ── Print leaderboard ────────────────────────────────────────────────────
    print()
    print("  Grid search leaderboard (sorted by val_f1):")
    print(
        f"  {'Rank':>4}  {'ldim':>5}  {'lr':>7}  "
        f"{'prec':>6}  {'rec':>6}  {'f1':>6}  {'auc':>6}  "
        f"{'ep':>3}  {'time':>6}"
    )
    print("  " + "-" * 63)
    for r in results:
        marker = " ◄ best" if r["rank"] == 1 else ""
        print(
            f"  {r['rank']:>4}  {r['latent_dim']:>5}  "
            f"{r['learning_rate']:>7.1e}  "
            f"{r['val_precision']:>6.4f}  {r['val_recall']:>6.4f}  "
            f"{r['val_f1']:>6.4f}  {r['val_roc_auc']:>6.4f}  "
            f"{r['epochs_trained']:>3}  {r['train_time_s']:>5.0f}s{marker}"
        )

    # ── Test set evaluation ──────────────────────────────────────────────────
    log.info("")
    log.info("Evaluating best model on held-out test set…")
    test_metrics = best_model.evaluate(X_test, y_test)

    print()
    print("=" * 66)
    print("  Best model parameters:")
    print(f"    latent_dim    = {best_row['latent_dim']}")
    print(f"    learning_rate = {best_row['learning_rate']:.1e}")
    print(f"    epochs_trained= {best_row['epochs_trained']}")
    print(f"    threshold     = {best_model.threshold_:.6f}  (mean + 2σ on val normal)")
    _print_metrics("Validation", {
        "accuracy"        : best_row["val_accuracy"],
        "precision"       : best_row["val_precision"],
        "recall"          : best_row["val_recall"],
        "f1"              : best_row["val_f1"],
        "roc_auc"         : best_row["val_roc_auc"],
        "confusion_matrix": np.array([
            [best_row["val_tn"], best_row["val_fp"]],
            [best_row["val_fn"], best_row["val_tp"]],
        ]),
    }, best_model.threshold_)
    _print_metrics("Test", test_metrics, best_model.threshold_)
    print("=" * 66)

    # ── Save best model ──────────────────────────────────────────────────────
    model_dir = out_dir / "lstm_ae_best"
    out_dir.mkdir(parents=True, exist_ok=True)
    best_model.save(model_dir)

    print()
    print(f"  Model saved  → {model_dir}")
    print(f"  Results CSV  → {csv_path}")
    print()

    # ── Append test metrics to the rank-1 CSV row ────────────────────────────
    test_cm = test_metrics["confusion_matrix"]
    test_cols = {
        "test_accuracy" : round(test_metrics["accuracy"],  4),
        "test_precision": round(test_metrics["precision"], 4),
        "test_recall"   : round(test_metrics["recall"],    4),
        "test_f1"       : round(test_metrics["f1"],        4),
        "test_roc_auc"  : round(test_metrics["roc_auc"],   4),
        "test_tn"       : int(test_cm[0, 0]),
        "test_fp"       : int(test_cm[0, 1]),
        "test_fn"       : int(test_cm[1, 0]),
        "test_tp"       : int(test_cm[1, 1]),
    }
    existing = pd.read_csv(csv_path)
    best_mask = existing["rank"] == 1
    for col, val in test_cols.items():
        if col not in existing.columns:
            existing[col] = None
        existing.loc[best_mask, col] = val
    existing.to_csv(csv_path, index=False)
    log.info("Test metrics appended to %s", csv_path)


def parse_args() -> argparse.Namespace:
    """
    Parse CLI arguments.

    Returns
    -------
    argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description="LSTM Autoencoder grid search for SecureCloud-BD",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        default="ml/data/processed",
        help="Directory containing train.parquet, val.parquet, test.parquet",
    )
    parser.add_argument(
        "--out-dir",
        default="ml/models/saved",
        help="Parent directory for the saved best model (lstm_ae_best/)",
    )
    parser.add_argument(
        "--results-dir",
        default="ml/experiments/results",
        help="Directory for the grid search CSV",
    )
    parser.add_argument(
        "--max-epochs",
        type=int,
        default=50,
        help="Maximum training epochs per configuration",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=256,
        help="Mini-batch size for Keras training",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for TF and numpy",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main(parse_args())
