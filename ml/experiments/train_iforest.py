"""
Isolation Forest grid search and evaluation for SecureCloud-BD.

Workflow
--------
1. Load pre-processed train / val / test parquet splits from
   ``ml/data/processed/`` (produced by ``ml/preprocessing/train_test_split.py``).
2. Filter the training split to **normal traffic only** (``label == 0``).
   The Isolation Forest is an unsupervised anomaly detector — training on
   attack rows would teach it that attacks are normal.
3. Run a 3×3 grid search over ``n_estimators`` × ``contamination``.
   Each configuration is fitted on the normal training rows and evaluated
   on the full validation split (all labels).
4. Select the configuration with the highest **validation F1 score**.
   F1 is used (over accuracy) because the dataset is imbalanced: a model that
   flags nothing would still score ~56 % accuracy on UNSW-NB15.
5. Evaluate the best model on the held-out test set.
6. Save all 9 grid-search results to ``ml/experiments/results/iforest_grid_search.csv``.
7. Serialise the best model to ``ml/models/saved/iforest_best.joblib``.

Usage
-----
::

    # From the repo root:
    python ml/experiments/train_iforest.py

    # Override default paths:
    python ml/experiments/train_iforest.py \\
        --data-dir ml/data/processed \\
        --out-dir  ml/models/saved \\
        --results-dir ml/experiments/results \\
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

# Ensure the repo root is on sys.path when running as a script.
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from ml.models.isolation_forest import IForestAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Grid search parameter space
# ---------------------------------------------------------------------------

N_ESTIMATORS_GRID: list[int] = [100, 200, 300]
CONTAMINATION_GRID: list[float] = [0.05, 0.10, 0.15]

# Decision threshold applied to anomaly scores when converting to binary labels.
# Kept fixed throughout grid search to isolate the effect of model parameters.
DECISION_THRESHOLD: float = 0.5

# CSV column order for the results file.
RESULT_COLUMNS: list[str] = [
    "rank",
    "n_estimators",
    "contamination",
    "train_time_s",
    "n_train_normal",
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

    The parquet files written by ``train_test_split.py`` contain one column
    per feature plus a ``label`` column (int8, binary).

    Parameters
    ----------
    path : Path
        Path to a ``.parquet`` file.

    Returns
    -------
    X : np.ndarray, shape (n_samples, n_features), dtype float32
        Feature matrix (all columns except ``label``).
    y : np.ndarray, shape (n_samples,), dtype int
        Binary labels (0 = normal, 1 = attack).

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    KeyError
        If the ``label`` column is absent from the parquet file.
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
    seed: int,
) -> tuple[list[dict[str, Any]], IForestAnomalyDetector, dict[str, Any]]:
    """
    Evaluate every combination of ``N_ESTIMATORS_GRID`` × ``CONTAMINATION_GRID``.

    Each model is trained on *X_train_normal* (normal rows only) and evaluated
    on the full validation split (*X_val*, *y_val*).

    Parameters
    ----------
    X_train_normal : np.ndarray, shape (n_normal, n_features)
        Normal-traffic feature rows only.
    X_val : np.ndarray, shape (n_val, n_features)
        Full validation feature matrix (normal + attack rows).
    y_val : np.ndarray, shape (n_val,)
        Validation ground-truth labels.
    seed : int
        Random seed passed to each ``IForestAnomalyDetector``.

    Returns
    -------
    results : list[dict]
        One dict per configuration, sorted by ``val_f1`` descending.
    best_model : IForestAnomalyDetector
        Fitted detector with the highest validation F1.
    best_row : dict
        Row from *results* corresponding to the best model.
    """
    n_configs = len(N_ESTIMATORS_GRID) * len(CONTAMINATION_GRID)
    log.info(
        "Starting grid search: %d configurations over %d×%d parameter grid",
        n_configs, len(N_ESTIMATORS_GRID), len(CONTAMINATION_GRID),
    )
    log.info("  n_estimators : %s", N_ESTIMATORS_GRID)
    log.info("  contamination: %s", CONTAMINATION_GRID)
    log.info("  training rows (normal only): %d", len(X_train_normal))
    log.info("  validation rows (all labels): %d", len(X_val))
    log.info("")

    results: list[dict[str, Any]] = []
    best_f1 = -1.0
    best_model: IForestAnomalyDetector | None = None
    best_row: dict[str, Any] = {}

    config_idx = 0
    for n_est in N_ESTIMATORS_GRID:
        for cont in CONTAMINATION_GRID:
            config_idx += 1
            log.info(
                "[%d/%d] n_estimators=%d  contamination=%.2f",
                config_idx, n_configs, n_est, cont,
            )

            detector = IForestAnomalyDetector(
                n_estimators=n_est,
                contamination=cont,
                random_state=seed,
            )
            detector.fit(X_train_normal)
            val_metrics = detector.evaluate(X_val, y_val, threshold=DECISION_THRESHOLD)
            cm = val_metrics["confusion_matrix"]  # shape (2, 2): [[TN,FP],[FN,TP]]

            row: dict[str, Any] = {
                "n_estimators"  : n_est,
                "contamination" : cont,
                "train_time_s"  : round(detector.train_time_s_, 3),
                "n_train_normal": len(X_train_normal),
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
                "        precision=%.4f  recall=%.4f  f1=%.4f  "
                "roc_auc=%.4f  time=%.1fs",
                val_metrics["precision"], val_metrics["recall"],
                val_metrics["f1"], val_metrics["roc_auc"],
                detector.train_time_s_,
            )

            if val_metrics["f1"] > best_f1:
                best_f1 = val_metrics["f1"]
                best_model = detector
                best_row = row

    # Sort by F1 descending and assign rank
    results.sort(key=lambda r: r["val_f1"], reverse=True)
    for i, r in enumerate(results, start=1):
        r["rank"] = i

    log.info("")
    log.info(
        "Best config: n_estimators=%d  contamination=%.2f  val_f1=%.4f",
        best_row["n_estimators"], best_row["contamination"], best_row["val_f1"],
    )
    return results, best_model, best_row


# ---------------------------------------------------------------------------
# Results persistence
# ---------------------------------------------------------------------------

def save_results_csv(
    results: list[dict[str, Any]],
    path: Path,
) -> None:
    """
    Write grid search results to a CSV file.

    Overwrites any existing file at *path*.  Column order follows
    ``RESULT_COLUMNS`` so the file is human-readable top-to-bottom
    (rank 1 = best configuration).

    Parameters
    ----------
    results : list[dict]
        Rows returned by ``run_grid_search()``, already sorted and ranked.
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

def _print_metrics(
    label: str,
    metrics: dict[str, Any],
    threshold: float,
) -> None:
    """
    Print a formatted metrics table to stdout.

    Parameters
    ----------
    label : str
        Header label (e.g. ``"Validation"`` or ``"Test"``).
    metrics : dict
        Output of ``IForestAnomalyDetector.evaluate()``.
    threshold : float
        Decision threshold used to produce the labels.
    """
    cm = metrics["confusion_matrix"]
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    print()
    print(f"  ── {label} Metrics (threshold={threshold}) ──")
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
    Entry point for the grid search experiment.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments (see ``parse_args()``).
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
    # The Isolation Forest is unsupervised: it learns the distribution of
    # normal traffic, then flags deviations.  Including attack rows during
    # training degrades recall because the model treats them as part of the
    # normal manifold.
    normal_mask     = y_train == 0
    X_train_normal  = X_train[normal_mask]
    n_attacks_dropped = int((~normal_mask).sum())

    log.info("")
    log.info(
        "Training filter — normal: %d  attack (dropped): %d  (%.1f%% of train set)",
        len(X_train_normal), n_attacks_dropped,
        n_attacks_dropped / len(y_train) * 100,
    )

    # ── Grid search ──────────────────────────────────────────────────────────
    print()
    print("=" * 66)
    print("  SecureCloud-BD — Isolation Forest Grid Search")
    print("=" * 66)

    t_gs = time.perf_counter()
    results, best_model, best_row = run_grid_search(
        X_train_normal, X_val, y_val, seed=args.seed
    )
    log.info("Grid search complete in %.1fs", time.perf_counter() - t_gs)

    # ── Save CSV ─────────────────────────────────────────────────────────────
    csv_path = results_dir / "iforest_grid_search.csv"
    save_results_csv(results, csv_path)

    # ── Print leaderboard ────────────────────────────────────────────────────
    print()
    print("  Grid search leaderboard (sorted by val_f1):")
    print(f"  {'Rank':>4}  {'n_est':>5}  {'cont':>6}  "
          f"{'prec':>6}  {'rec':>6}  {'f1':>6}  {'auc':>6}  {'time':>6}")
    print("  " + "-" * 56)
    for r in results:
        marker = " ◄ best" if r["rank"] == 1 else ""
        print(
            f"  {r['rank']:>4}  {r['n_estimators']:>5}  "
            f"{r['contamination']:>6.2f}  "
            f"{r['val_precision']:>6.4f}  {r['val_recall']:>6.4f}  "
            f"{r['val_f1']:>6.4f}  {r['val_roc_auc']:>6.4f}  "
            f"{r['train_time_s']:>5.1f}s{marker}"
        )

    # ── Test set evaluation ──────────────────────────────────────────────────
    log.info("")
    log.info("Evaluating best model on held-out test set…")
    test_metrics = best_model.evaluate(X_test, y_test, threshold=DECISION_THRESHOLD)

    print()
    print("=" * 66)
    print("  Best model parameters:")
    print(f"    n_estimators  = {best_row['n_estimators']}")
    print(f"    contamination = {best_row['contamination']}")
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
    }, DECISION_THRESHOLD)
    _print_metrics("Test", test_metrics, DECISION_THRESHOLD)
    print("=" * 66)

    # ── Save best model ──────────────────────────────────────────────────────
    model_path = out_dir / "iforest_best.joblib"
    out_dir.mkdir(parents=True, exist_ok=True)
    best_model.save(model_path)

    print()
    print(f"  Model saved  → {model_path}")
    print(f"  Results CSV  → {csv_path}")
    print()

    # ── Append test metrics to the CSV ───────────────────────────────────────
    # Re-open and add a test_* column group so one file has the complete picture.
    test_cm = test_metrics["confusion_matrix"]
    best_row_extended = {
        **best_row,
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

    # Read existing CSV, mark the best row with test metrics, re-write
    existing = pd.read_csv(csv_path)
    best_rank_mask = existing["rank"] == 1
    for col, val in best_row_extended.items():
        if col not in existing.columns:
            existing[col] = None
        existing.loc[best_rank_mask, col] = val
    existing.to_csv(csv_path, index=False)
    log.info("Test metrics appended to %s", csv_path)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed arguments with defaults filled in.
    """
    parser = argparse.ArgumentParser(
        description="IsolationForest grid search for SecureCloud-BD",
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
        help="Directory for the saved best model (iforest_best.joblib)",
    )
    parser.add_argument(
        "--results-dir",
        default="ml/experiments/results",
        help="Directory for the grid search CSV",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed passed to every IForestAnomalyDetector",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main(parse_args())
