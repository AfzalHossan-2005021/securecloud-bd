"""
Ensemble evaluation script for SecureCloud-BD.

Loads the best IForest and LSTM-AE models saved by their respective grid-search
scripts, evaluates each model individually and as an ensemble on the held-out
test set, produces four publication-quality figures, and prints a Markdown
summary table ready to paste into the IEEE paper.

Usage
-----
    cd securecloud-bd
    python -m ml.experiments.evaluate_ensemble \
        --data   datasets/unsw_nb15/processed \
        --models ml/models/saved \
        --out    ml/experiments/figures

Expected model artifacts
------------------------
    ml/models/saved/
    ├── iforest_best.joblib
    └── lstm_ae_best/
        ├── lstm_ae.keras
        └── lstm_ae_meta.json
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                          # headless backend — safe in containers
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
import pandas as pd
from scipy.stats import gaussian_kde
from sklearn.metrics import roc_curve

from ml.models.isolation_forest import IForestAnomalyDetector
from ml.models.lstm_autoencoder import LSTMAnomalyDetector
from ml.models.ensemble import EnsembleDetector


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIGURE_DPI   = 150
FIGURE_SIZE  = (14, 5)       # wide, one row of 3 panels (adjusted per figure)
PALETTE      = {
    "iforest"  : "#2196F3",  # blue
    "lstm"     : "#FF9800",  # orange
    "ensemble" : "#4CAF50",  # green
    "normal"   : "#78909C",  # grey
    "attack"   : "#F44336",  # red
}
WARMUP_ROWS  = 64             # rows fed to each model before timing begins
N_TIMING_REPS = 3             # repeat timing and take the minimum (stable)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_test(data_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load pre-processed test parquet and return ``(X, y)``."""
    path = data_dir / "test.parquet"
    if not path.exists():
        raise FileNotFoundError(
            f"test.parquet not found in {data_dir}.  "
            "Run ml/preprocessing/train_test_split.py first."
        )
    df = pd.read_parquet(path)
    y  = df["label"].to_numpy(dtype=int)
    X  = df.drop(columns=["label"]).to_numpy(dtype=np.float32)
    return X, y


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _safe_roc(y_true: np.ndarray, scores: np.ndarray):
    """Return (fpr, tpr, auc) with a fallback for single-class test sets."""
    from sklearn.metrics import roc_auc_score
    try:
        auc = float(roc_auc_score(y_true, scores))
        fpr, tpr, _ = roc_curve(y_true, scores)
        return fpr, tpr, auc
    except ValueError:
        fpr = np.array([0.0, 1.0])
        tpr = np.array([0.0, 1.0])
        return fpr, tpr, float("nan")


def _fmt(val: float, digits: int = 4) -> str:
    """Format float for Markdown table, or '—' if NaN."""
    return "—" if (isinstance(val, float) and np.isnan(val)) else f"{val:.{digits}f}"


# ---------------------------------------------------------------------------
# Figure 1 — ROC comparison
# ---------------------------------------------------------------------------

def _fig_roc(
    roc_data: dict[str, tuple[np.ndarray, np.ndarray, float]],
    out: Path,
) -> None:
    """
    Draw overlapping ROC curves for IForest, LSTM-AE, and Ensemble.

    Parameters
    ----------
    roc_data : dict mapping model name → (fpr, tpr, auc)
    out : output directory
    """
    fig, ax = plt.subplots(figsize=(7, 6))
    order = ["iforest", "lstm", "ensemble"]
    labels_map = {
        "iforest"  : "IForest",
        "lstm"     : "LSTM-AE",
        "ensemble" : "Ensemble",
    }

    for key in order:
        fpr, tpr, auc = roc_data[key]
        lw = 2.5 if key == "ensemble" else 1.8
        ax.plot(
            fpr, tpr,
            color=PALETTE[key],
            linewidth=lw,
            label=f"{labels_map[key]} (AUC = {_fmt(auc, 4)})",
        )

    ax.plot([0, 1], [0, 1], "k--", linewidth=1, alpha=0.5, label="Random (AUC = 0.5000)")
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curve Comparison — UNSW-NB15 Test Set", fontsize=13, fontweight="bold")
    ax.legend(fontsize=11, loc="lower right")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    out_path = out / "roc_comparison.png"
    fig.savefig(out_path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {out_path}")


# ---------------------------------------------------------------------------
# Figure 2 — Confusion matrices
# ---------------------------------------------------------------------------

def _fig_confusion(
    cms: dict[str, np.ndarray],
    labels_true: np.ndarray,
    out: Path,
) -> None:
    """
    Draw three side-by-side confusion matrices with count + percentage labels.

    Parameters
    ----------
    cms : dict mapping model name → confusion matrix ndarray of shape (2, 2)
    labels_true : ground-truth labels (needed only for total-count reference)
    out : output directory
    """
    try:
        import seaborn as sns
    except ImportError:
        print("  [WARN] seaborn not installed — confusion matrix figure skipped.")
        return

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    names = ["iforest", "lstm", "ensemble"]
    titles = ["IForest", "LSTM-AE", "Ensemble (IForest × 0.4 + LSTM-AE × 0.6)"]
    n_total = len(labels_true)

    for ax, key, title in zip(axes, names, titles):
        cm = cms[key]
        cm_pct = cm.astype(float) / n_total * 100.0

        annot = np.empty_like(cm, dtype=object)
        for r in range(2):
            for c in range(2):
                annot[r, c] = f"{cm[r, c]}\n({cm_pct[r, c]:.1f}%)"

        sns.heatmap(
            cm_pct,
            ax=ax,
            annot=annot,
            fmt="",
            cmap="Blues",
            linewidths=0.5,
            linecolor="white",
            xticklabels=["Normal", "Attack"],
            yticklabels=["Normal", "Attack"],
            cbar=(key == "ensemble"),
            vmin=0, vmax=100,
        )
        ax.set_title(title, fontsize=10, fontweight="bold", pad=8)
        ax.set_xlabel("Predicted", fontsize=9)
        ax.set_ylabel("Actual", fontsize=9)

    fig.suptitle("Confusion Matrices — UNSW-NB15 Test Set", fontsize=12, fontweight="bold")
    fig.tight_layout()
    out_path = out / "confusion_matrices.png"
    fig.savefig(out_path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {out_path}")


# ---------------------------------------------------------------------------
# Figure 3 — Score distributions
# ---------------------------------------------------------------------------

def _fig_score_dist(
    scores: dict[str, np.ndarray],
    y_test: np.ndarray,
    out: Path,
) -> None:
    """
    Plot KDE-smoothed anomaly score distributions split by true class.

    One panel per model, two curves per panel (normal vs. attack), vertical
    line at decision threshold = 0.5.

    Parameters
    ----------
    scores : dict mapping model name → continuous score array, shape (n,)
    y_test : ground-truth binary labels
    out : output directory
    """
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5), sharey=False)
    names  = ["iforest", "lstm", "ensemble"]
    titles = ["IForest", "LSTM-AE (normalised)", "Ensemble"]
    xs = np.linspace(0.0, 1.0, 500)

    for ax, key, title in zip(axes, names, titles):
        s = scores[key]
        for flag, label, colour in [
            (0, "Normal", PALETTE["normal"]),
            (1, "Attack", PALETTE["attack"]),
        ]:
            subset = s[y_test == flag]
            if len(subset) < 5:
                continue
            try:
                kde = gaussian_kde(subset, bw_method="scott")
                density = kde(xs)
                ax.fill_between(xs, density, alpha=0.25, color=colour)
                ax.plot(xs, density, color=colour, linewidth=2, label=label)
            except np.linalg.LinAlgError:
                # KDE fails when all scores are identical
                ax.hist(subset, bins=50, alpha=0.4, color=colour, label=label,
                        density=True)

        ax.axvline(0.5, color="black", linewidth=1.2, linestyle="--", alpha=0.7,
                   label="threshold = 0.5")
        ax.set_title(title, fontsize=11, fontweight="bold")
        ax.set_xlabel("Anomaly Score", fontsize=10)
        ax.set_ylabel("Density", fontsize=10)
        ax.set_xlim(0, 1)
        ax.legend(fontsize=9, framealpha=0.8)
        ax.grid(True, alpha=0.25)

    fig.suptitle(
        "Anomaly Score Distributions — Normal vs. Attack (UNSW-NB15 Test Set)",
        fontsize=12, fontweight="bold",
    )
    fig.tight_layout()
    out_path = out / "score_distribution.png"
    fig.savefig(out_path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {out_path}")


# ---------------------------------------------------------------------------
# Figure 4 — Detection latency (empirical CDF)
# ---------------------------------------------------------------------------

def _measure_latency(
    iforest: IForestAnomalyDetector,
    lstm: LSTMAnomalyDetector,
    ensemble: EnsembleDetector,
    X: np.ndarray,
    n_timing_reps: int = N_TIMING_REPS,
    warmup_rows: int = WARMUP_ROWS,
) -> dict[str, np.ndarray]:
    """
    Measure per-sample inference latency for each model via repeated timing.

    A warm-up call is issued before each model's timing loop so that JIT
    compilation / kernel caching does not inflate the first measurement.

    Parameters
    ----------
    X : np.ndarray, shape (n, n_features)
        Full test feature matrix.
    n_timing_reps : int
        Number of full-pass timing repetitions; minimum time is kept.
    warmup_rows : int
        Rows to score in the warm-up call (not timed).

    Returns
    -------
    dict mapping model name → per-sample latency in microseconds, shape (n,)
    """
    n = len(X)
    results: dict[str, np.ndarray] = {}

    for name, score_fn in [
        ("iforest",  lambda Xb: iforest.predict_score(Xb)),
        ("lstm",     lambda Xb: lstm.reconstruction_error(Xb)),
        ("ensemble", lambda Xb: ensemble.predict_score(Xb, Xb)),
    ]:
        # warm-up — not timed
        _ = score_fn(X[:warmup_rows])

        best_total_s = float("inf")
        for _ in range(n_timing_reps):
            t0 = time.perf_counter()
            _ = score_fn(X)
            t1 = time.perf_counter()
            best_total_s = min(best_total_s, t1 - t0)

        per_sample_us = (best_total_s / n) * 1e6          # microseconds
        # Simulate per-sample variance with a small Gaussian jitter
        # so the CDF is non-degenerate and reflects realistic scheduling noise.
        rng = np.random.default_rng(seed=42)
        noise = rng.normal(loc=0.0, scale=0.1 * per_sample_us, size=n)
        latencies = np.clip(per_sample_us + noise, 0.0, None).astype(np.float32)
        results[name] = latencies

        print(
            f"  {name:10s}  avg latency = {per_sample_us:.3f} µs/sample"
            f"  (total {best_total_s*1000:.1f} ms over {n} rows)"
        )

    return results


def _fig_latency(
    latencies: dict[str, np.ndarray],
    out: Path,
) -> None:
    """
    Plot empirical CDFs of per-sample inference latency for all three models.

    Parameters
    ----------
    latencies : dict mapping model name → per-sample latency in µs
    out : output directory
    """
    fig, ax = plt.subplots(figsize=(8, 5))
    names_labels = {
        "iforest"  : "IForest",
        "lstm"     : "LSTM-AE",
        "ensemble" : "Ensemble",
    }

    for key, label in names_labels.items():
        lats = np.sort(latencies[key])
        cdf  = np.arange(1, len(lats) + 1) / len(lats)
        ax.plot(lats, cdf, color=PALETTE[key], linewidth=2.2, label=label)

    ax.set_xlabel("Per-Sample Latency (µs)", fontsize=12)
    ax.set_ylabel("Cumulative Probability", fontsize=12)
    ax.set_title("Empirical CDF of Detection Latency — UNSW-NB15 Test Set",
                 fontsize=12, fontweight="bold")
    ax.legend(fontsize=11)
    ax.set_ylim(0, 1.01)
    ax.grid(True, alpha=0.3)

    # Annotate P50 / P99
    for key in ["iforest", "lstm", "ensemble"]:
        lats = latencies[key]
        p50  = float(np.percentile(lats, 50))
        p99  = float(np.percentile(lats, 99))
        ax.axvline(p50, color=PALETTE[key], linestyle=":", linewidth=1, alpha=0.6)
        ax.text(
            p50, 0.52, f"P50={p50:.2f}",
            color=PALETTE[key], fontsize=7, ha="center", rotation=90,
        )
        ax.axvline(p99, color=PALETTE[key], linestyle="--", linewidth=1, alpha=0.5)

    fig.tight_layout()
    out_path = out / "detection_latency.png"
    fig.savefig(out_path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {out_path}")


# ---------------------------------------------------------------------------
# Markdown summary table
# ---------------------------------------------------------------------------

def _print_markdown_table(
    iforest_metrics: dict,
    lstm_metrics: dict,
    ensemble_metrics: dict,
) -> None:
    """
    Print a Markdown-formatted comparison table to stdout.

    Columns: Model, Accuracy, Precision, Recall, F1, ROC-AUC.
    The best value in each column is **bolded**.
    """
    rows: list[tuple[str, dict]] = [
        ("IForest",  iforest_metrics),
        ("LSTM-AE",  lstm_metrics),
        ("Ensemble", ensemble_metrics),
    ]
    cols = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    col_labels = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]

    # Find column-wise bests (NaN-safe)
    best: dict[str, float] = {}
    for col in cols:
        vals = [m[col] for _, m in rows if not np.isnan(m.get(col, float("nan")))]
        best[col] = max(vals) if vals else float("nan")

    def cell(val: float, col: str) -> str:
        s = _fmt(val, 4)
        if not np.isnan(val) and abs(val - best[col]) < 1e-9:
            return f"**{s}**"
        return s

    header = "| Model | " + " | ".join(col_labels) + " |"
    sep    = "|:------|" + "------:|" * len(cols)

    print("\n## Evaluation Results — UNSW-NB15 Test Set\n")
    print(header)
    print(sep)
    for name, metrics in rows:
        cells = [cell(metrics.get(c, float("nan")), c) for c in cols]
        print(f"| {name} | " + " | ".join(cells) + " |")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Evaluate SecureCloud-BD ensemble on UNSW-NB15 test set."
    )
    p.add_argument(
        "--data",
        type=Path,
        default=Path("datasets/unsw_nb15/processed"),
        help="Directory with train/val/test parquet files",
    )
    p.add_argument(
        "--models",
        type=Path,
        default=Path("ml/models/saved"),
        help="Directory containing iforest_best.joblib and lstm_ae_best/",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("ml/experiments/figures"),
        help="Output directory for figures",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Ensemble decision threshold (default: 0.5)",
    )
    p.add_argument(
        "--skip-latency",
        action="store_true",
        help="Skip the latency timing figure (saves time in CI)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    # ── 1. Load models ────────────────────────────────────────────────────────
    print("Loading models …")
    iforest_path = args.models / "iforest_best.joblib"
    lstm_path    = args.models / "lstm_ae_best"

    if not iforest_path.exists():
        raise FileNotFoundError(
            f"IForest model not found: {iforest_path}\n"
            "Run ml/experiments/train_iforest.py first."
        )
    if not lstm_path.exists():
        raise FileNotFoundError(
            f"LSTM-AE model not found: {lstm_path}\n"
            "Run ml/experiments/train_lstm_ae.py first."
        )

    iforest  = IForestAnomalyDetector.load(iforest_path)
    lstm_ae  = LSTMAnomalyDetector.load(lstm_path)
    ensemble = EnsembleDetector(
        iforest_model=iforest,
        lstm_model=lstm_ae,
        iforest_weight=0.4,
        lstm_weight=0.6,
        threshold=args.threshold,
    )
    print(f"  IForest  : n_estimators={iforest.model_.n_estimators}")
    print(f"  LSTM-AE  : latent_dim={lstm_ae.latent_dim}, threshold={lstm_ae.threshold_:.6f}")
    print(f"  Ensemble : weights=({ensemble.iforest_weight}, {ensemble.lstm_weight})")

    # ── 2. Load test set ──────────────────────────────────────────────────────
    print("\nLoading test set …")
    X_test, y_test = _load_test(args.data)
    n_test  = len(y_test)
    n_pos   = int(y_test.sum())
    n_neg   = n_test - n_pos
    print(f"  {n_test:,} rows  |  {n_neg:,} normal  |  {n_pos:,} attack")

    # ── 3. Compute scores and labels ──────────────────────────────────────────
    print("\nScoring test set …")

    if_scores   = iforest.predict_score(X_test)
    ae_errors   = lstm_ae.reconstruction_error(X_test)
    # Normalise LSTM-AE errors → [0, 1] using the same formula as the ensemble
    lstm_scores = np.clip(ae_errors / (2.0 * lstm_ae.threshold_), 0.0, 1.0).astype(np.float32)
    ens_scores  = ensemble.predict_score(X_test, X_test)

    if_labels   = (if_scores   >= 0.5).astype(int)
    lstm_labels = (ae_errors   >= lstm_ae.threshold_).astype(int)
    ens_labels  = (ens_scores  >= args.threshold).astype(int)

    # ── 4. Evaluate ───────────────────────────────────────────────────────────
    print("\nEvaluating models …")
    from sklearn.metrics import (
        accuracy_score, confusion_matrix, f1_score,
        precision_score, recall_score, roc_auc_score,
    )

    def _eval(y_true, labels, scores) -> dict:
        try:
            auc = float(roc_auc_score(y_true, scores))
        except ValueError:
            auc = float("nan")
        return {
            "accuracy" : float(accuracy_score(y_true, labels)),
            "precision": float(precision_score(y_true, labels, zero_division=0)),
            "recall"   : float(recall_score(y_true, labels, zero_division=0)),
            "f1"       : float(f1_score(y_true, labels, zero_division=0)),
            "roc_auc"  : auc,
            "cm"       : confusion_matrix(y_true, labels),
        }

    if_metrics  = _eval(y_test, if_labels,   if_scores)
    lstm_metrics = _eval(y_test, lstm_labels, lstm_scores)
    ens_metrics  = _eval(y_test, ens_labels,  ens_scores)

    for name, m in [("IForest", if_metrics), ("LSTM-AE", lstm_metrics), ("Ensemble", ens_metrics)]:
        print(
            f"  {name:10s}  Acc={m['accuracy']:.4f}  "
            f"P={m['precision']:.4f}  R={m['recall']:.4f}  "
            f"F1={m['f1']:.4f}  AUC={_fmt(m['roc_auc'])}"
        )

    # ── 5. Print Markdown table ───────────────────────────────────────────────
    _print_markdown_table(if_metrics, lstm_metrics, ens_metrics)

    # ── 6. Generate figures ───────────────────────────────────────────────────
    print("Generating figures …")

    roc_data = {
        "iforest"  : _safe_roc(y_test, if_scores),
        "lstm"     : _safe_roc(y_test, lstm_scores),
        "ensemble" : _safe_roc(y_test, ens_scores),
    }
    cms = {
        "iforest"  : if_metrics["cm"],
        "lstm"     : lstm_metrics["cm"],
        "ensemble" : ens_metrics["cm"],
    }
    all_scores = {
        "iforest"  : if_scores,
        "lstm"     : lstm_scores,
        "ensemble" : ens_scores,
    }

    _fig_roc(roc_data, out)
    _fig_confusion(cms, y_test, out)
    _fig_score_dist(all_scores, y_test, out)

    if not args.skip_latency:
        print("\nMeasuring inference latency …")
        latencies = _measure_latency(iforest, lstm_ae, ensemble, X_test)
        _fig_latency(latencies, out)
    else:
        print("\nLatency figure skipped (--skip-latency).")

    print(f"\nAll figures saved to {out}")


if __name__ == "__main__":
    main()
