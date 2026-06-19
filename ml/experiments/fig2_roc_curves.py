"""
fig2_roc_curves.py — ROC comparison chart for all 5 models (IEEE single column).

Draws overlapping ROC curves for:
  Isolation Forest, LSTM-AE, Ensemble (ours), SVM (baseline), RF (baseline)

The ``draw()`` function accepts a ``roc_data`` dict; when called from
``paper_results.py``, real AUC values are passed in.  When run standalone
(``--mock``), synthetic curves are generated.

Usage
-----
    python -m ml.experiments.fig2_roc_curves --out ml/experiments/paper_results
    python -m ml.experiments.fig2_roc_curves --mock
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ml.experiments._paper_style import (
    apply_ieee_style, save_figure, PALETTE, MODEL_LABELS,
    COL_W, mock_roc_curve,
)

apply_ieee_style()

# Model draw order: baselines first, then ours last (so it renders on top)
_ORDER = ["svm", "rf", "iforest", "lstm_ae", "ensemble"]
_STYLES = {
    "svm"      : dict(linestyle=":",  linewidth=1.2, alpha=0.85),
    "rf"       : dict(linestyle="-.", linewidth=1.2, alpha=0.85),
    "iforest"  : dict(linestyle="--", linewidth=1.6),
    "lstm_ae"  : dict(linestyle="--", linewidth=1.6),
    "ensemble" : dict(linestyle="-",  linewidth=2.2),
}

# Default synthetic AUC targets (replaced by real values in paper_results.py)
_MOCK_AUCS = {
    "iforest"  : 0.9421,
    "lstm_ae"  : 0.9638,
    "ensemble" : 0.9817,
    "svm"      : 0.9103,
    "rf"       : 0.9355,
}


def draw(
    roc_data: dict[str, tuple[np.ndarray, np.ndarray, float]],
    out_dir: Path,
    width: float = COL_W,
) -> plt.Figure:
    """
    Draw publication-quality ROC curves.

    Parameters
    ----------
    roc_data : mapping model_key → (fpr, tpr, auc)
    out_dir  : output directory for fig2_roc_curves.{pdf,png}
    width    : figure width in inches (default: IEEE single column = 3.5")
    """
    fig, ax = plt.subplots(figsize=(width, width * 1.05))

    # Random baseline
    ax.plot([0, 1], [0, 1], color="#aaaaaa", linewidth=0.9,
            linestyle=":", label="Random (AUC = 0.5000)")

    for key in _ORDER:
        if key not in roc_data:
            continue
        fpr, tpr, auc = roc_data[key]
        label = f"{MODEL_LABELS[key]} ({auc:.4f})"
        ax.plot(
            fpr, tpr,
            color=PALETTE[key],
            label=label,
            **_STYLES[key],
        )

    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — UNSW-NB15 Test Set", pad=6)
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.01)
    ax.set_aspect("equal", adjustable="box")
    ax.grid(True)

    # Legend outside right (avoids clutter at small column width)
    ax.legend(
        loc="lower right",
        fontsize=7.5,
        framealpha=0.95,
        edgecolor="#cccccc",
    )

    # Zoom inset on top-left corner (high-sensitivity region)
    inset = ax.inset_axes([0.08, 0.54, 0.38, 0.40])
    inset.set_xlim(0, 0.10)
    inset.set_ylim(0.88, 1.01)
    for key in _ORDER:
        if key not in roc_data:
            continue
        fpr, tpr, _ = roc_data[key]
        mask = fpr <= 0.12
        inset.plot(fpr[mask], tpr[mask], color=PALETTE[key], **_STYLES[key])
    inset.set_title("Low-FPR\nzoom", fontsize=7, pad=2)
    inset.tick_params(labelsize=6.5)
    inset.grid(True, linewidth=0.4, alpha=0.5)
    ax.indicate_inset_zoom(inset, edgecolor="#888888", linewidth=0.7)

    fig.tight_layout()
    save_figure(fig, out_dir, "fig2_roc_curves")
    return fig


def main() -> None:
    p = argparse.ArgumentParser(description="Generate ROC comparison chart (Fig. 2).")
    p.add_argument("--out", type=Path,
                   default=Path("ml/experiments/paper_results"))
    p.add_argument("--mock", action="store_true",
                   help="Use synthetic ROC curves (no models required)")
    args = p.parse_args()

    roc_data: dict[str, tuple[np.ndarray, np.ndarray, float]] = {}
    for i, (key, auc_target) in enumerate(_MOCK_AUCS.items()):
        roc_data[key] = mock_roc_curve(auc_target, seed=i)
    print("[MOCK] Using synthetic ROC curves.")

    draw(roc_data, args.out)


if __name__ == "__main__":
    main()
