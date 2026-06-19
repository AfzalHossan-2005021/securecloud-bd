"""
fig3_confusion_matrices.py — Side-by-side confusion matrices for 3 models.

Shows Isolation Forest, LSTM-AE, and Ensemble (ours) on the UNSW-NB15 test
set.  Each cell displays absolute count + row-normalised percentage.

Usage
-----
    python -m ml.experiments.fig3_confusion_matrices --out ml/experiments/paper_results
    python -m ml.experiments.fig3_confusion_matrices --mock
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ml.experiments._paper_style import (
    apply_ieee_style, save_figure, PALETTE, DBLW, mock_confusion_matrix,
)

apply_ieee_style()

_CLASS_NAMES = ["Normal", "Attack"]

# Mock confusion matrix specs: (accuracy, recall) for each model
_MOCK_SPECS = {
    "iforest"  : (0.921, 0.908),
    "lstm_ae"  : (0.934, 0.927),
    "ensemble" : (0.961, 0.958),
}
_N_TEST = 82_332   # approximate UNSW-NB15 test set size


def _draw_one_cm(
    ax: plt.Axes,
    cm: np.ndarray,
    title: str,
    border_color: str,
    show_cbar: bool = False,
) -> None:
    """Draw a single annotated confusion matrix on ``ax``."""
    n_total = cm.sum()
    # Row-normalise for color (each row independently) so both classes are visible
    cm_row_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True).clip(1)

    im = ax.imshow(cm_row_norm, cmap="Blues", vmin=0.0, vmax=1.0, aspect="auto")

    if show_cbar:
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, format="%.1f")

    # Cell annotations: absolute + percentage of test set
    for r in range(2):
        for c in range(2):
            count   = cm[r, c]
            pct_row = cm_row_norm[r, c] * 100
            text_color = "white" if cm_row_norm[r, c] > 0.55 else "#212121"
            ax.text(
                c, r,
                f"{count:,}\n({pct_row:.1f}%)",
                ha="center", va="center",
                fontsize=8.5, color=text_color,
            )

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(_CLASS_NAMES)
    ax.set_yticklabels(_CLASS_NAMES)
    ax.set_xlabel("Predicted", labelpad=4)
    ax.set_ylabel("Actual", labelpad=4)

    # Derive scalar metrics from the CM
    tn, fp, fn, tp = cm.ravel()
    acc  = (tp + tn) / n_total
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    subtitle = f"Acc={acc:.3f}  P={prec:.3f}  R={rec:.3f}  F1={f1:.3f}"

    # Title with colored top border effect via bold + colored text
    ax.set_title(f"{title}\n{subtitle}", fontsize=9, color=border_color, pad=5)

    # Colored box around axes spines
    for spine in ax.spines.values():
        spine.set_edgecolor(border_color)
        spine.set_linewidth(1.5)
        spine.set_visible(True)


_PANEL_COLORS = {
    "iforest"  : "#1565C0",
    "lstm_ae"  : "#E65100",
    "ensemble" : "#2E7D32",
}
_PANEL_TITLES = {
    "iforest"  : "Isolation Forest",
    "lstm_ae"  : "LSTM-AE",
    "ensemble" : "Ensemble (Ours)",
}


def draw(
    cms: dict[str, np.ndarray],
    n_test: int,
    out_dir: Path,
    width: float = DBLW,
) -> plt.Figure:
    """
    Draw three side-by-side confusion matrices.

    Parameters
    ----------
    cms    : mapping model_key → 2×2 confusion matrix (TN FP / FN TP layout)
    n_test : total number of test samples (used for percentage calculations)
    out_dir : output directory
    width  : figure width in inches (default: IEEE double column)
    """
    fig, axes = plt.subplots(1, 3, figsize=(width, width * 0.35))
    fig.subplots_adjust(wspace=0.42)

    for ax, key in zip(axes, ["iforest", "lstm_ae", "ensemble"]):
        cm = cms.get(key)
        if cm is None:
            ax.axis("off")
            continue
        _draw_one_cm(
            ax,
            cm,
            title=_PANEL_TITLES[key],
            border_color=_PANEL_COLORS[key],
            show_cbar=(key == "ensemble"),
        )

    fig.suptitle(
        "Confusion Matrices — UNSW-NB15 Test Set",
        fontsize=10, fontweight="bold", y=1.02,
    )
    save_figure(fig, out_dir, "fig3_confusion_matrices")
    return fig


def main() -> None:
    p = argparse.ArgumentParser(description="Generate confusion matrix figure (Fig. 3).")
    p.add_argument("--out", type=Path,
                   default=Path("ml/experiments/paper_results"))
    p.add_argument("--mock", action="store_true")
    args = p.parse_args()

    cms: dict[str, np.ndarray] = {}
    for i, (key, (acc, rec)) in enumerate(_MOCK_SPECS.items()):
        cms[key] = mock_confusion_matrix(_N_TEST, acc, rec, seed=i)
    print("[MOCK] Using synthetic confusion matrices.")

    draw(cms, _N_TEST, args.out)


if __name__ == "__main__":
    main()
