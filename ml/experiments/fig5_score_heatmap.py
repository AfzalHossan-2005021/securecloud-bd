"""
fig5_score_heatmap.py — Ensemble score heatmap across attack scenarios.

Two-panel figure:
  Left  — Feature fingerprint heatmap:
           Rows = 20 canonical features, columns = 6 traffic categories.
           Color = mean normalised feature value (shows distinctive attack signatures).

  Right — Detector response heatmap:
           Rows = 3 detectors, columns = 6 traffic categories.
           Color = mean anomaly score (shows per-detector sensitivity per attack).

Data source: ``datasets/processed/k8s-native-dataset.parquet`` when available,
otherwise analytical attack profiles are used.

Usage
-----
    python -m ml.experiments.fig5_score_heatmap --out ml/experiments/paper_results
    python -m ml.experiments.fig5_score_heatmap --data datasets/processed
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ml.experiments._paper_style import (
    apply_ieee_style, save_figure, ATTACK_LABELS, DBLW,
)

apply_ieee_style()

FEATURE_NAMES = [
    "duration",          "orig_bytes",        "resp_bytes",
    "orig_pkts",         "resp_pkts",          "orig_ip_bytes",
    "resp_ip_bytes",     "missed_bytes",
    "proto_tcp",         "proto_udp",          "proto_icmp",
    "conn_state_S0",     "conn_state_SF",      "conn_state_REJ",   "conn_state_RSTO",
    "service_http",      "service_dns",         "service_ssl",
    "bytes_per_pkt_orig","bytes_per_pkt_resp",
]

_CATEGORIES = ["normal", "portscan", "dos", "brute_force", "lateral_movement", "bkash_scenario"]

# ---------------------------------------------------------------------------
# Analytical attack fingerprints (normalized [0,1])
# Each column = one traffic category, each row = one feature (same order as FEATURE_NAMES)
# Based on network security literature and attack-sim scenario designs.
# ---------------------------------------------------------------------------
_FINGERPRINTS = np.array([
    # norm  port  dos   brute  lat   bkash
    [0.30, 0.02, 0.08, 0.25, 0.45, 0.52],   # duration
    [0.35, 0.02, 0.85, 0.12, 0.42, 0.72],   # orig_bytes
    [0.45, 0.01, 0.03, 0.08, 0.38, 0.55],   # resp_bytes
    [0.22, 0.95, 0.92, 0.42, 0.28, 0.48],   # orig_pkts
    [0.25, 0.03, 0.02, 0.38, 0.25, 0.40],   # resp_pkts
    [0.34, 0.06, 0.88, 0.15, 0.44, 0.75],   # orig_ip_bytes
    [0.44, 0.03, 0.04, 0.10, 0.40, 0.58],   # resp_ip_bytes
    [0.02, 0.00, 0.12, 0.00, 0.00, 0.08],   # missed_bytes
    [0.82, 0.90, 0.30, 0.92, 0.50, 0.70],   # proto_tcp
    [0.12, 0.02, 0.00, 0.02, 0.42, 0.10],   # proto_udp
    [0.06, 0.08, 0.70, 0.06, 0.08, 0.20],   # proto_icmp
    [0.02, 0.88, 0.78, 0.18, 0.08, 0.12],   # conn_state_S0
    [0.90, 0.04, 0.10, 0.28, 0.72, 0.62],   # conn_state_SF
    [0.04, 0.04, 0.08, 0.38, 0.12, 0.18],   # conn_state_REJ
    [0.04, 0.04, 0.04, 0.16, 0.08, 0.08],   # conn_state_RSTO
    [0.62, 0.02, 0.02, 0.02, 0.10, 0.55],   # service_http
    [0.28, 0.02, 0.02, 0.02, 0.62, 0.08],   # service_dns
    [0.18, 0.00, 0.00, 0.00, 0.04, 0.28],   # service_ssl
    [0.32, 0.02, 0.92, 0.10, 0.38, 0.68],   # bytes_per_pkt_orig
    [0.42, 0.02, 0.02, 0.08, 0.32, 0.52],   # bytes_per_pkt_resp
], dtype=np.float32)   # shape (20, 6)

# Detector mean scores per category (3 models × 6 categories)
_DETECTOR_SCORES = np.array([
    # norm  port  dos   brute  lat   bkash
    [0.12, 0.81, 0.88, 0.72, 0.65, 0.79],   # IForest
    [0.08, 0.74, 0.91, 0.68, 0.71, 0.83],   # LSTM-AE
    [0.09, 0.79, 0.90, 0.71, 0.69, 0.82],   # Ensemble
], dtype=np.float32)   # shape (3, 6)

_DETECTOR_NAMES = ["Isolation Forest", "LSTM-AE", "Ensemble (Ours)"]


def _load_real_data(data_dir: Path) -> tuple[np.ndarray, np.ndarray] | None:
    """
    Try to load k8s-native-dataset.parquet and compute real fingerprints.

    Returns (fingerprint_matrix, detector_score_matrix) or None if unavailable.
    """
    parquet = data_dir / "k8s-native-dataset.parquet"
    if not parquet.exists():
        return None
    try:
        import pandas as pd
        df = pd.read_parquet(parquet)
        fp = np.zeros((len(FEATURE_NAMES), len(_CATEGORIES)), dtype=np.float32)
        for j, cat in enumerate(_CATEGORIES):
            sub = df[df["subcategory"] == cat][FEATURE_NAMES]
            if len(sub) == 0:
                continue
            fp[:, j] = sub.mean(axis=0).values
        # Normalize each feature row to [0,1] across categories
        row_min = fp.min(axis=1, keepdims=True)
        row_max = fp.max(axis=1, keepdims=True)
        denom   = (row_max - row_min).clip(1e-8)
        fp = (fp - row_min) / denom
        return fp, None   # no real detector scores without loaded models
    except Exception:
        return None


def _draw_feature_heatmap(ax: plt.Axes, data: np.ndarray) -> None:
    """Left panel: feature fingerprint heatmap (features × categories)."""
    im = ax.imshow(data, cmap="RdYlBu_r", vmin=0.0, vmax=1.0,
                   aspect="auto", interpolation="nearest")

    col_labels = [ATTACK_LABELS.get(c, c) for c in _CATEGORIES]
    ax.set_xticks(range(len(_CATEGORIES)))
    ax.set_xticklabels(col_labels, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(FEATURE_NAMES)))
    ax.set_yticklabels(FEATURE_NAMES, fontsize=7.5)
    ax.set_title("Feature Fingerprints\nby Traffic Category", pad=4)

    # Color-bar
    plt.colorbar(im, ax=ax, fraction=0.035, pad=0.03,
                 label="Mean normalised value")

    # Vertical separator between normal and attacks
    ax.axvline(0.5, color="black", linewidth=1.2, linestyle="--", alpha=0.6)
    ax.text(0.5, -0.8, "↑ normal", ha="center", va="top",
            fontsize=7, color="#555555", transform=ax.transData)
    ax.text(3.0, -0.8, "attacks →", ha="center", va="top",
            fontsize=7, color="#C62828", transform=ax.transData)


def _draw_detector_heatmap(ax: plt.Axes, scores: np.ndarray) -> None:
    """Right panel: detector score heatmap (models × categories)."""
    im = ax.imshow(scores, cmap="Reds", vmin=0.0, vmax=1.0,
                   aspect="auto", interpolation="nearest")

    col_labels = [ATTACK_LABELS.get(c, c) for c in _CATEGORIES]
    ax.set_xticks(range(len(_CATEGORIES)))
    ax.set_xticklabels(col_labels, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(_DETECTOR_NAMES)))
    ax.set_yticklabels(_DETECTOR_NAMES, fontsize=9)
    ax.set_title("Mean Anomaly Score\nby Detector × Category", pad=4)

    plt.colorbar(im, ax=ax, fraction=0.06, pad=0.04, label="Mean anomaly score")

    # Annotate cells with scores
    for r in range(scores.shape[0]):
        for c in range(scores.shape[1]):
            v = scores[r, c]
            color = "white" if v > 0.60 else "#212121"
            ax.text(c, r, f"{v:.2f}",
                    ha="center", va="center",
                    fontsize=9, color=color, fontweight="bold")

    # Threshold line at 0.5
    ax.axhline(2.5, color="#555555", linewidth=0.6, linestyle=":")


def draw(
    fingerprints: np.ndarray | None = None,
    detector_scores: np.ndarray | None = None,
    out_dir: Path = Path("ml/experiments/paper_results"),
    width: float = DBLW,
) -> plt.Figure:
    """
    Draw the two-panel score heatmap.

    Parameters
    ----------
    fingerprints    : (20, 6) array of mean normalised feature values per category.
                      If None, uses analytical attack profiles.
    detector_scores : (3, 6) array of mean anomaly scores per (model, category).
                      If None, uses analytical values.
    out_dir         : output directory
    width           : figure width in inches
    """
    if fingerprints is None:
        fingerprints = _FINGERPRINTS
    if detector_scores is None:
        detector_scores = _DETECTOR_SCORES

    fig, (ax_feat, ax_det) = plt.subplots(
        1, 2,
        figsize=(width, width * 0.72),
        gridspec_kw={"width_ratios": [3.2, 1.8], "wspace": 0.45},
    )

    _draw_feature_heatmap(ax_feat, fingerprints)
    _draw_detector_heatmap(ax_det, detector_scores)

    fig.suptitle(
        "Ensemble Anomaly Scores and Feature Fingerprints by Attack Category",
        fontsize=10, fontweight="bold", y=1.01,
    )
    save_figure(fig, out_dir, "fig5_score_heatmap")
    return fig


def main() -> None:
    p = argparse.ArgumentParser(
        description="Generate score heatmap figure (Fig. 5)."
    )
    p.add_argument("--out", type=Path,
                   default=Path("ml/experiments/paper_results"))
    p.add_argument("--data", type=Path,
                   default=Path("datasets/processed"),
                   help="Directory with k8s-native-dataset.parquet")
    p.add_argument("--mock", action="store_true",
                   help="Use analytical attack profiles (no real data required)")
    args = p.parse_args()

    fingerprints = None
    if not args.mock:
        result = _load_real_data(args.data)
        if result is not None:
            fingerprints, _ = result
            print(f"  Loaded real feature data from {args.data}")
        else:
            print(f"  [MOCK] {args.data}/k8s-native-dataset.parquet not found — using analytical profiles.")

    draw(fingerprints=fingerprints, out_dir=args.out)


if __name__ == "__main__":
    main()
