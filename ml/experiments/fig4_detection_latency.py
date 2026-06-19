"""
fig4_detection_latency.py — CDF of mean time to detect (MTTD) across scenarios.

Two sub-plots side by side:
  Left  — bar chart of per-scenario MTTD (from attack-sim results)
  Right — empirical CDF of ensemble per-sample ML inference latency (µs)

The left panel answers "how quickly does the framework detect each attack?"
The right panel answers "what is the per-sample scoring cost in production?"

Data sources
------------
Left  : ``mttd_data``  dict mapping scenario label → seconds (from collect-results.py)
Right : ``latency_us`` dict mapping model key → ndarray of µs latencies

Usage
-----
    python -m ml.experiments.fig4_detection_latency --out ml/experiments/paper_results
    python -m ml.experiments.fig4_detection_latency --mock
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ml.experiments._paper_style import (
    apply_ieee_style, save_figure, PALETTE, ATTACK_LABELS,
    DBLW, _rng,
)

apply_ieee_style()

# Default placeholder MTTD values (seconds) per scenario
_MOCK_MTTD = {
    "portscan"         : 28.0,
    "dos"              : 45.0,
    "brute_force"      : 12.0,
    "lateral_movement" : 18.0,
    "bkash_scenario"   : 36.0,
}

# Detection baseline for the "zero-trust blocked before ML" distinction
_MOCK_ZT_BLOCKED = {
    "portscan"         : False,
    "dos"              : False,
    "brute_force"      : True,   # SSH blocked by mTLS strict
    "lateral_movement" : True,
    "bkash_scenario"   : True,
}

# Approximate per-sample inference latency (µs) per model on CPU
_MOCK_LATENCY_US = {
    "iforest"  : 2.8,
    "lstm_ae"  : 18.4,
    "ensemble" : 21.7,
    "svm"      : 0.8,
    "rf"       : 4.1,
}


def _mock_latency_arrays(
    n: int = 5000,
) -> dict[str, np.ndarray]:
    """Generate synthetic per-sample latency arrays with realistic variance."""
    rng = _rng(42)
    out: dict[str, np.ndarray] = {}
    for key, mean_us in _MOCK_LATENCY_US.items():
        # Lognormal latency is more realistic than Gaussian (skewed right)
        log_mean = np.log(mean_us) - 0.5 * 0.25 ** 2
        out[key] = rng.lognormal(log_mean, 0.25, size=n).astype(np.float32)
    return out


def _draw_mttd_bars(
    ax: plt.Axes,
    mttd_data: dict[str, float],
    zt_blocked: dict[str, bool],
) -> None:
    """Bar chart of MTTD per attack scenario, coloured by detection mechanism."""
    scenarios = list(mttd_data.keys())
    mttd_vals = [mttd_data[s] for s in scenarios]
    x = np.arange(len(scenarios))

    for i, (sc, val) in enumerate(zip(scenarios, mttd_vals)):
        color = PALETTE.get(sc, "#888888")
        hatch = "//" if zt_blocked.get(sc, False) else ""
        ax.bar(
            i, val,
            color=color, alpha=0.80,
            width=0.55, hatch=hatch,
            edgecolor="white", linewidth=0.5,
        )
        # Value label on top
        ax.text(i, val + 0.8, f"{val:.0f}s",
                ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(
        [ATTACK_LABELS.get(s, s) for s in scenarios],
        rotation=28, ha="right", fontsize=8,
    )
    ax.set_ylabel("MTTD (seconds)")
    ax.set_title("Mean Time to Detect\nper Attack Scenario", pad=4)
    ax.set_ylim(0, max(mttd_vals) * 1.20 + 5)
    ax.grid(axis="y", linewidth=0.5, alpha=0.4)
    ax.spines["bottom"].set_visible(True)

    # Legend: hatching = zero-trust also contributed
    import matplotlib.patches as mpatches
    handles = [
        mpatches.Patch(facecolor="#aaaaaa", alpha=0.8, label="ML-only detection"),
        mpatches.Patch(facecolor="#aaaaaa", alpha=0.8, hatch="//",
                       label="ZT policy + ML"),
    ]
    ax.legend(handles=handles, fontsize=7.5, loc="upper right",
              framealpha=0.9, handlelength=1.5)


def _draw_latency_cdf(
    ax: plt.Axes,
    latency_us: dict[str, np.ndarray],
) -> None:
    """Empirical CDF of per-sample inference latency."""
    _ORDER = ["svm", "rf", "iforest", "lstm_ae", "ensemble"]
    _STYLES = {
        "svm"      : dict(linestyle=":",  linewidth=1.0, alpha=0.85),
        "rf"       : dict(linestyle="-.", linewidth=1.0, alpha=0.85),
        "iforest"  : dict(linestyle="--", linewidth=1.4),
        "lstm_ae"  : dict(linestyle="--", linewidth=1.4),
        "ensemble" : dict(linestyle="-",  linewidth=2.0),
    }
    _LABELS = {
        "iforest"  : "Isolation Forest",
        "lstm_ae"  : "LSTM-AE",
        "ensemble" : "Ensemble (Ours)",
        "svm"      : "SVM",
        "rf"       : "Random Forest",
    }

    p99_ensemble = None
    for key in _ORDER:
        if key not in latency_us:
            continue
        lats = np.sort(latency_us[key])
        cdf  = np.arange(1, len(lats) + 1) / len(lats)
        p50  = float(np.percentile(lats, 50))
        p99  = float(np.percentile(lats, 99))
        label = f"{_LABELS[key]} (P50={p50:.1f}µs)"
        ax.plot(lats, cdf, color=PALETTE[key], label=label, **_STYLES[key])
        if key == "ensemble":
            p99_ensemble = p99

    if p99_ensemble is not None:
        ax.axvline(p99_ensemble, color=PALETTE["ensemble"],
                   linewidth=0.9, linestyle=":", alpha=0.7)
        ax.text(p99_ensemble + 0.3, 0.10,
                f"P99={p99_ensemble:.1f}µs",
                color=PALETTE["ensemble"], fontsize=7.5, va="bottom")

    ax.set_xlabel("Per-Sample Latency (µs)")
    ax.set_ylabel("Cumulative Probability")
    ax.set_title("Inference Latency CDF\n(UNSW-NB15 Test Set, CPU)", pad=4)
    ax.set_ylim(0, 1.02)
    ax.set_xlim(left=0)
    ax.grid(True)
    ax.legend(fontsize=7.5, loc="lower right", framealpha=0.9)


def draw(
    mttd_data: dict[str, float],
    latency_us: dict[str, np.ndarray],
    zt_blocked: dict[str, bool] | None = None,
    out_dir: Path = Path("ml/experiments/paper_results"),
    width: float = DBLW,
) -> plt.Figure:
    """
    Draw two-panel detection latency figure.

    Parameters
    ----------
    mttd_data  : scenario key → MTTD in seconds (from attack-sim results)
    latency_us : model key → per-sample latency array in microseconds
    zt_blocked : optional, scenario key → True if ZT policy also triggered
    out_dir    : output directory
    width      : figure width in inches
    """
    if zt_blocked is None:
        zt_blocked = {k: False for k in mttd_data}

    fig, (ax_bar, ax_cdf) = plt.subplots(
        1, 2, figsize=(width, width * 0.42),
        gridspec_kw={"wspace": 0.38},
    )

    _draw_mttd_bars(ax_bar, mttd_data, zt_blocked)
    _draw_latency_cdf(ax_cdf, latency_us)

    fig.suptitle("Detection Latency Analysis", fontsize=10, fontweight="bold", y=1.02)
    save_figure(fig, out_dir, "fig4_detection_latency")
    return fig


def main() -> None:
    p = argparse.ArgumentParser(
        description="Generate detection latency figure (Fig. 4)."
    )
    p.add_argument("--out", type=Path,
                   default=Path("ml/experiments/paper_results"))
    p.add_argument("--mock", action="store_true",
                   help="Use synthetic data (no models/results required)")
    args = p.parse_args()

    print("[MOCK] Using synthetic MTTD and latency data.")
    draw(
        mttd_data=_MOCK_MTTD,
        latency_us=_mock_latency_arrays(),
        zt_blocked=_MOCK_ZT_BLOCKED,
        out_dir=args.out,
    )


if __name__ == "__main__":
    main()
