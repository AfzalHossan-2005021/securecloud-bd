"""
fig1_architecture.py — SecureCloud-BD system architecture diagram.

Programmatic matplotlib figure: no external images, no Graphviz.
The diagram shows four vertical layers connected by data-flow arrows:

    Network Collection → ML Detection → Policy Enforcement → SIEM

Usage
-----
    python -m ml.experiments.fig1_architecture --out ml/experiments/paper_results
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

from ml.experiments._paper_style import apply_ieee_style, save_figure, DBLW

apply_ieee_style()

# ---------------------------------------------------------------------------
# Layout constants (data coordinates over a [0, 10] × [0, 7] canvas)
# ---------------------------------------------------------------------------

_BG   = "white"

_LAYERS = [
    # (x_left, label, bg_color, border_color, items)
    (0.15, "Network\nCollection",    "#E3F2FD", "#1565C0", [
        "Minikube Cluster",
        "3 Namespaces",
        "(securecloud, siem, ml)",
        "",
        "Zeek 6.x",
        "Interface: br-* / eth0",
        "conn.log (JSONL)",
        "1 record / flow",
    ]),
    (2.65, "ML Detection",           "#E8F5E9", "#2E7D32", [
        "Feature Extraction",
        "20 Zeek fields → vector",
        "",
        "Isolation Forest",
        "weight = 0.40",
        "",
        "LSTM Autoencoder",
        "weight = 0.60",
        "",
        "Ensemble Score ∈ [0,1]",
        "threshold = 0.5",
    ]),
    (5.15, "Policy\nEnforcement",    "#FFF3E0", "#E65100", [
        "Istio Service Mesh",
        "mTLS STRICT (3 NS)",
        "default-deny AP",
        "",
        "OPA Gatekeeper",
        "ConstraintTemplates",
        "Admission Webhooks",
        "",
        "Falco Runtime",
        "Custom YAML rules",
        "SIEM integration",
    ]),
    (7.65, "SIEM &\nAlerting",       "#F3E5F5", "#6A1B9A", [
        "Elasticsearch",
        "Index: ml-scores-*",
        "",
        "Logstash",
        "Pipeline: scored flows",
        "",
        "Kibana",
        "Dashboards + alerts",
        "",
        "Filebeat DaemonSet",
    ]),
]

_BOX_W  = 2.35
_BOX_Y0 = 0.40
_BOX_Y1 = 6.60


def _layer_box(ax: plt.Axes, x: float, title: str, bg: str, border: str,
               items: list[str]) -> None:
    """Draw one layer: titled rectangle + content text."""
    # Outer box
    rect = FancyBboxPatch(
        (x, _BOX_Y0), _BOX_W, _BOX_Y1 - _BOX_Y0,
        boxstyle="round,pad=0.05",
        linewidth=1.5,
        edgecolor=border,
        facecolor=bg,
        zorder=2,
    )
    ax.add_patch(rect)

    # Title banner at top
    ax.text(
        x + _BOX_W / 2,
        _BOX_Y1 - 0.30,
        title,
        ha="center", va="center",
        fontsize=9, fontweight="bold",
        color=border,
        zorder=3,
    )

    # Horizontal rule below title
    ax.plot(
        [x + 0.12, x + _BOX_W - 0.12],
        [_BOX_Y1 - 0.62, _BOX_Y1 - 0.62],
        color=border, linewidth=0.8, alpha=0.6, zorder=3,
    )

    # Content items (small text, left-aligned within box)
    y_start = _BOX_Y1 - 0.90
    y_step  = 0.50
    for item in items:
        if not item:
            y_start -= y_step * 0.4
            continue
        is_header = not item.startswith(" ") and item[0].isupper() and ":" not in item
        ax.text(
            x + 0.16,
            y_start,
            item,
            ha="left", va="center",
            fontsize=7.5,
            fontweight="bold" if is_header else "normal",
            color="#212121" if is_header else "#424242",
            zorder=3,
        )
        y_start -= y_step


def _arrow(ax: plt.Axes, x0: float, x1: float, y: float,
           label: str = "", color: str = "#555555") -> None:
    """Draw a horizontal arrow between two layer boxes."""
    ax.annotate(
        "",
        xy=(x1, y), xytext=(x0, y),
        arrowprops=dict(
            arrowstyle="->,head_width=0.25,head_length=0.15",
            color=color,
            lw=1.4,
            connectionstyle="arc3,rad=0",
        ),
        zorder=4,
    )
    if label:
        ax.text(
            (x0 + x1) / 2, y + 0.22,
            label,
            ha="center", va="bottom",
            fontsize=7, color=color,
            style="italic",
            zorder=5,
        )


def _sub_box(ax: plt.Axes, x: float, y: float, w: float, h: float,
             text: str, color: str) -> None:
    """Draw a small highlighted sub-component box inside a layer."""
    r = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.04",
        linewidth=0.8,
        edgecolor=color,
        facecolor="white",
        zorder=4,
        alpha=0.9,
    )
    ax.add_patch(r)
    ax.text(
        x + w / 2, y + h / 2,
        text,
        ha="center", va="center",
        fontsize=7, color=color,
        fontweight="bold",
        zorder=5,
    )


def draw(out_dir: Path, width: float = DBLW) -> plt.Figure:
    """
    Draw the architecture diagram and save as PDF + PNG.

    Parameters
    ----------
    out_dir : directory where fig1_architecture.{pdf,png} will be written
    width   : figure width in inches (default: IEEE double-column = 7.16")
    """
    height = width * 0.55
    fig, ax = plt.subplots(figsize=(width, height))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")

    # ── Layer boxes ────────────────────────────────────────────────────────
    for x, title, bg, border, items in _LAYERS:
        _layer_box(ax, x, title, bg, border, items)

    # ── Sub-component boxes highlighting key components ─────────────────
    # IForest box inside ML Detection
    _sub_box(ax, 2.78, 3.10, 2.10, 0.55, "IForest  ×0.4", "#2E7D32")
    _sub_box(ax, 2.78, 2.40, 2.10, 0.55, "LSTM-AE  ×0.6", "#2E7D32")
    _sub_box(ax, 2.78, 1.65, 2.10, 0.55, "Ensemble Score", "#1B5E20")

    # ── Data-flow arrows between layers ────────────────────────────────
    gap   = 0.12
    arrow_y_top = 5.60
    arrow_y_mid = 3.20

    # Network → ML Detection
    _arrow(ax,
           0.15 + _BOX_W + gap, 2.65 - gap,
           arrow_y_top,
           label="conn.log\n(JSONL)", color="#1565C0")

    # ML Detection → Policy Enforcement
    _arrow(ax,
           2.65 + _BOX_W + gap, 5.15 - gap,
           arrow_y_top,
           label="score ≥ 0.5\n→ enforce", color="#2E7D32")

    # ML Detection → SIEM
    _arrow(ax,
           2.65 + _BOX_W + gap, 7.65 - gap,
           arrow_y_mid,
           label="scored\nflows", color="#6A1B9A")

    # Policy Enforcement → SIEM (event feed)
    _arrow(ax,
           5.15 + _BOX_W + gap, 7.65 - gap,
           arrow_y_top - 0.60,
           label="Falco\nalerts", color="#E65100")

    # ── Attacker annotation ────────────────────────────────────────────
    ax.annotate(
        "Attacker VM\n(Kali Linux)",
        xy=(0.15 + _BOX_W * 0.5, _BOX_Y1 + 0.08),
        xytext=(0.15 + _BOX_W * 0.5, _BOX_Y1 + 0.52),
        ha="center", va="bottom",
        fontsize=8, color="#B71C1C",
        arrowprops=dict(
            arrowstyle="->,head_width=0.20,head_length=0.12",
            color="#B71C1C",
            lw=1.2,
        ),
        zorder=5,
    )
    ax.text(
        0.15 + _BOX_W * 0.5, _BOX_Y1 + 0.56,
        "5 MITRE ATT&CK scenarios",
        ha="center", va="bottom",
        fontsize=7, color="#B71C1C", style="italic",
        zorder=5,
    )

    # ── Legend annotation ──────────────────────────────────────────────
    legend_patches = [
        mpatches.Patch(facecolor="#E3F2FD", edgecolor="#1565C0", label="Traffic Collection"),
        mpatches.Patch(facecolor="#E8F5E9", edgecolor="#2E7D32", label="ML Detection (Novel)"),
        mpatches.Patch(facecolor="#FFF3E0", edgecolor="#E65100", label="Policy Enforcement"),
        mpatches.Patch(facecolor="#F3E5F5", edgecolor="#6A1B9A", label="SIEM & Alerting"),
    ]
    ax.legend(
        handles=legend_patches,
        loc="lower center",
        ncol=4,
        bbox_to_anchor=(0.5, -0.04),
        framealpha=0.95,
        fontsize=8,
        handlelength=1.2,
        handleheight=0.9,
    )

    fig.suptitle(
        "SecureCloud-BD: Kubernetes-Native Threat Detection Framework",
        fontsize=11, fontweight="bold", y=1.01,
    )
    fig.tight_layout()

    save_figure(fig, out_dir, "fig1_architecture")
    return fig


def main() -> None:
    p = argparse.ArgumentParser(description="Generate architecture diagram (Fig. 1).")
    p.add_argument("--out", type=Path,
                   default=Path("ml/experiments/paper_results"))
    args = p.parse_args()
    draw(args.out)


if __name__ == "__main__":
    main()
