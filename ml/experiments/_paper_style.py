"""
Shared IEEE publication style constants and helpers for paper_results figures.

Import pattern in each figure module:
    from ml.experiments._paper_style import apply_ieee_style, PALETTE, save_figure
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# IEEE figure dimensions (inches)
# ---------------------------------------------------------------------------
COL_W  = 3.5    # single column
DBLW   = 7.16   # double column / full-width
DPI    = 300

# ---------------------------------------------------------------------------
# Color palette (consistent across all figures)
# ---------------------------------------------------------------------------
PALETTE: dict[str, str] = {
    "iforest"          : "#1565C0",   # dark blue
    "lstm_ae"          : "#E65100",   # dark orange
    "ensemble"         : "#2E7D32",   # dark green  — our method
    "svm"              : "#6A1B9A",   # dark purple
    "rf"               : "#4E342E",   # dark brown
    "normal"           : "#78909C",   # blue-grey
    "attack"           : "#C62828",   # dark red
    "portscan"         : "#1565C0",
    "dos"              : "#C62828",
    "brute_force"      : "#E65100",
    "lateral_movement" : "#6A1B9A",
    "bkash_scenario"   : "#2E7D32",
}

MODEL_LABELS: dict[str, str] = {
    "iforest"  : "Isolation Forest",
    "lstm_ae"  : "LSTM-AE",
    "ensemble" : "Ensemble (Ours)",
    "svm"      : "SVM (Baseline)",
    "rf"       : "Random Forest (Baseline)",
}

ATTACK_LABELS: dict[str, str] = {
    "normal"           : "Normal",
    "portscan"         : "Port Scan",
    "dos"              : "DoS Flood",
    "brute_force"      : "SSH Brute Force",
    "lateral_movement" : "Lateral Movement",
    "bkash_scenario"   : "bKash Scenario",
}

# ---------------------------------------------------------------------------
# IEEE publication rcParams
# ---------------------------------------------------------------------------
IEEE_RCPARAMS: dict = {
    # Typography
    "font.family"       : "serif",
    "font.serif"        : ["Times New Roman", "Times", "STIXGeneral", "DejaVu Serif"],
    "font.size"         : 10,
    "axes.labelsize"    : 10,
    "axes.titlesize"    : 10,
    "xtick.labelsize"   : 9,
    "ytick.labelsize"   : 9,
    "legend.fontsize"   : 9,
    "legend.framealpha" : 0.92,
    "legend.edgecolor"  : "#cccccc",
    # Lines and grids
    "lines.linewidth"   : 1.5,
    "axes.linewidth"    : 0.8,
    "grid.linewidth"    : 0.5,
    "grid.alpha"        : 0.35,
    "grid.color"        : "#cccccc",
    # Spines — top/right removed for clean look
    "axes.spines.top"   : False,
    "axes.spines.right" : False,
    # Colors
    "figure.facecolor"  : "white",
    "axes.facecolor"    : "white",
    # PDF/PS: embed TrueType fonts (required for IEEE Xplore PDF submission)
    "pdf.fonttype"      : 42,
    "ps.fonttype"       : 42,
    # Save
    "savefig.dpi"       : DPI,
    "savefig.bbox"      : "tight",
}


def apply_ieee_style() -> None:
    """Apply IEEE rcParams globally. Call once at module level in each figure script."""
    matplotlib.rcParams.update(IEEE_RCPARAMS)


def save_figure(fig: plt.Figure, out_dir: Path, stem: str) -> None:
    """Save figure as PDF (paper) and PNG (preview / README) at 300 DPI."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        dest = out_dir / f"{stem}.{ext}"
        fig.savefig(dest, bbox_inches="tight", dpi=DPI)
        print(f"  → {dest}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# LaTeX table formatter (IEEE booktabs style)
# ---------------------------------------------------------------------------

def _bold(s: str) -> str:
    return r"\textbf{" + str(s) + "}"


def _check() -> str:
    return r"\checkmark"


def _cross() -> str:
    return r"\texttimes"


def to_booktabs(
    headers: list[str],
    rows: list[list],
    caption: str,
    label: str,
    col_fmt: str | None = None,
    bold_row: int | None = None,
    note: str | None = None,
) -> str:
    """
    Render a LaTeX table using booktabs and the ``table`` environment.

    Parameters
    ----------
    headers : column header strings
    rows    : data rows (each row is a list of values; use raw strings for LaTeX markup)
    caption : LaTeX caption text
    label   : LaTeX \\label tag (without the ``tab:`` prefix — that is added here)
    col_fmt : ColumnTransformer format string, e.g. ``"lrrrrc"``.
              If None, first column is left-aligned, rest are right-aligned.
    bold_row : row index (0-based) to bold all cells
    note    : optional footnote appended below \\bottomrule
    """
    n_cols = len(headers)
    if col_fmt is None:
        col_fmt = "l" + "r" * (n_cols - 1)

    lines: list[str] = [
        r"\begin{table}[h]",
        r"  \centering",
        f"  \\caption{{{caption}}}",
        f"  \\label{{tab:{label}}}",
        r"  \begin{tabular}{" + col_fmt + "}",
        r"    \toprule",
        "    " + " & ".join(_bold(h) for h in headers) + r" \\",
        r"    \midrule",
    ]

    for i, row in enumerate(rows):
        cells = [str(v) for v in row]
        if i == bold_row:
            cells = [_bold(c) for c in cells]
        lines.append("    " + " & ".join(cells) + r" \\")

    lines.append(r"    \bottomrule")
    if note:
        lines.append(
            r"    \multicolumn{" + str(n_cols) + r"}{l}{\small\textit{" + note + r"}} \\"
        )
    lines += [r"  \end{tabular}", r"\end{table}"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Synthetic mock-data generators (used when real models are unavailable)
# ---------------------------------------------------------------------------

def _rng(seed: int = 42) -> np.random.Generator:
    return np.random.default_rng(seed)


def mock_roc_curve(
    auc_target: float,
    n_points: int = 200,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, float]:
    """
    Generate a plausible synthetic ROC curve achieving approximately ``auc_target``.

    Uses a beta-distribution-based construction that produces smooth, convex curves.
    """
    rng = _rng(seed)
    fpr  = np.linspace(0, 1, n_points)
    # Power-law TPR gives AUC close to target
    power = np.log(0.5) / np.log(1.0 - auc_target + 0.5) if auc_target < 1 else 0.01
    tpr   = fpr ** max(power, 0.01)
    # Add small noise for realism
    noise = rng.normal(0, 0.005, size=n_points)
    tpr   = np.clip(tpr + noise, 0, 1)
    tpr   = np.sort(tpr)   # ensure monotone
    tpr[0], tpr[-1] = 0.0, 1.0
    actual_auc = float(np.trapz(tpr, fpr))
    return fpr, tpr, actual_auc


def mock_confusion_matrix(
    n_test: int,
    accuracy: float,
    recall: float,
    seed: int = 42,
) -> np.ndarray:
    """Generate a plausible 2×2 confusion matrix for ``n_test`` samples."""
    rng = _rng(seed)
    n_attack = int(n_test * 0.40)
    n_normal = n_test - n_attack
    tp = int(n_attack * recall)
    fn = n_attack - tp
    tn = int(n_normal * (2 * accuracy - recall))
    fp = n_normal - tn
    return np.array([[max(tn, 0), max(fp, 0)], [max(fn, 0), max(tp, 0)]])
