#!/usr/bin/env python3
"""
build-k8s-dataset.py — Parse Zeek conn.log captures → labelled Parquet dataset.

Reads all ``datasets/raw/*.log`` files, extracts the canonical 20-feature
vector from each Zeek flow record (mirroring ``ml/zeek/flow-to-features.py``),
infers the binary label and subcategory from the filename, applies
MinMaxScaler fitted on normal flows only, and writes:

  datasets/processed/k8s-native-dataset.parquet
  datasets/processed/k8s-scaler.joblib        (for future test-set scaling)

The scaler is fitted on normal traffic only so that [0, 1] calibrates to
benign behaviour; attack flows may produce out-of-range values, which is
informative for the anomaly detection models.

Filename → label mapping
------------------------
  normal-*.log                → label=0, subcategory="normal"
  attack-portscan-*.log       → label=1, subcategory="portscan"
  attack-dos-*.log            → label=1, subcategory="dos"
  attack-brute_force-*.log    → label=1, subcategory="brute_force"
  attack-lateral_movement-*.log → label=1, subcategory="lateral_movement"
  attack-bkash_scenario-*.log → label=1, subcategory="bkash_scenario"

Usage
-----
    python3 datasets/capture/build-k8s-dataset.py
    python3 datasets/capture/build-k8s-dataset.py \\
        --raw-dir  datasets/raw \\
        --output   datasets/processed/k8s-native-dataset.parquet \\
        --scaler   datasets/processed/k8s-scaler.joblib \\
        --no-scale          # skip MinMaxScaler (raw features)
        --pretty            # verbose feature-distribution table
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from itertools import islice
from pathlib import Path
from typing import Iterator

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

# ---------------------------------------------------------------------------
# Repo root on sys.path so ``datasets.*`` imports work
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Import canonical feature list from the existing preprocessor for DRY-ness
try:
    from datasets.unsw_nb15.preprocess import FEATURE_COLS
except ImportError:
    FEATURE_COLS = [
        "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
        "proto_tcp", "proto_udp", "proto_icmp",
        "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
        "service_http", "service_dns", "service_ssl",
        "bytes_per_pkt_orig", "bytes_per_pkt_resp",
    ]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Zeek field helpers — mirrors ml/zeek/flow-to-features.py
# ---------------------------------------------------------------------------

def _safe_float(value: object, default: float = 0.0) -> float:
    if value is None or value in ("-", ""):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_features_json(rec: dict) -> list[float] | None:
    """
    Extract 20 canonical features from a Zeek conn.log JSON record.

    Returns None for records that are not complete flows (e.g., Zeek headers).
    """
    proto    = (rec.get("proto") or "").lower()
    state    = (rec.get("conn_state") or "").upper()
    service  = (rec.get("service") or "").lower()

    orig_bytes = _safe_float(rec.get("orig_bytes"))
    resp_bytes = _safe_float(rec.get("resp_bytes"))
    orig_pkts  = _safe_float(rec.get("orig_pkts"))
    resp_pkts  = _safe_float(rec.get("resp_pkts"))

    return [
        _safe_float(rec.get("duration")),
        orig_bytes,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        _safe_float(rec.get("orig_ip_bytes")),
        _safe_float(rec.get("resp_ip_bytes")),
        _safe_float(rec.get("missed_bytes")),
        # proto one-hot
        1.0 if proto == "tcp"  else 0.0,
        1.0 if proto == "udp"  else 0.0,
        1.0 if proto in ("icmp", "icmpv6") else 0.0,
        # conn_state one-hot
        1.0 if state == "S0"   else 0.0,
        1.0 if state == "SF"   else 0.0,
        1.0 if state == "REJ"  else 0.0,
        1.0 if state == "RSTO" else 0.0,
        # service one-hot
        1.0 if service in ("http", "https")    else 0.0,
        1.0 if service == "dns"                else 0.0,
        1.0 if service in ("ssl", "tls")       else 0.0,
        # derived: bytes per packet
        orig_bytes / orig_pkts if orig_pkts > 0 else 0.0,
        resp_bytes / resp_pkts if resp_pkts > 0 else 0.0,
    ]


# ---------------------------------------------------------------------------
# Zeek log parsers
# ---------------------------------------------------------------------------

def _parse_zeek_json(path: Path) -> Iterator[dict]:
    """Yield records from a Zeek conn.log in JSON format (one object per line)."""
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _parse_zeek_tsv(path: Path) -> Iterator[dict]:
    """Yield records from a Zeek conn.log in TSV format."""
    fields: list[str] = []
    unset_field = "-"
    empty_field = "(empty)"

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields\t"):
                fields = line.split("\t")[1:]
            elif line.startswith("#unset_field\t"):
                unset_field = line.split("\t")[1]
            elif line.startswith("#empty_field\t"):
                empty_field = line.split("\t")[1]
            elif line.startswith("#"):
                continue
            elif fields:
                values = line.split("\t")
                yield {
                    k: (None if v in (unset_field, empty_field) else v)
                    for k, v in zip(fields, values)
                }


def _detect_format(path: Path) -> str:
    """Return 'json' or 'tsv' by peeking at the first non-blank, non-#separator line."""
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in islice(fh, 50):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#separator"):
                return "tsv"
            if line.startswith("{"):
                return "json"
            if line.startswith("#fields") or line.startswith("#types"):
                return "tsv"
    return "tsv"   # default


def iter_records(path: Path) -> Iterator[dict]:
    fmt = _detect_format(path)
    if fmt == "json":
        yield from _parse_zeek_json(path)
    else:
        yield from _parse_zeek_tsv(path)


# ---------------------------------------------------------------------------
# Filename → label inference
# ---------------------------------------------------------------------------

_SUBCATEGORY_MAP = {
    "normal":             (0, "normal"),
    "portscan":           (1, "portscan"),
    "dos":                (1, "dos"),
    "brute_force":        (1, "brute_force"),
    "lateral_movement":   (1, "lateral_movement"),
    "bkash_scenario":     (1, "bkash_scenario"),
}


def infer_label(path: Path) -> tuple[int, str] | None:
    """
    Parse label and subcategory from filename.

    Returns ``(label_int, subcategory_str)`` or ``None`` for unrecognised files.
    """
    stem = path.stem  # e.g. "normal-20260619-143022" or "attack-portscan-20260619-150000"

    if stem.startswith("normal-"):
        return 0, "normal"

    if stem.startswith("attack-"):
        parts = stem.split("-", 2)   # ["attack", "<type>", "<timestamp>"]
        if len(parts) >= 2:
            sub = parts[1]
            if sub in _SUBCATEGORY_MAP:
                return _SUBCATEGORY_MAP[sub]

    return None


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def parse_log_file(path: Path) -> tuple[list[list[float]], int, str]:
    """
    Parse one Zeek log file into feature rows.

    Returns ``(rows, label, subcategory)`` where each row is a list of 20 floats.
    Rows where all features are zero are dropped (Zeek protocol packets, etc.).
    """
    label_info = infer_label(path)
    if label_info is None:
        log.warning("Skipping unrecognised file: %s", path.name)
        return [], -1, ""

    label, subcategory = label_info
    rows: list[list[float]] = []
    skipped = 0

    for rec in iter_records(path):
        features = _extract_features_json(rec)
        if features is None:
            skipped += 1
            continue
        # Drop zero-sum records (Zeek metadata lines, zero-duration probes)
        if sum(features) == 0.0:
            skipped += 1
            continue
        rows.append(features)

    log.info(
        "  %s → %d flows  (label=%d, sub=%s, skipped=%d)",
        path.name, len(rows), label, subcategory, skipped,
    )
    return rows, label, subcategory


def build_dataframe(raw_dir: Path) -> pd.DataFrame:
    """Load all *.log files from raw_dir and return a combined DataFrame."""
    log_files = sorted(raw_dir.glob("*.log"))
    if not log_files:
        log.error("No .log files found in %s", raw_dir)
        sys.exit(2)

    all_rows: list[list[float]] = []
    all_labels: list[int] = []
    all_subcats: list[str] = []
    all_sources: list[str] = []

    for path in log_files:
        rows, label, subcategory = parse_log_file(path)
        if label == -1:
            continue
        all_rows.extend(rows)
        all_labels.extend([label] * len(rows))
        all_subcats.extend([subcategory] * len(rows))
        all_sources.extend([path.name] * len(rows))

    if not all_rows:
        log.error("No valid flow records found across all log files.")
        sys.exit(2)

    df = pd.DataFrame(all_rows, columns=FEATURE_COLS, dtype=np.float32)
    df["label"]       = np.array(all_labels, dtype=np.int8)
    df["subcategory"] = all_subcats
    df["source_file"] = all_sources

    # Replace Inf/-Inf with 0 (malformed flows)
    df[FEATURE_COLS] = df[FEATURE_COLS].replace([np.inf, -np.inf], 0.0).fillna(0.0)

    return df


def scale_features(
    df: pd.DataFrame,
    scaler_path: Path | None,
    skip_scale: bool,
) -> tuple[pd.DataFrame, MinMaxScaler | None]:
    """
    Fit MinMaxScaler on normal flows, apply to all rows.

    The scaler is fitted only on normal (label=0) rows so that the [0,1]
    range calibrates to benign behaviour — attack flows may exceed 1.0,
    which preserves anomaly signal in the scaled representation.
    """
    if skip_scale:
        return df, None

    normal_mask = df["label"] == 0
    if normal_mask.sum() == 0:
        log.warning("No normal flows found — fitting scaler on all data.")
        normal_mask = pd.Series(True, index=df.index)

    scaler = MinMaxScaler()
    scaler.fit(df.loc[normal_mask, FEATURE_COLS].values)
    df[FEATURE_COLS] = scaler.transform(df[FEATURE_COLS].values).astype(np.float32)

    log.info(
        "MinMaxScaler fitted on %d normal flows, applied to %d total rows.",
        normal_mask.sum(), len(df),
    )

    if scaler_path is not None:
        scaler_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(scaler, scaler_path)
        log.info("Scaler saved → %s", scaler_path)

    return df, scaler


# ---------------------------------------------------------------------------
# Statistics printer
# ---------------------------------------------------------------------------

def print_stats(df: pd.DataFrame, output_path: Path, pretty: bool) -> None:
    total      = len(df)
    n_normal   = int((df["label"] == 0).sum())
    n_attack   = int((df["label"] == 1).sum())
    pct_attack = n_attack / total * 100 if total else 0.0

    print()
    print("━" * 66)
    print("  k8s-native-dataset  —  Statistics")
    print("━" * 66)
    print(f"  Output   : {output_path}")
    print(f"  Rows     : {total:,}")
    print(f"  Normal   : {n_normal:,}  ({100 - pct_attack:.1f}%)")
    print(f"  Attack   : {n_attack:,}  ({pct_attack:.1f}%)")
    print()

    if n_attack > 0:
        sub_counts = df[df["label"] == 1]["subcategory"].value_counts()
        print("  Attack subcategories:")
        for sub, count in sub_counts.items():
            pct = count / n_attack * 100
            print(f"    {sub:<25} {count:>7,}  ({pct:.1f}%)")
        print()

    if pretty:
        print(f"  {'Feature':<24}  {'min':>10}  {'median':>10}  {'max':>10}  {'miss%':>6}")
        print(f"  {'-'*24}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*6}")
        for col in FEATURE_COLS:
            s = df[col]
            miss_pct = s.isna().mean() * 100
            print(
                f"  {col:<24}  {s.min():>10.4f}  {s.median():>10.4f}"
                f"  {s.max():>10.4f}  {miss_pct:>5.1f}%"
            )
        print()

    # Class-balance advisory
    ratio = n_attack / n_normal if n_normal > 0 else float("inf")
    if ratio < 0.2:
        print(f"  ⚠ Class imbalance: attack/normal = {ratio:.2f}")
        print("    Consider: oversampling attack flows or class_weight='balanced'")
    elif ratio > 2.0:
        print(f"  ⚠ Attack-heavy: attack/normal = {ratio:.2f}")
        print("    Consider collecting more normal traffic (capture-normal-traffic.sh).")

    print("━" * 66)
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build k8s-native-dataset.parquet from Zeek conn.log captures.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--raw-dir",
        type=Path,
        default=Path("datasets/raw"),
        help="Directory containing captured *.log files.",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("datasets/processed/k8s-native-dataset.parquet"),
        help="Output Parquet path.",
    )
    p.add_argument(
        "--scaler",
        type=Path,
        default=Path("datasets/processed/k8s-scaler.joblib"),
        help="Save MinMaxScaler (fitted on normal flows) to this path.",
    )
    p.add_argument(
        "--no-scale",
        action="store_true",
        help="Skip MinMaxScaler; write raw feature values.",
    )
    p.add_argument(
        "--pretty",
        action="store_true",
        help="Print full per-feature distribution table.",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    log.info("Scanning %s for Zeek log files…", args.raw_dir)
    if not args.raw_dir.is_dir():
        log.error("raw-dir not found: %s", args.raw_dir)
        log.error("Run capture-normal-traffic.sh and capture-attack-traffic.sh first.")
        sys.exit(2)

    df = build_dataframe(args.raw_dir)
    df, _ = scale_features(df, None if args.no_scale else args.scaler, args.no_scale)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.output, index=False, compression="snappy")
    log.info("Dataset written → %s  (%d rows, %d columns)", args.output, len(df), len(df.columns))

    print_stats(df, args.output, args.pretty)


if __name__ == "__main__":
    main()
