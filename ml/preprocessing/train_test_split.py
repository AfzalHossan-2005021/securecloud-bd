"""
Stratified 80/10/10 train / val / test split for UNSW-NB15.

Reads the raw CSV parts, applies ``FeatureEngineeringPipeline``, and writes
three parquet files to ``ml/data/processed/``:

    train.parquet   — 80 % of rows
    val.parquet     — 10 % of rows
    test.parquet    — 10 % of rows

Each parquet file contains the full float32 feature matrix **plus** a ``label``
column (int8, binary) so that evaluation scripts can load a single file rather
than two.  The pipeline object is serialised alongside the splits at
``ml/data/processed/feature_pipeline.joblib`` so that identical preprocessing
can be applied to new data at inference time.

Stratification is performed on the binary ``label`` column, preserving the
~44 % / ~56 % attack / normal ratio in every split.

Usage
-----
Standalone script::

    python ml/preprocessing/train_test_split.py \\
        --raw-dir  ml/data/raw/unsw_nb15 \\
        --out-dir  ml/data/processed \\
        --val-size 0.10 \\
        --test-size 0.10 \\
        --seed 42

Library call::

    from ml.preprocessing.train_test_split import run_split
    run_split(raw_dir="ml/data/raw/unsw_nb15", out_dir="ml/data/processed")
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.preprocessing.feature_engineering import FeatureEngineeringPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# Column names for all 49 UNSW-NB15 columns (including label).
# The CSV parts have no header row, so we assign names manually.
UNSW_NB15_COLUMNS: list[str] = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur",
    "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service",
    "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb",
    "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt",
    "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src",
    "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]


def load_raw(raw_dir: str | Path) -> pd.DataFrame:
    """
    Load and concatenate all UNSW-NB15 CSV parts from *raw_dir*.

    Scans ``raw_dir`` for files matching ``UNSW-NB15_*.csv`` and loads them
    in alphabetical order.  Column names are assigned from
    ``UNSW_NB15_COLUMNS`` since the CSV parts contain no header row.

    Parameters
    ----------
    raw_dir : str | Path
        Directory containing ``UNSW-NB15_1.csv`` … ``UNSW-NB15_4.csv``.

    Returns
    -------
    pd.DataFrame
        Concatenated DataFrame with ``UNSW_NB15_COLUMNS`` as column names
        and a ``_source_part`` column added for traceability.

    Raises
    ------
    FileNotFoundError
        If no matching CSV files are found in *raw_dir*.
    """
    raw_dir = Path(raw_dir)
    csv_files = sorted(raw_dir.glob("UNSW-NB15_*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No UNSW-NB15_*.csv files found in {raw_dir}.\n"
            "Run: bash ml/data/download-datasets.sh --unsw-only"
        )

    parts: list[pd.DataFrame] = []
    for i, path in enumerate(csv_files, start=1):
        df_part = pd.read_csv(
            path,
            header=None,
            names=UNSW_NB15_COLUMNS,
            low_memory=False,
            encoding="latin-1",
        )
        df_part["_source_part"] = i
        parts.append(df_part)
        log.info("  Loaded %s: %d rows", path.name, len(df_part))

    df = pd.concat(parts, ignore_index=True)
    log.info("Combined: %d rows × %d columns", *df.shape)
    return df


def _stratified_split(
    X: np.ndarray,
    y: np.ndarray,
    val_size: float,
    test_size: float,
    random_state: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Perform a two-stage stratified split to produce 80 / 10 / 10 partitions.

    The split is done in two stages to preserve the class ratio in all three
    partitions:

    Stage 1
        Separate *test_size* of the data as the held-out test set.

    Stage 2
        From the remaining data, separate ``val_size / (1 - test_size)``
        as the validation set, leaving ``train_size`` as training data.

    Parameters
    ----------
    X : np.ndarray, shape (n_samples, n_features)
        Feature matrix.
    y : np.ndarray, shape (n_samples,)
        Binary labels (0 = normal, 1 = attack).
    val_size : float
        Fraction of the full dataset to use for validation (default 0.10).
    test_size : float
        Fraction of the full dataset to use for testing (default 0.10).
    random_state : int
        Seed for reproducibility.

    Returns
    -------
    tuple of six arrays
        ``(X_train, X_val, X_test, y_train, y_val, y_test)``
    """
    # Stage 1: carve out the test set.
    splitter1 = StratifiedShuffleSplit(
        n_splits=1, test_size=test_size, random_state=random_state
    )
    train_val_idx, test_idx = next(splitter1.split(X, y))

    X_train_val, y_train_val = X[train_val_idx], y[train_val_idx]
    X_test, y_test           = X[test_idx],      y[test_idx]

    # Stage 2: split train+val into train / val.
    # val fraction relative to the remaining (1 - test_size) of the data.
    val_size_adj = val_size / (1.0 - test_size)
    splitter2 = StratifiedShuffleSplit(
        n_splits=1, test_size=val_size_adj, random_state=random_state
    )
    train_idx, val_idx = next(splitter2.split(X_train_val, y_train_val))

    X_train, y_train = X_train_val[train_idx], y_train_val[train_idx]
    X_val,   y_val   = X_train_val[val_idx],   y_train_val[val_idx]

    return X_train, X_val, X_test, y_train, y_val, y_test


def _save_split(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    path: Path,
) -> None:
    """
    Write a feature matrix and labels to a parquet file.

    The parquet file contains one column per feature (named from
    *feature_names*) plus a ``label`` column (int8).  Using parquet
    preserves dtypes across reads, which avoids silent float64 promotions.

    Parameters
    ----------
    X : np.ndarray, shape (n_samples, n_features), dtype float32
        Preprocessed feature matrix.
    y : np.ndarray, shape (n_samples,), dtype int
        Binary labels.
    feature_names : list[str]
        Column names for *X*; length must equal ``X.shape[1]``.
    path : Path
        Destination ``.parquet`` file.
    """
    df = pd.DataFrame(X, columns=feature_names)
    df["label"] = y.astype(np.int8)
    df.to_parquet(path, index=False, engine="pyarrow")
    log.info(
        "  Saved %s: %d rows, %d feature columns + label",
        path.name, len(df), X.shape[1],
    )


def run_split(
    raw_dir: str | Path = "ml/data/raw/unsw_nb15",
    out_dir: str | Path = "ml/data/processed",
    val_size: float = 0.10,
    test_size: float = 0.10,
    random_state: int = 42,
    pipeline: Optional[FeatureEngineeringPipeline] = None,
) -> dict[str, Path]:
    """
    End-to-end split: load raw CSVs → preprocess → stratified split → save.

    This is the library entry point.  The CLI ``main()`` delegates to this
    function.

    Parameters
    ----------
    raw_dir : str | Path
        Directory containing UNSW-NB15 CSV parts (see ``load_raw()``).
    out_dir : str | Path
        Output directory.  Created if it does not exist.
    val_size : float
        Fraction of the full dataset for validation.  Default 0.10.
    test_size : float
        Fraction of the full dataset for testing.  Default 0.10.
    random_state : int
        Random seed for reproducibility.
    pipeline : FeatureEngineeringPipeline, optional
        Pre-fitted pipeline to use.  When *None* (default), a new pipeline
        is constructed and fitted on the **training split only** to prevent
        data leakage.

    Returns
    -------
    dict[str, Path]
        Mapping ``{"train": Path, "val": Path, "test": Path,
        "pipeline": Path}`` pointing to the four written files.

    Notes
    -----
    The pipeline is fitted on the **training split only**.  Imputer medians
    and scaler statistics are computed from training data, then applied
    identically to val and test.  This prevents leakage of validation / test
    statistics into the scaler.
    """
    raw_dir = Path(raw_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("Loading raw UNSW-NB15 data from %s", raw_dir)
    df = load_raw(raw_dir)

    # Extract binary labels before the pipeline strips the `label` column.
    if "label" not in df.columns:
        raise ValueError("'label' column not found in the raw DataFrame.")
    y = df["label"].astype(np.int8).values
    log.info(
        "Class distribution — normal: %d (%.1f%%), attack: %d (%.1f%%)",
        (y == 0).sum(), (y == 0).mean() * 100,
        (y == 1).sum(), (y == 1).mean() * 100,
    )

    # ── Step 1: preliminary stratified index split ──────────────────────────
    # Split indices first so the pipeline is fitted on training rows only.
    n = len(df)
    idx = np.arange(n)

    splitter1 = StratifiedShuffleSplit(
        n_splits=1, test_size=test_size, random_state=random_state
    )
    train_val_idx, test_idx = next(splitter1.split(idx, y))

    val_size_adj = val_size / (1.0 - test_size)
    splitter2 = StratifiedShuffleSplit(
        n_splits=1, test_size=val_size_adj, random_state=random_state
    )
    train_idx, val_idx = next(
        splitter2.split(train_val_idx, y[train_val_idx])
    )
    # val_idx and train_idx are positions *within* train_val_idx
    train_idx = train_val_idx[train_idx]
    val_idx   = train_val_idx[val_idx]

    log.info(
        "Split sizes — train: %d, val: %d, test: %d  (%.0f/%.0f/%.0f %%)",
        len(train_idx), len(val_idx), len(test_idx),
        len(train_idx) / n * 100, len(val_idx) / n * 100,
        len(test_idx) / n * 100,
    )

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_val   = df.iloc[val_idx].reset_index(drop=True)
    df_test  = df.iloc[test_idx].reset_index(drop=True)

    y_train = y[train_idx]
    y_val   = y[val_idx]
    y_test  = y[test_idx]

    # ── Step 2: fit pipeline on training data only ───────────────────────────
    if pipeline is None:
        log.info("Fitting FeatureEngineeringPipeline on training split…")
        pipeline = FeatureEngineeringPipeline()
        X_train = pipeline.fit_transform(df_train)
    else:
        log.info("Using provided pre-fitted pipeline.")
        X_train = pipeline.transform(df_train)

    X_val  = pipeline.transform(df_val)
    X_test = pipeline.transform(df_test)

    feature_names = pipeline.feature_names_
    log.info("Output feature count: %d", len(feature_names))

    # ── Step 3: save parquet files ───────────────────────────────────────────
    log.info("Saving splits to %s …", out_dir)
    out_paths: dict[str, Path] = {}

    for split_name, X_split, y_split in [
        ("train", X_train, y_train),
        ("val",   X_val,   y_val),
        ("test",  X_test,  y_test),
    ]:
        path = out_dir / f"{split_name}.parquet"
        _save_split(X_split, y_split, feature_names, path)
        out_paths[split_name] = path

    # ── Step 4: save the fitted pipeline ────────────────────────────────────
    pipeline_path = out_dir / "feature_pipeline.joblib"
    pipeline.save(pipeline_path)
    out_paths["pipeline"] = pipeline_path

    # ── Step 5: write a metadata manifest ───────────────────────────────────
    manifest_path = out_dir / "split_manifest.txt"
    with open(manifest_path, "w") as fh:
        fh.write("UNSW-NB15 split manifest — SecureCloud-BD\n")
        fh.write(f"random_state : {random_state}\n")
        fh.write(f"val_size     : {val_size}\n")
        fh.write(f"test_size    : {test_size}\n")
        fh.write(f"n_total      : {n}\n")
        fh.write(f"n_train      : {len(train_idx)} ({len(train_idx)/n:.4f})\n")
        fh.write(f"n_val        : {len(val_idx)}   ({len(val_idx)/n:.4f})\n")
        fh.write(f"n_test       : {len(test_idx)}  ({len(test_idx)/n:.4f})\n")
        fh.write(f"n_features   : {len(feature_names)}\n")
        fh.write("feature_names:\n")
        for name in feature_names:
            fh.write(f"  {name}\n")
    out_paths["manifest"] = manifest_path

    log.info("Done.  To train models:\n"
             "  python ml/training/train.py --data %s", out_paths["train"])

    return out_paths


def main() -> None:
    """
    CLI entry point for the train/val/test split script.

    Arguments
    ---------
    --raw-dir
        Directory containing UNSW-NB15 CSV parts.
        Default: ``ml/data/raw/unsw_nb15``
    --out-dir
        Output directory for parquet files and the serialised pipeline.
        Default: ``ml/data/processed``
    --val-size
        Fraction of the full dataset for validation.  Default: 0.10
    --test-size
        Fraction of the full dataset for testing.  Default: 0.10
    --seed
        Random seed.  Default: 42
    """
    parser = argparse.ArgumentParser(
        description="Stratified 80/10/10 split for UNSW-NB15 + preprocessing"
    )
    parser.add_argument(
        "--raw-dir",
        default="ml/data/raw/unsw_nb15",
        help="Directory with UNSW-NB15_*.csv files (default: ml/data/raw/unsw_nb15)",
    )
    parser.add_argument(
        "--out-dir",
        default="ml/data/processed",
        help="Output directory for parquet splits (default: ml/data/processed)",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.10,
        help="Validation fraction of full dataset (default: 0.10)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.10,
        help="Test fraction of full dataset (default: 0.10)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )
    args = parser.parse_args()

    if args.val_size + args.test_size >= 1.0:
        parser.error("val_size + test_size must be < 1.0")

    run_split(
        raw_dir=args.raw_dir,
        out_dir=args.out_dir,
        val_size=args.val_size,
        test_size=args.test_size,
        random_state=args.seed,
    )


if __name__ == "__main__":
    main()
