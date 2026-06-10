"""
CIC-IDS2017 preprocessing pipeline.

Download from: https://www.unb.ca/cic/datasets/ids-2017.html
Expected input: CSVs from MachineLearningCVE/ folder (one per day).
Output: features.parquet (normalised, label column = 'label')

Usage:
    python preprocess.py --input-dir MachineLearningCVE/ --out datasets/cic_ids2017/processed/
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# CIC-IDS2017 column mapping → canonical schema
_CIC_RENAME = {
    "flow duration":          "duration",
    "total fwd packets":      "orig_pkts",
    "total backward packets": "resp_pkts",
    "total length of fwd packets": "orig_bytes",
    "total length of bwd packets": "resp_bytes",
    "fwd header length":      "orig_ip_bytes",
    "bwd header length":      "resp_ip_bytes",
}

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]

# CIC-IDS2017 attack labels that are NOT "BENIGN"
_ATTACK_LABELS = {
    "dos hulk", "dos goldeneye", "dos slowloris", "dos slowhttptest",
    "ddos", "portscan", "bot", "infiltration",
    "web attack – brute force", "web attack – xss", "web attack – sql injection",
    "ftp-patator", "ssh-patator", "heartbleed",
}


def _load_raw(csv_dir: str | Path) -> pd.DataFrame:
    dfs = []
    for p in sorted(Path(csv_dir).glob("*.csv")):
        log.info("  Reading %s", p.name)
        df = pd.read_csv(p, low_memory=False)
        df.columns = [c.strip().lower() for c in df.columns]
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def _map_to_canonical(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={k: v for k, v in _CIC_RENAME.items() if k in df.columns})
    for col in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "orig_ip_bytes", "resp_ip_bytes"]:
        if col not in df.columns:
            df[col] = 0.0

    df["missed_bytes"] = 0
    df["bytes_per_pkt_orig"] = df["orig_bytes"] / (df["orig_pkts"] + 1e-8)
    df["bytes_per_pkt_resp"] = df["resp_bytes"] / (df["resp_pkts"] + 1e-8)

    # CIC-IDS2017 has no protocol column; assume TCP dominance
    df["proto_tcp"] = 1.0
    df["proto_udp"] = 0.0
    df["proto_icmp"] = 0.0

    # No state column either
    df["conn_state_S0"] = 0.0
    df["conn_state_SF"] = 1.0
    df["conn_state_REJ"] = 0.0
    df["conn_state_RSTO"] = 0.0

    # No service column
    df["service_http"] = 0.0
    df["service_dns"] = 0.0
    df["service_ssl"] = 0.0

    return df


def preprocess(
    df_raw: pd.DataFrame,
    scaler: MinMaxScaler | None = None,
) -> tuple[pd.DataFrame, MinMaxScaler]:
    df = _map_to_canonical(df_raw.copy())

    # Labels
    if " label" in df.columns:
        label_col = " label"
    elif "label" in df.columns:
        label_col = "label"
    else:
        raise ValueError("No label column found — expected 'label' or ' label'")

    labels = (~df[label_col].str.strip().str.upper().eq("BENIGN")).astype(int)

    features = df[FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0).clip(lower=0)
    features = features.astype(np.float32)

    if scaler is None:
        scaler = MinMaxScaler()
        features[FEATURE_COLS] = scaler.fit_transform(features)
    else:
        features[FEATURE_COLS] = scaler.transform(features)

    features["label"] = labels.values
    return features, scaler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--out", default="datasets/cic_ids2017/processed")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    log.info("Loading CSVs from %s", args.input_dir)
    raw = _load_raw(args.input_dir)
    log.info("Total rows: %d", len(raw))

    from sklearn.model_selection import train_test_split
    train_raw, test_raw = train_test_split(raw, test_size=0.2, random_state=42)

    train_df, scaler = preprocess(train_raw)
    train_df.to_parquet(out / "train.parquet", index=False)
    log.info("Train → %s  (%d rows, %d attacks)", out / "train.parquet",
             len(train_df), train_df["label"].sum())

    test_df, _ = preprocess(test_raw, scaler=scaler)
    test_df.to_parquet(out / "test.parquet", index=False)
    log.info("Test  → %s  (%d rows, %d attacks)", out / "test.parquet",
             len(test_df), test_df["label"].sum())


if __name__ == "__main__":
    main()
