"""
UNSW-NB15 preprocessing pipeline.

Download the dataset from:
  https://research.unsw.edu.au/projects/unsw-nb15-dataset

Expected input: UNSW_NB15_training-set.csv / UNSW_NB15_testing-set.csv
Output: features.parquet (normalised, one-hot encoded, label column = 'label')

Usage:
    python preprocess.py --train UNSW_NB15_training-set.csv \
                         --test  UNSW_NB15_testing-set.csv  \
                         --out   datasets/unsw_nb15/processed/
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

# UNSW-NB15 columns that map to our 20 canonical features
_UNSW_NUMERIC = [
    "dur",          # → duration
    "sbytes",       # → orig_bytes
    "dbytes",       # → resp_bytes
    "spkts",        # → orig_pkts
    "dpkts",        # → resp_pkts
    "sip_bytes",    # → orig_ip_bytes  (not in all versions; falls back to sbytes)
    "dip_bytes",    # → resp_ip_bytes
]

_UNSW_CATEGORICAL = ["proto", "state", "service"]

_TARGET_COL = "label"   # 0 = normal, 1 = attack


def _load_raw(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def _map_to_canonical(df: pd.DataFrame) -> pd.DataFrame:
    """Rename UNSW columns to the 20-feature canonical schema."""
    rename = {
        "dur":      "duration",
        "sbytes":   "orig_bytes",
        "dbytes":   "resp_bytes",
        "spkts":    "orig_pkts",
        "dpkts":    "resp_pkts",
    }
    # sip_bytes / dip_bytes may not exist in older dataset versions
    if "sip_bytes" in df.columns:
        rename["sip_bytes"] = "orig_ip_bytes"
    else:
        df["orig_ip_bytes"] = df.get("sbytes", 0)
    if "dip_bytes" in df.columns:
        rename["dip_bytes"] = "resp_ip_bytes"
    else:
        df["resp_ip_bytes"] = df.get("dbytes", 0)

    df = df.rename(columns=rename)
    df["missed_bytes"] = 0

    # Bytes per packet
    df["bytes_per_pkt_orig"] = df["orig_bytes"] / (df["orig_pkts"] + 1e-8)
    df["bytes_per_pkt_resp"] = df["resp_bytes"] / (df["resp_pkts"] + 1e-8)
    return df


def _encode_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    # Proto → proto_tcp / proto_udp / proto_icmp
    proto = df.get("proto", pd.Series(["tcp"] * len(df)))
    df["proto_tcp"] = (proto.str.lower() == "tcp").astype(float)
    df["proto_udp"] = (proto.str.lower() == "udp").astype(float)
    df["proto_icmp"] = (proto.str.lower().isin(["icmp", "icmpv6"])).astype(float)

    # State → conn_state equivalents
    state = df.get("state", pd.Series(["FIN"] * len(df)))
    df["conn_state_S0"] = (state.str.upper() == "INT").astype(float)
    df["conn_state_SF"] = (state.str.upper() == "FIN").astype(float)
    df["conn_state_REJ"] = (state.str.upper() == "REQ").astype(float)
    df["conn_state_RSTO"] = (state.str.upper() == "RST").astype(float)

    # Service
    service = df.get("service", pd.Series(["-"] * len(df)))
    df["service_http"] = (service.str.lower().isin(["http", "https"])).astype(float)
    df["service_dns"] = (service.str.lower() == "dns").astype(float)
    df["service_ssl"] = (service.str.lower().isin(["ssl", "tls"])).astype(float)

    return df


FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]


def preprocess(df_raw: pd.DataFrame, scaler: MinMaxScaler | None = None) -> tuple[pd.DataFrame, MinMaxScaler]:
    df = _map_to_canonical(df_raw.copy())
    df = _encode_categoricals(df)

    # Resolve label column
    if "label" in df.columns:
        labels = df["label"].astype(int)
    elif "attack_cat" in df.columns:
        labels = (df["attack_cat"].str.strip() != "").astype(int)
    else:
        labels = pd.Series(np.zeros(len(df), dtype=int))

    features = df[FEATURE_COLS].fillna(0).clip(lower=0).astype(np.float32)

    if scaler is None:
        scaler = MinMaxScaler()
        features[FEATURE_COLS] = scaler.fit_transform(features)
    else:
        features[FEATURE_COLS] = scaler.transform(features)

    features["label"] = labels.values
    return features, scaler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", required=True)
    parser.add_argument("--test",  required=True)
    parser.add_argument("--out",   default="datasets/unsw_nb15/processed")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    log.info("Loading train: %s", args.train)
    train_raw = _load_raw(args.train)
    train_df, scaler = preprocess(train_raw)
    train_df.to_parquet(out / "train.parquet", index=False)
    log.info("Train → %s  (%d rows, %d attacks)", out / "train.parquet",
             len(train_df), train_df["label"].sum())

    log.info("Loading test: %s", args.test)
    test_raw = _load_raw(args.test)
    test_df, _ = preprocess(test_raw, scaler=scaler)
    test_df.to_parquet(out / "test.parquet", index=False)
    log.info("Test  → %s  (%d rows, %d attacks)", out / "test.parquet",
             len(test_df), test_df["label"].sum())


if __name__ == "__main__":
    main()
