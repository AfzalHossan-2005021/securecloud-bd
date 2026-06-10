"""Tests for both preprocessing pipelines using synthetic mini-CSVs."""
from __future__ import annotations

import io
import numpy as np
import pandas as pd
import pytest

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]

RNG = np.random.default_rng(0)


# ---- UNSW-NB15 ----

def _unsw_df(n: int = 100) -> pd.DataFrame:
    return pd.DataFrame({
        "dur": RNG.exponential(2, n),
        "sbytes": RNG.lognormal(6, 1.5, n),
        "dbytes": RNG.lognormal(7, 1.5, n),
        "spkts": RNG.randint(1, 50, n),
        "dpkts": RNG.randint(1, 50, n),
        "proto": RNG.choice(["tcp", "udp", "icmp"], n),
        "state": RNG.choice(["FIN", "INT", "REQ", "RST"], n),
        "service": RNG.choice(["http", "dns", "-"], n),
        "label": RNG.integers(0, 2, n),
    })


def test_unsw_output_columns():
    from datasets.unsw_nb15.preprocess import preprocess
    df, _ = preprocess(_unsw_df())
    for col in FEATURE_COLS + ["label"]:
        assert col in df.columns, f"Missing column: {col}"


def test_unsw_no_nulls():
    from datasets.unsw_nb15.preprocess import preprocess
    df, _ = preprocess(_unsw_df())
    assert not df[FEATURE_COLS].isnull().any().any()


def test_unsw_values_in_range():
    from datasets.unsw_nb15.preprocess import preprocess
    df, _ = preprocess(_unsw_df())
    assert df[FEATURE_COLS].ge(0).all().all()
    assert df[FEATURE_COLS].le(1).all().all()


def test_unsw_scaler_reuse():
    from datasets.unsw_nb15.preprocess import preprocess
    df_train, scaler = preprocess(_unsw_df(200))
    df_test, _ = preprocess(_unsw_df(50), scaler=scaler)
    assert len(df_test) == 50


# ---- CIC-IDS2017 ----

def _cic_df(n: int = 100) -> pd.DataFrame:
    return pd.DataFrame({
        "flow duration": RNG.exponential(2, n),
        "total fwd packets": RNG.randint(1, 50, n),
        "total backward packets": RNG.randint(1, 50, n),
        "total length of fwd packets": RNG.lognormal(6, 1.5, n),
        "total length of bwd packets": RNG.lognormal(7, 1.5, n),
        " label": RNG.choice(["BENIGN", "DoS Hulk", "PortScan"], n),
    })


def test_cic_output_columns():
    from datasets.cic_ids2017.preprocess import preprocess
    df, _ = preprocess(_cic_df())
    for col in FEATURE_COLS + ["label"]:
        assert col in df.columns, f"Missing column: {col}"


def test_cic_label_binary():
    from datasets.cic_ids2017.preprocess import preprocess
    df, _ = preprocess(_cic_df(500))
    assert set(df["label"].unique()).issubset({0, 1})
