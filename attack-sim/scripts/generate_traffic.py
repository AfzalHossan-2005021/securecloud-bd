#!/usr/bin/env python3
"""
Generate synthetic labelled network flow CSV for ML training.

Usage:
    python generate_traffic.py --normal 50000 --attack 5000 --out datasets/synthetic.csv
"""
from __future__ import annotations

import argparse
import numpy as np
import pandas as pd
from pathlib import Path

RNG = np.random.default_rng(42)

COLUMNS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
    "label",
]


def _proto_flags(n: int, weights=(0.7, 0.25, 0.05)):
    protos = RNG.choice(["tcp", "udp", "icmp"], size=n, p=weights)
    return (
        (protos == "tcp").astype(float),
        (protos == "udp").astype(float),
        (protos == "icmp").astype(float),
    )


def _service_flags(n: int):
    svcs = RNG.choice(["http", "dns", "ssl", "other"], size=n, p=(0.5, 0.2, 0.2, 0.1))
    return (
        (svcs == "http").astype(float),
        (svcs == "dns").astype(float),
        (svcs == "ssl").astype(float),
    )


def _conn_state_flags(n: int, weights=(0.05, 0.75, 0.1, 0.1)):
    states = RNG.choice(["S0", "SF", "REJ", "RSTO"], size=n, p=weights)
    return (
        (states == "S0").astype(float),
        (states == "SF").astype(float),
        (states == "REJ").astype(float),
        (states == "RSTO").astype(float),
    )


def normal_flows(n: int) -> pd.DataFrame:
    dur = RNG.exponential(scale=2.0, size=n)
    ob = RNG.lognormal(mean=6, sigma=1.5, size=n)
    rb = RNG.lognormal(mean=7, sigma=1.5, size=n)
    op = np.maximum(1, (ob / 1400).astype(int))
    rp = np.maximum(1, (rb / 1400).astype(int))
    oib = ob * RNG.uniform(1.0, 1.2, n)
    rib = rb * RNG.uniform(1.0, 1.2, n)
    mb = np.zeros(n)

    tcp, udp, icmp = _proto_flags(n)
    s0, sf, rej, rsto = _conn_state_flags(n)
    shttp, sdns, sssl = _service_flags(n)

    bppo = ob / (op + 1e-8)
    bppr = rb / (rp + 1e-8)

    return pd.DataFrame(
        dict(
            duration=dur, orig_bytes=ob, resp_bytes=rb,
            orig_pkts=op, resp_pkts=rp,
            orig_ip_bytes=oib, resp_ip_bytes=rib, missed_bytes=mb,
            proto_tcp=tcp, proto_udp=udp, proto_icmp=icmp,
            conn_state_S0=s0, conn_state_SF=sf,
            conn_state_REJ=rej, conn_state_RSTO=rsto,
            service_http=shttp, service_dns=sdns, service_ssl=sssl,
            bytes_per_pkt_orig=bppo, bytes_per_pkt_resp=bppr,
            label=0,
        )
    )


def attack_flows(n: int) -> pd.DataFrame:
    """Simulate recon + exfil + lateral movement traffic patterns."""
    n_recon = n // 3
    n_exfil = n // 3
    n_lateral = n - n_recon - n_exfil

    # Recon: many short connections, high packet count, tiny bytes
    recon = normal_flows(n_recon)
    recon["duration"] = RNG.uniform(0, 0.5, n_recon)
    recon["orig_bytes"] = RNG.uniform(40, 200, n_recon)
    recon["resp_bytes"] = 0
    recon["orig_pkts"] = RNG.randint(1, 5, n_recon)
    recon["conn_state_S0"] = 1.0
    recon["conn_state_SF"] = 0.0

    # Exfil: large outbound, small inbound, long duration
    exfil = normal_flows(n_exfil)
    exfil["duration"] = RNG.uniform(30, 600, n_exfil)
    exfil["orig_bytes"] = RNG.lognormal(mean=15, sigma=1, size=n_exfil)
    exfil["resp_bytes"] = RNG.uniform(100, 1000, n_exfil)

    # Lateral: unusual service combos, mid-range bytes
    lateral = normal_flows(n_lateral)
    lateral["service_http"] = 0
    lateral["service_ssl"] = 0
    lateral["proto_tcp"] = 1

    df = pd.concat([recon, exfil, lateral], ignore_index=True)
    df["label"] = 1
    return df


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal", type=int, default=50_000)
    parser.add_argument("--attack", type=int, default=5_000)
    parser.add_argument("--out", default="datasets/synthetic.csv")
    args = parser.parse_args()

    print(f"Generating {args.normal} normal + {args.attack} attack flows …")
    df = pd.concat(
        [normal_flows(args.normal), attack_flows(args.attack)],
        ignore_index=True,
    ).sample(frac=1, random_state=42)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} rows → {out}")
    print(f"Label distribution:\n{df['label'].value_counts()}")


if __name__ == "__main__":
    main()
