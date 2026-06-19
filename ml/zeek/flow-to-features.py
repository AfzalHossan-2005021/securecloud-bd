#!/usr/bin/env python3
"""
flow-to-features.py — Real-time Zeek conn.log → SecureCloud-BD ML API.

Architecture
------------

    Zeek conn.log (JSONL)
          │
          │  watchdog FileSystemEventHandler (inotify / kqueue / FSEvents)
          ▼
    ConnLogTailer
          │  extract_features()
          │  20 canonical features matching api/schemas.py:FEATURE_NAMES
          ▼
    POST /score  →  SecureCloud-BD FastAPI (iforest + lstm-ae ensemble)
          │
          ▼
    zeek-scored-flows.log  (one JSONL record per flow, enriched with scores)

Feature mapping (Zeek conn.log JSON field → canonical name)
------------------------------------------------------------
duration           dur  (float seconds; 0.0 for incomplete flows)
orig_bytes         bytes transmitted by the originator
resp_bytes         bytes transmitted by the responder
orig_pkts          packet count from originator
resp_pkts          packet count from responder
orig_ip_bytes      IP-layer byte count from originator
resp_ip_bytes      IP-layer byte count from responder
missed_bytes       bytes lost to packet-capture gaps
proto_tcp          1.0 iff proto == "tcp"
proto_udp          1.0 iff proto == "udp"
proto_icmp         1.0 iff proto == "icmp"
conn_state_S0      1.0 iff conn_state == "S0"   (SYN seen, no reply)
conn_state_SF      1.0 iff conn_state == "SF"   (normal finish)
conn_state_REJ     1.0 iff conn_state == "REJ"  (SYN rejected)
conn_state_RSTO    1.0 iff conn_state == "RSTO" (RST by originator)
service_http       1.0 iff service   == "http"
service_dns        1.0 iff service   == "dns"
service_ssl        1.0 iff service   in {"ssl", "tls"}
bytes_per_pkt_orig orig_bytes / orig_pkts  (0.0 if orig_pkts == 0)
bytes_per_pkt_resp resp_bytes / resp_pkts  (0.0 if resp_pkts == 0)

Prerequisites
-------------
    pip install watchdog requests

Usage
-----
    python3 flow-to-features.py \\
        --conn-log  /opt/zeek/logs/current/conn.log \\
        --api-url   http://localhost:8080/score \\
        --output    zeek-scored-flows.log \\
        [--api-timeout 5] \\
        [--api-retries 3] \\
        [--from-beginning] \\
        [--poll]
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from io import TextIOWrapper
from pathlib import Path
from typing import Any

import requests
import urllib3
from watchdog.events import (
    DirCreatedEvent,
    DirModifiedEvent,
    FileCreatedEvent,
    FileModifiedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("zeek.flow-to-features")

# Suppress verbose urllib3 retry warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Feature contract — must match api/schemas.py:FEATURE_NAMES exactly
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
    "service_http", "service_dns", "service_ssl",
    "bytes_per_pkt_orig", "bytes_per_pkt_resp",
]
N_FEATURES = len(FEATURE_NAMES)  # 20

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _safe_float(value: Any, default: float = 0.0) -> float:
    """
    Convert a Zeek field value to float.

    Zeek uses ``-`` (hyphen) in TSV logs to denote null/unset values.
    In JSON logs, missing fields are absent or ``null``.  Both cases
    return *default*.
    """
    if value is None or value == "-" or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_features(record: dict[str, Any]) -> list[float]:
    """
    Extract the 20 canonical SecureCloud-BD features from one conn.log record.

    Parameters
    ----------
    record : dict
        Parsed JSON object from Zeek's conn.log.

    Returns
    -------
    list[float]
        Feature vector in the order defined by ``FEATURE_NAMES``.
        Never contains NaN or Inf; all nulls map to 0.0.
    """
    # --- Raw numeric fields ---
    duration      = _safe_float(record.get("duration"))
    orig_bytes    = _safe_float(record.get("orig_bytes"))
    resp_bytes    = _safe_float(record.get("resp_bytes"))
    orig_pkts     = _safe_float(record.get("orig_pkts"))
    resp_pkts     = _safe_float(record.get("resp_pkts"))
    orig_ip_bytes = _safe_float(record.get("orig_ip_bytes"))
    resp_ip_bytes = _safe_float(record.get("resp_ip_bytes"))
    missed_bytes  = _safe_float(record.get("missed_bytes"))

    # --- Protocol one-hot ---
    proto      = str(record.get("proto", "")).lower()
    proto_tcp  = 1.0 if proto == "tcp"  else 0.0
    proto_udp  = 1.0 if proto == "udp"  else 0.0
    proto_icmp = 1.0 if proto == "icmp" else 0.0

    # --- Connection state one-hot ---
    conn_state = str(record.get("conn_state", ""))
    cs_S0      = 1.0 if conn_state == "S0"   else 0.0
    cs_SF      = 1.0 if conn_state == "SF"   else 0.0
    cs_REJ     = 1.0 if conn_state == "REJ"  else 0.0
    cs_RSTO    = 1.0 if conn_state == "RSTO" else 0.0

    # --- Service one-hot ---
    service    = str(record.get("service", "")).lower()
    svc_http   = 1.0 if service == "http"         else 0.0
    svc_dns    = 1.0 if service == "dns"           else 0.0
    svc_ssl    = 1.0 if service in ("ssl", "tls")  else 0.0

    # --- Derived features ---
    bpp_orig = orig_bytes / orig_pkts if orig_pkts > 0.0 else 0.0
    bpp_resp = resp_bytes / resp_pkts if resp_pkts > 0.0 else 0.0

    return [
        duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
        orig_ip_bytes, resp_ip_bytes, missed_bytes,
        proto_tcp, proto_udp, proto_icmp,
        cs_S0, cs_SF, cs_REJ, cs_RSTO,
        svc_http, svc_dns, svc_ssl,
        bpp_orig, bpp_resp,
    ]


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------

class ScoringClient:
    """
    Thin wrapper around the /score endpoint with connection pooling and retry.

    Parameters
    ----------
    api_url : str
        Full URL of the /score endpoint, e.g. ``http://localhost:8080/score``.
    timeout : float
        Per-request timeout in seconds.
    max_retries : int
        Number of attempts before giving up.  Uses exponential back-off
        (0.5 s, 1 s, 2 s, …).
    """

    def __init__(
        self,
        api_url: str,
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.api_url     = api_url
        self.timeout     = timeout
        self.max_retries = max_retries
        self._session    = requests.Session()
        # Mount a retry adapter for transient network errors
        adapter = requests.adapters.HTTPAdapter(
            max_retries=urllib3.util.Retry(
                total=0,           # we manage retries ourselves
                raise_on_status=False,
            )
        )
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers["Content-Type"] = "application/json"

    def score(self, features: list[float]) -> dict[str, Any]:
        """
        POST features to /score and return the parsed JSON response.

        Raises
        ------
        requests.RequestException
            After all retry attempts are exhausted.
        """
        payload = {"features": features}
        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                t0   = time.perf_counter()
                resp = self._session.post(
                    self.api_url, json=payload, timeout=self.timeout
                )
                latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                resp.raise_for_status()
                result = resp.json()
                result["_api_latency_ms"] = latency_ms
                return result
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    delay = 0.5 * (2 ** attempt)
                    log.warning(
                        "API error on attempt %d/%d: %s — retrying in %.1fs",
                        attempt + 1, self.max_retries, exc, delay,
                    )
                    time.sleep(delay)

        raise last_exc  # type: ignore[misc]

    def close(self) -> None:
        self._session.close()


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    flows_seen:      int   = 0
    features_ok:     int   = 0
    api_ok:          int   = 0
    api_err:         int   = 0
    parse_err:       int   = 0
    anomalies:       int   = 0
    _last_report:    float = field(default_factory=time.monotonic, repr=False)
    _report_interval: float = 60.0

    def maybe_report(self) -> None:
        now = time.monotonic()
        if now - self._last_report >= self._report_interval:
            self.report()
            self._last_report = now

    def report(self) -> None:
        anomaly_rate = (
            self.anomalies / self.api_ok if self.api_ok > 0 else 0.0
        )
        log.info(
            "Stats — flows=%d  features_ok=%d  api_ok=%d  api_err=%d  "
            "parse_err=%d  anomalies=%d  anomaly_rate=%.2f%%",
            self.flows_seen, self.features_ok, self.api_ok,
            self.api_err, self.parse_err,
            self.anomalies, anomaly_rate * 100,
        )


# ---------------------------------------------------------------------------
# Watchdog file handler
# ---------------------------------------------------------------------------

class ConnLogHandler(FileSystemEventHandler):
    """
    Tail Zeek's conn.log in real time using filesystem change notifications.

    For each new line:
      1. Parses the JSON record.
      2. Extracts the 20-feature vector.
      3. POSTs to the ML API /score endpoint.
      4. Writes an enriched JSONL entry to the output file.

    File rotation
    -------------
    ZeekControl rotates conn.log hourly by renaming the current file and
    creating a fresh one.  ``on_created`` handles this case by reopening
    the file handle.

    Parameters
    ----------
    conn_log_path : Path
        Absolute path to ``/opt/zeek/logs/current/conn.log``.
    client : ScoringClient
        Pre-configured API client.
    output_path : Path
        Path to the scored flows output file (JSONL).
    stats : Stats
        Shared statistics object.
    from_beginning : bool
        If ``True``, replay the entire current log on startup instead of
        tailing from the end.
    """

    def __init__(
        self,
        conn_log_path: Path,
        client: ScoringClient,
        output_path: Path,
        stats: Stats,
        from_beginning: bool = False,
    ) -> None:
        super().__init__()
        self._conn_log     = conn_log_path.resolve()
        self._client       = client
        self._output_path  = output_path
        self._stats        = stats
        self._buf: str     = ""
        self._fp: TextIOWrapper | None = None
        self._out: TextIOWrapper | None = None
        self._open_output()
        self._open_log(seek_end=not from_beginning)

    # --- File management ---

    def _open_log(self, seek_end: bool = True) -> None:
        """Open (or reopen) the conn.log file handle."""
        try:
            self._fp = open(self._conn_log, encoding="utf-8", errors="replace")
            if seek_end:
                self._fp.seek(0, 2)
            pos = self._fp.tell()
            log.info("Opened %s at position %d", self._conn_log, pos)
        except FileNotFoundError:
            log.warning(
                "%s not found — waiting for Zeek to create it", self._conn_log
            )
            self._fp = None

    def _open_output(self) -> None:
        """Open the scored-flows output file in append mode."""
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._out = open(self._output_path, "a", encoding="utf-8", buffering=1)
        log.info("Writing scored flows to %s", self._output_path)

    def close(self) -> None:
        if self._fp:
            self._fp.close()
        if self._out:
            self._out.close()

    # --- Watchdog callbacks ---

    def on_modified(self, event: FileSystemEvent) -> None:
        if isinstance(event, (DirModifiedEvent, DirCreatedEvent)):
            return
        if Path(event.src_path).resolve() == self._conn_log:
            self._drain()

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, DirCreatedEvent):
            return
        if Path(event.src_path).resolve() == self._conn_log:
            # Log was rotated — drain remainder, close, reopen
            if self._fp:
                self._drain()
                self._fp.close()
                log.info("conn.log rotated — reopening")
            self._open_log(seek_end=False)

    # --- Core processing ---

    def _drain(self) -> None:
        """Read and process all new data since the last call."""
        if self._fp is None:
            self._open_log(seek_end=True)
            return

        # Read in 64 KiB chunks to avoid holding large buffers
        while True:
            chunk = self._fp.read(65536)
            if not chunk:
                break
            self._buf += chunk

        # Process complete lines only; keep partial tail in buffer
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_line(line)

        self._stats.maybe_report()

    def _process_line(self, line: str) -> None:
        """Parse one JSON line, score it, and write the result."""
        self._stats.flows_seen += 1

        # --- Parse JSON ---
        try:
            record: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError as exc:
            log.debug("JSON parse error: %s | line: %.80s", exc, line)
            self._stats.parse_err += 1
            return

        # --- Extract features ---
        features = extract_features(record)
        self._stats.features_ok += 1

        # --- Score via API ---
        try:
            response = self._client.score(features)
            self._stats.api_ok += 1
            if response.get("is_anomaly"):
                self._stats.anomalies += 1
                self._on_anomaly(record, response, features)
        except requests.RequestException as exc:
            log.error(
                "API unreachable for flow uid=%s: %s",
                record.get("uid", "?"), exc,
            )
            self._stats.api_err += 1
            return

        # --- Write enriched record ---
        self._write_output(record, features, response)

    def _on_anomaly(
        self,
        record: dict[str, Any],
        response: dict[str, Any],
        features: list[float],
    ) -> None:
        """Log a human-readable alert for anomalous flows."""
        log.warning(
            "ANOMALY detected  uid=%-20s  src=%s:%s → dst=%s:%s  "
            "proto=%-4s  service=%-8s  ensemble=%.4f  "
            "iforest=%.4f  lstm=%.4f",
            record.get("uid", "?"),
            record.get("id.orig_h", "?"), record.get("id.orig_p", "?"),
            record.get("id.resp_h", "?"), record.get("id.resp_p", "?"),
            record.get("proto", "?"),
            record.get("service", "-"),
            response.get("ensemble_score", 0.0),
            response.get("iforest_score",  0.0),
            response.get("lstm_score",     0.0),
        )

    def _write_output(
        self,
        record: dict[str, Any],
        features: list[float],
        response: dict[str, Any],
    ) -> None:
        """Append one enriched JSONL record to the output file."""
        if self._out is None:
            return

        # Convert Zeek epoch timestamp → ISO-8601
        ts_raw = record.get("ts")
        try:
            iso_ts = datetime.datetime.fromtimestamp(
                float(ts_raw), tz=datetime.timezone.utc
            ).isoformat()
        except (TypeError, ValueError, OSError):
            iso_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        enriched: dict[str, Any] = {
            # Zeek connection metadata (pass-through)
            "@timestamp": iso_ts,
            "uid":        record.get("uid"),
            "src_ip":     record.get("id.orig_h"),
            "src_port":   record.get("id.orig_p"),
            "dst_ip":     record.get("id.resp_h"),
            "dst_port":   record.get("id.resp_p"),
            "proto":      record.get("proto"),
            "service":    record.get("service"),
            "conn_state": record.get("conn_state"),
            "duration":   record.get("duration"),
            "orig_bytes": record.get("orig_bytes"),
            "resp_bytes": record.get("resp_bytes"),
            # ML scores
            "_securecloud": {
                "feature_names":  FEATURE_NAMES,
                "features":       features,
                "iforest_score":  response.get("iforest_score"),
                "lstm_score":     response.get("lstm_score"),
                "ensemble_score": response.get("ensemble_score"),
                "is_anomaly":     response.get("is_anomaly"),
                "explanation":    response.get("explanation"),
                "api_latency_ms": response.get("_api_latency_ms"),
                "scored_at":      datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
            },
        }
        self._out.write(json.dumps(enriched, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Tail Zeek conn.log in real time and score each flow via the ML API.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--conn-log",
        type=Path,
        default=Path("/opt/zeek/logs/current/conn.log"),
        help="Path to Zeek's conn.log (JSON format required).",
    )
    p.add_argument(
        "--api-url",
        default=os.environ.get("SECURECLOUD_API_URL", "http://localhost:8080/score"),
        help="URL of the SecureCloud-BD /score endpoint.",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("zeek-scored-flows.log"),
        help="Path for the enriched scored-flows JSONL output.",
    )
    p.add_argument(
        "--api-timeout",
        type=float,
        default=5.0,
        help="API request timeout in seconds.",
    )
    p.add_argument(
        "--api-retries",
        type=int,
        default=3,
        help="Number of API retry attempts before dropping a flow.",
    )
    p.add_argument(
        "--from-beginning",
        action="store_true",
        help="Process conn.log from the beginning of the current file, not just new entries.",
    )
    p.add_argument(
        "--poll",
        action="store_true",
        help="Use polling observer instead of inotify/FSEvents (for NFS or Docker volumes).",
    )
    p.add_argument(
        "--stats-interval",
        type=float,
        default=60.0,
        help="Seconds between periodic stats log lines.",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    log.info("SecureCloud-BD flow-to-features starting")
    log.info("  conn.log : %s", args.conn_log)
    log.info("  API URL  : %s", args.api_url)
    log.info("  output   : %s", args.output)

    # --- Health-check the API before starting ---
    health_url = args.api_url.replace("/score", "/health")
    try:
        r = requests.get(health_url, timeout=5.0)
        body = r.json()
        log.info(
            "API health: status=%s  model_version=%s",
            body.get("status"), body.get("model_version"),
        )
        if body.get("status") != "ok":
            log.warning("API reports status=%s — models may not be loaded yet", body.get("status"))
    except requests.RequestException as exc:
        log.error("Cannot reach API at %s: %s — aborting.", health_url, exc)
        sys.exit(1)

    client = ScoringClient(
        api_url=args.api_url,
        timeout=args.api_timeout,
        max_retries=args.api_retries,
    )

    stats   = Stats(_report_interval=args.stats_interval)
    handler = ConnLogHandler(
        conn_log_path=args.conn_log,
        client=client,
        output_path=args.output,
        stats=stats,
        from_beginning=args.from_beginning,
    )

    ObserverClass = PollingObserver if args.poll else Observer
    observer      = ObserverClass()
    observer.schedule(handler, path=str(args.conn_log.parent), recursive=False)
    observer.start()

    log.info("Watching %s for new flows…", args.conn_log)

    # --- Graceful shutdown on SIGTERM / SIGINT ---
    _shutdown = False

    def _handle_signal(signum: int, frame: object) -> None:
        nonlocal _shutdown
        log.info("Signal %d received — shutting down", signum)
        _shutdown = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    try:
        while not _shutdown:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()
        handler.close()
        client.close()
        stats.report()
        log.info("Shutdown complete.")


if __name__ == "__main__":
    main()
