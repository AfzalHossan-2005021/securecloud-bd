#!/usr/bin/env python3
"""
scored-to-elastic.py — Ship zeek-scored-flows.log to Elasticsearch.

Architecture
------------

    zeek-scored-flows.log  (JSONL from flow-to-features.py)
          │
          │  watchdog FileSystemEventHandler
          ▼
    RecordBuffer  (up to --batch-size records or --flush-interval seconds)
          │
          │  POST /_bulk
          ▼
    Elasticsearch  index: ml-scores-YYYY.MM.DD

Document structure in Elasticsearch
------------------------------------
{
  "@timestamp"    : "2024-01-15T10:30:00.123Z",  // from Zeek ts
  "uid"           : "Cg1234abcdef",               // Zeek connection ID
  "src_ip"        : "192.168.1.10",
  "src_port"      : 54321,
  "dst_ip"        : "93.184.216.34",
  "dst_port"      : 80,
  "proto"         : "tcp",
  "service"       : "http",
  "conn_state"    : "SF",
  "duration"      : 0.352941,
  "orig_bytes"    : 254,
  "resp_bytes"    : 1200,
  "ml.iforest_score"  : 0.3,
  "ml.lstm_score"     : 0.25,
  "ml.ensemble_score" : 0.27,
  "ml.is_anomaly"     : false,
  "ml.explanation"    : { ... },
  "ml.api_latency_ms" : 4.2,
  "ml.scored_at"      : "2024-01-15T10:30:00.456Z"
}

Prerequisites
-------------
    pip install requests watchdog

Usage
-----
    python3 scored-to-elastic.py \\
        --input    zeek-scored-flows.log \\
        --es-url   http://localhost:9200 \\
        [--es-user elastic --es-password changeme] \\
        [--index-prefix ml-scores] \\
        [--batch-size 100] \\
        [--flush-interval 5.0] \\
        [--from-beginning] \\
        [--poll]

Environment variables (override CLI defaults)
----------------------------------------------
ES_URL      Elasticsearch base URL
ES_USER     Basic auth username
ES_PASSWORD Basic auth password
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
import threading
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
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("zeek.scored-to-elastic")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Elasticsearch client
# ---------------------------------------------------------------------------

class ElasticsearchClient:
    """
    Minimal Elasticsearch client using the REST bulk API.

    Avoids the ``elasticsearch`` package dependency for portability.
    Supports HTTP basic auth and connection keep-alive via a requests Session.

    Parameters
    ----------
    base_url : str
        Elasticsearch base URL, e.g. ``http://localhost:9200``.
    username : str, optional
        HTTP basic auth username.
    password : str, optional
        HTTP basic auth password.
    timeout : float
        Per-request timeout in seconds.
    index_prefix : str
        Index name prefix; date suffix is appended as ``{prefix}-YYYY.MM.DD``.
    """

    def __init__(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
        index_prefix: str = "ml-scores",
    ) -> None:
        self.base_url     = base_url.rstrip("/")
        self.timeout      = timeout
        self.index_prefix = index_prefix
        self._session     = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/x-ndjson",
            "Accept":       "application/json",
        })
        if username and password:
            self._session.auth = (username, password)

    def index_name(self, dt: datetime.date | None = None) -> str:
        """Return the date-scoped index name."""
        day = dt or datetime.date.today()
        return f"{self.index_prefix}-{day.strftime('%Y.%m.%d')}"

    def ping(self) -> bool:
        """Return True if Elasticsearch is reachable and responds to GET /."""
        try:
            r = self._session.get(self.base_url, timeout=5.0)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def bulk_index(
        self,
        documents: list[dict[str, Any]],
        max_retries: int = 3,
    ) -> tuple[int, int]:
        """
        Index *documents* using the Elasticsearch bulk API.

        Parameters
        ----------
        documents : list of dicts
            Documents to index.  The ``@timestamp`` field determines the
            index suffix (date).
        max_retries : int
            Number of retry attempts on transient errors.

        Returns
        -------
        (n_ok, n_err) : (int, int)
            Count of successfully and unsuccessfully indexed documents.
        """
        if not documents:
            return 0, 0

        # Build NDJSON body: alternating action / source pairs
        lines: list[str] = []
        for doc in documents:
            # Derive index name from the document's @timestamp
            try:
                ts_str = doc.get("@timestamp", "")
                ts_date = datetime.date.fromisoformat(ts_str[:10])
            except (TypeError, ValueError):
                ts_date = datetime.date.today()

            action = json.dumps(
                {"index": {"_index": self.index_name(ts_date)}},
                separators=(",", ":"),
            )
            source = json.dumps(doc, separators=(",", ":"))
            lines.append(action)
            lines.append(source)

        ndjson_body = "\n".join(lines) + "\n"
        url         = f"{self.base_url}/_bulk"
        last_exc: Exception | None = None

        for attempt in range(max_retries):
            try:
                resp = self._session.post(
                    url, data=ndjson_body.encode("utf-8"), timeout=self.timeout
                )
                resp.raise_for_status()
                return self._parse_bulk_response(resp.json(), len(documents))
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < max_retries - 1:
                    delay = 1.0 * (2 ** attempt)
                    log.warning(
                        "Bulk index error (attempt %d/%d): %s — retry in %.1fs",
                        attempt + 1, max_retries, exc, delay,
                    )
                    time.sleep(delay)

        log.error("Bulk index permanently failed after %d attempts: %s", max_retries, last_exc)
        return 0, len(documents)

    @staticmethod
    def _parse_bulk_response(
        body: dict[str, Any], n_sent: int
    ) -> tuple[int, int]:
        """Parse the Elasticsearch bulk response and count successes / errors."""
        if not body.get("errors"):
            return n_sent, 0

        n_ok  = 0
        n_err = 0
        for item in body.get("items", []):
            action_result = item.get("index") or item.get("create") or {}
            status = action_result.get("status", 500)
            if 200 <= status < 300:
                n_ok += 1
            else:
                n_err += 1
                err_info = action_result.get("error", {})
                log.debug(
                    "Document index error: type=%s reason=%s",
                    err_info.get("type"), err_info.get("reason"),
                )
        return n_ok, n_err

    def close(self) -> None:
        self._session.close()


# ---------------------------------------------------------------------------
# Document transformation
# ---------------------------------------------------------------------------

def _to_es_document(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a zeek-scored-flows.log entry into an Elasticsearch document.

    Flattens the nested ``_securecloud`` dict into a ``ml.*`` namespace so
    that Kibana field discovery works without sub-object field mappings.

    Parameters
    ----------
    raw : dict
        Parsed JSON from zeek-scored-flows.log (written by flow-to-features.py).

    Returns
    -------
    dict
        Flat Elasticsearch document ready for ``/_bulk`` indexing.
    """
    sc = raw.get("_securecloud") or {}
    doc: dict[str, Any] = {
        "@timestamp"        : raw.get("@timestamp"),
        "uid"               : raw.get("uid"),
        "src_ip"            : raw.get("src_ip"),
        "src_port"          : raw.get("src_port"),
        "dst_ip"            : raw.get("dst_ip"),
        "dst_port"          : raw.get("dst_port"),
        "proto"             : raw.get("proto"),
        "service"           : raw.get("service"),
        "conn_state"        : raw.get("conn_state"),
        "duration"          : raw.get("duration"),
        "orig_bytes"        : raw.get("orig_bytes"),
        "resp_bytes"        : raw.get("resp_bytes"),
        # ML scores (ml.* namespace)
        "ml.iforest_score"  : sc.get("iforest_score"),
        "ml.lstm_score"     : sc.get("lstm_score"),
        "ml.ensemble_score" : sc.get("ensemble_score"),
        "ml.is_anomaly"     : sc.get("is_anomaly"),
        "ml.api_latency_ms" : sc.get("api_latency_ms"),
        "ml.scored_at"      : sc.get("scored_at"),
        "ml.explanation"    : sc.get("explanation"),
        # Features as a dense_vector for optional similarity search
        "ml.features"       : sc.get("features"),
    }
    # Drop None values so ES auto-mapping doesn't create null fields
    return {k: v for k, v in doc.items() if v is not None}


# ---------------------------------------------------------------------------
# Buffered record handler
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    lines_seen: int   = 0
    parse_err:  int   = 0
    es_ok:      int   = 0
    es_err:     int   = 0
    anomalies:  int   = 0
    _last_report: float = field(default_factory=time.monotonic, repr=False)
    _interval:  float = 60.0

    def maybe_report(self) -> None:
        if time.monotonic() - self._last_report >= self._interval:
            self.report()
            self._last_report = time.monotonic()

    def report(self) -> None:
        log.info(
            "Stats — lines=%d  parse_err=%d  es_ok=%d  es_err=%d  anomalies=%d",
            self.lines_seen, self.parse_err, self.es_ok, self.es_err, self.anomalies,
        )


class ScoredLogHandler(FileSystemEventHandler):
    """
    Tail zeek-scored-flows.log and ship entries to Elasticsearch in batches.

    Documents are buffered in memory until either ``batch_size`` is reached
    or ``flush_interval`` seconds have elapsed, whichever comes first.
    A background timer thread drives the time-based flush.

    Parameters
    ----------
    input_path : Path
        Path to ``zeek-scored-flows.log``.
    es_client : ElasticsearchClient
    batch_size : int
        Flush after accumulating this many documents.
    flush_interval : float
        Maximum seconds between flushes (even for small batches).
    stats : Stats
    from_beginning : bool
        Process the entire file from position 0 on startup.
    """

    def __init__(
        self,
        input_path: Path,
        es_client: ElasticsearchClient,
        batch_size: int,
        flush_interval: float,
        stats: Stats,
        from_beginning: bool = False,
    ) -> None:
        super().__init__()
        self._input_path    = input_path.resolve()
        self._es            = es_client
        self._batch_size    = batch_size
        self._flush_interval = flush_interval
        self._stats         = stats
        self._buf: str      = ""
        self._fp: TextIOWrapper | None = None
        self._queue: list[dict[str, Any]] = []
        self._lock          = threading.Lock()
        self._timer: threading.Timer | None = None
        self._open(seek_end=not from_beginning)
        self._schedule_flush()

    def _open(self, seek_end: bool = True) -> None:
        try:
            self._fp = open(self._input_path, encoding="utf-8", errors="replace")
            if seek_end:
                self._fp.seek(0, 2)
            log.info("Tailing %s from position %d", self._input_path, self._fp.tell())
        except FileNotFoundError:
            log.warning(
                "%s not found — waiting for flow-to-features.py to create it",
                self._input_path,
            )
            self._fp = None

    def close(self) -> None:
        if self._timer:
            self._timer.cancel()
        self._flush()
        if self._fp:
            self._fp.close()

    # --- Watchdog callbacks ---

    def on_modified(self, event: FileSystemEvent) -> None:
        if isinstance(event, (DirModifiedEvent, DirCreatedEvent)):
            return
        if Path(event.src_path).resolve() == self._input_path:
            self._drain()

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, DirCreatedEvent):
            return
        if Path(event.src_path).resolve() == self._input_path:
            if self._fp:
                self._drain()
                self._fp.close()
            self._open(seek_end=False)

    # --- Core processing ---

    def _drain(self) -> None:
        if self._fp is None:
            self._open(seek_end=True)
            return

        while True:
            chunk = self._fp.read(65536)
            if not chunk:
                break
            self._buf += chunk

        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_line(line)

        self._stats.maybe_report()

    def _process_line(self, line: str) -> None:
        self._stats.lines_seen += 1
        try:
            raw  = json.loads(line)
            doc  = _to_es_document(raw)
        except (json.JSONDecodeError, KeyError) as exc:
            log.debug("Parse error: %s | %.80s", exc, line)
            self._stats.parse_err += 1
            return

        if doc.get("ml.is_anomaly"):
            self._stats.anomalies += 1

        with self._lock:
            self._queue.append(doc)
            if len(self._queue) >= self._batch_size:
                self._flush_locked()

    # --- Flush ---

    def _schedule_flush(self) -> None:
        """Schedule a timer-based flush after flush_interval seconds."""
        self._timer = threading.Timer(self._flush_interval, self._timed_flush)
        self._timer.daemon = True
        self._timer.start()

    def _timed_flush(self) -> None:
        self._flush()
        self._schedule_flush()

    def _flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        """Send the current queue to Elasticsearch (caller holds _lock)."""
        if not self._queue:
            return
        batch = self._queue[:]
        self._queue.clear()

        n_ok, n_err = self._es.bulk_index(batch)
        self._stats.es_ok  += n_ok
        self._stats.es_err += n_err

        if n_ok:
            log.info(
                "Indexed %d documents to Elasticsearch  (%d errors)",
                n_ok, n_err,
            )
        if n_err:
            log.error("%d documents failed to index", n_err)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ship zeek-scored-flows.log to Elasticsearch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--input",
        type=Path,
        default=Path("zeek-scored-flows.log"),
        help="Path to the scored flows JSONL file (written by flow-to-features.py).",
    )
    p.add_argument(
        "--es-url",
        default=os.environ.get("ES_URL", "http://localhost:9200"),
        help="Elasticsearch base URL.",
    )
    p.add_argument(
        "--es-user",
        default=os.environ.get("ES_USER", ""),
        help="Elasticsearch HTTP basic auth username.",
    )
    p.add_argument(
        "--es-password",
        default=os.environ.get("ES_PASSWORD", ""),
        help="Elasticsearch HTTP basic auth password.",
    )
    p.add_argument(
        "--index-prefix",
        default="ml-scores",
        help="Elasticsearch index name prefix (suffix: -YYYY.MM.DD).",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Maximum documents per bulk request.",
    )
    p.add_argument(
        "--flush-interval",
        type=float,
        default=5.0,
        help="Seconds between time-triggered flushes (for low-volume periods).",
    )
    p.add_argument(
        "--from-beginning",
        action="store_true",
        help="Process the entire input file from position 0.",
    )
    p.add_argument(
        "--poll",
        action="store_true",
        help="Use polling observer instead of inotify (for NFS / Docker).",
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

    log.info("SecureCloud-BD scored-to-elastic starting")
    log.info("  input      : %s", args.input)
    log.info("  es_url     : %s", args.es_url)
    log.info("  index      : %s-YYYY.MM.DD", args.index_prefix)
    log.info("  batch_size : %d  flush_interval: %.1fs",
             args.batch_size, args.flush_interval)

    es = ElasticsearchClient(
        base_url=args.es_url,
        username=args.es_user or None,
        password=args.es_password or None,
        index_prefix=args.index_prefix,
    )

    # --- Health-check Elasticsearch ---
    if es.ping():
        log.info("Elasticsearch is reachable at %s", args.es_url)
    else:
        log.error("Cannot reach Elasticsearch at %s — aborting.", args.es_url)
        sys.exit(1)

    stats   = Stats(_interval=args.stats_interval)
    handler = ScoredLogHandler(
        input_path=args.input,
        es_client=es,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        stats=stats,
        from_beginning=args.from_beginning,
    )

    ObserverClass = PollingObserver if args.poll else Observer
    observer      = ObserverClass()
    watch_dir     = args.input.parent if args.input.parent.exists() else Path(".")
    observer.schedule(handler, path=str(watch_dir), recursive=False)
    observer.start()

    log.info("Watching %s for new scored flow entries…", args.input)

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
        es.close()
        stats.report()
        log.info("Shutdown complete.")


if __name__ == "__main__":
    main()
