"""
Prometheus metrics for the SecureCloud-BD Threat API.

Exposes four metrics via a private ``CollectorRegistry`` so that the default
process-level registry is not cluttered and test imports do not trigger
duplicate-registration errors.

Metrics
-------
securecloud_requests_total
    Counter.  Labels: ``method``, ``endpoint``, ``status``.
securecloud_request_duration_seconds
    Histogram.  Label: ``endpoint``.  Buckets tuned for sub-10 ms inference.
securecloud_flows_scored_total
    Counter.  Total network flows that have been scored.
securecloud_anomalies_detected_total
    Counter.  Total flows classified as anomalous.

Usage
-----
    from api.metrics import record_request, record_scores, request_duration_ctx, get_metrics_text
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

# ---------------------------------------------------------------------------
# Private registry — avoids polluting the default prometheus registry and
# prevents duplicate-registration errors on test imports.
# ---------------------------------------------------------------------------

_registry = CollectorRegistry(auto_describe=True)

_REQUESTS = Counter(
    "securecloud_requests_total",
    "Total HTTP requests processed by the threat API.",
    ["method", "endpoint", "status"],
    registry=_registry,
)

_DURATION = Histogram(
    "securecloud_request_duration_seconds",
    "End-to-end HTTP request processing time.",
    ["endpoint"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=_registry,
)

_FLOWS_SCORED = Counter(
    "securecloud_flows_scored_total",
    "Total network flows scored (single + batch).",
    registry=_registry,
)

_ANOMALIES = Counter(
    "securecloud_anomalies_detected_total",
    "Total flows classified as anomalous by the ensemble.",
    registry=_registry,
)


# ---------------------------------------------------------------------------
# Public helpers — called from api/main.py endpoints
# ---------------------------------------------------------------------------

def record_request(method: str, endpoint: str, status: int) -> None:
    """Increment the request counter for a given method/endpoint/status."""
    _REQUESTS.labels(method=method, endpoint=endpoint, status=str(status)).inc()


def record_scores(n_flows: int, n_anomalies: int) -> None:
    """Add scored-flow and anomaly counts to their respective counters."""
    _FLOWS_SCORED.inc(n_flows)
    _ANOMALIES.inc(n_anomalies)


@contextmanager
def request_duration_ctx(endpoint: str) -> Generator[None, None, None]:
    """Context manager that records elapsed time to the duration histogram."""
    start = time.perf_counter()
    try:
        yield
    finally:
        _DURATION.labels(endpoint=endpoint).observe(time.perf_counter() - start)


def get_metrics_text() -> str:
    """Return the current Prometheus metrics page as UTF-8 text."""
    return generate_latest(_registry).decode("utf-8")
