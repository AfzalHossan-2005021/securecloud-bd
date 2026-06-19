# syntax=docker/dockerfile:1.6
# ──────────────────────────────────────────────────────────────────────────────
# SecureCloud-BD Threat API
#
# Security hardening applied:
#   • Non-root user (uid 1000)
#   • Interactive shells removed from final image
#   • HEALTHCHECK in exec form (no shell required)
#   • Minimal apt surface — only libgomp1 added (required by scikit-learn)
#   • PYTHONDONTWRITEBYTECODE and PYTHONUNBUFFERED set for containers
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.10-slim AS builder

WORKDIR /build

# Install build-time system deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc \
      libgomp1 \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a prefix that we'll copy to the final stage
COPY api/requirements.txt  /tmp/api-requirements.txt
COPY ml/requirements.txt   /tmp/ml-requirements.txt

RUN pip install --no-cache-dir --prefix=/install \
      -r /tmp/api-requirements.txt \
      -r /tmp/ml-requirements.txt


# ──────────────────────────────────────────────────────────────────────────────
FROM python:3.10-slim AS final
# ──────────────────────────────────────────────────────────────────────────────

# Runtime-only system library
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

# Create a non-root user before doing anything else
RUN groupadd --system --gid 1000 appgroup \
 && useradd  --system --uid 1000 --gid 1000 \
             --no-create-home --shell /usr/sbin/nologin \
             appuser

WORKDIR /app

# Copy pre-built packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY ml/  /app/ml/
COPY api/ /app/api/

# Remove interactive shells — exec-form CMD and HEALTHCHECK do not need them.
# This step runs last (after all package installs) so apt/pip are unaffected.
RUN rm -f /bin/sh /bin/bash /usr/bin/bash \
          /usr/bin/sh /bin/dash /usr/bin/dash \
 || true

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Default runtime env vars (overridden by ConfigMap in Kubernetes)
    MODEL_DIR=/models \
    IFOREST_MODEL_PATH=/models/iforest_best.joblib \
    LSTM_MODEL_PATH=/models/lstm_ae_best \
    IFOREST_WEIGHT=0.4 \
    LSTM_WEIGHT=0.6 \
    ENSEMBLE_THRESHOLD=0.5 \
    LOG_LEVEL=INFO

EXPOSE 8080

# Exec-form HEALTHCHECK — does not require /bin/sh
HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=15s \
    --retries=3 \
    CMD ["python", "-c", \
         "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]

USER appuser

# Exec-form CMD — does not require /bin/sh
CMD ["uvicorn", "api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--log-level", "warning"]
