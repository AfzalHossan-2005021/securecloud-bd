FROM python:3.10-slim AS base

WORKDIR /app

# System deps for TensorFlow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install API deps
COPY api/requirements.txt /tmp/api-requirements.txt
RUN pip install --no-cache-dir -r /tmp/api-requirements.txt

# Install ML deps (same layer so tensorflow is shared)
COPY ml/requirements.txt /tmp/ml-requirements.txt
RUN pip install --no-cache-dir -r /tmp/ml-requirements.txt

# Copy source
COPY ml/ /app/ml/
COPY api/ /app/api/

ENV PYTHONPATH=/app
ENV MODEL_PATH=/models
ENV LOG_LEVEL=INFO
ENV IFOREST_WEIGHT=0.4
ENV AE_WEIGHT=0.6
ENV SCORE_THRESHOLD=0.5

EXPOSE 8080

RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

CMD ["uvicorn", "api.app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
