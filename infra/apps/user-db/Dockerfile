# Thin wrapper around postgres:15 that bakes in the init script.
# The official image auto-runs everything in /docker-entrypoint-initdb.d/
# on first start (when PGDATA is empty).
FROM postgres:15-alpine

LABEL maintainer="SecureCloud-BD"
LABEL description="bKash demo PostgreSQL database"

COPY init.sql /docker-entrypoint-initdb.d/01-init.sql

# Postgres runs as uid 999 (postgres) by default in this image — no changes needed.

EXPOSE 5432
