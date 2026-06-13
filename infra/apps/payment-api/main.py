"""
bKash-like payment API — FastAPI service.

Endpoints:
  POST /transfer               Debit from_user, credit to_user atomically
  GET  /balance/{user_id}      Fetch user name, phone, and current balance
  GET  /health                 Liveness probe

Environment variables (see ConfigMap / Secret):
  DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
  MIN_TRANSFER_AMOUNT   (default: 1.0 BDT)
  MAX_TRANSFER_AMOUNT   (default: 50000.0 BDT)
"""
from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# DB connection pool
# ──────────────────────────────────────────────────────────────────────

_pool: psycopg2.pool.SimpleConnectionPool | None = None


def _get_pool() -> psycopg2.pool.SimpleConnectionPool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised")
    return _pool


def _build_dsn() -> str:
    return (
        f"host={os.environ['DB_HOST']} "
        f"port={os.environ.get('DB_PORT', '5432')} "
        f"dbname={os.environ['DB_NAME']} "
        f"user={os.environ['DB_USER']} "
        f"password={os.environ['DB_PASSWORD']} "
        "connect_timeout=5 "
        "sslmode=prefer"
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool
    log.info("Opening DB connection pool")
    _pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=_build_dsn(),
    )
    log.info("DB pool ready")
    yield
    if _pool:
        _pool.closeall()
        log.info("DB pool closed")


# ──────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="bKash Payment API",
    version="0.1.0",
    description="Simulated mobile financial service API for SecureCloud-BD",
    lifespan=lifespan,
)

MIN_AMOUNT = float(os.environ.get("MIN_TRANSFER_AMOUNT", "1.0"))
MAX_AMOUNT = float(os.environ.get("MAX_TRANSFER_AMOUNT", "50000.0"))


# ──────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────

class TransferRequest(BaseModel):
    from_user: str = Field(min_length=1, max_length=20)
    to_user:   str = Field(min_length=1, max_length=20)
    amount:    float

    @field_validator("amount")
    @classmethod
    def amount_in_range(cls, v: float) -> float:
        if v < MIN_AMOUNT or v > MAX_AMOUNT:
            raise ValueError(
                f"Amount must be between {MIN_AMOUNT} and {MAX_AMOUNT} BDT"
            )
        return round(v, 2)

    @field_validator("to_user")
    @classmethod
    def not_self_transfer(cls, v: str, info) -> str:
        from_user = info.data.get("from_user")
        if from_user and v == from_user:
            raise ValueError("Cannot transfer to yourself")
        return v


class TransferResponse(BaseModel):
    transaction_id: str
    from_user:      str
    to_user:        str
    amount:         float
    new_balance:    float
    timestamp:      str


class BalanceResponse(BaseModel):
    user_id:  str
    name:     str
    phone:    str
    balance:  float


# ──────────────────────────────────────────────────────────────────────
# DB helpers
# ──────────────────────────────────────────────────────────────────────

def _fetch_user(conn, user_id: str) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name, phone, balance FROM users WHERE phone = %s OR id::text = %s",
            (user_id, user_id),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )
    return {"id": row[0], "name": row[1], "phone": row[2], "balance": float(row[3])}


# ──────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
def health():
    try:
        conn = _get_pool().getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        _get_pool().putconn(conn)
        return {"status": "ok", "db": "reachable"}
    except Exception as exc:  # noqa: BLE001
        log.error("Health check failed: %s", exc)
        raise HTTPException(status_code=503, detail="DB unreachable")


@app.get("/balance/{user_id}", response_model=BalanceResponse, tags=["accounts"])
def get_balance(user_id: str):
    pool = _get_pool()
    conn = pool.getconn()
    try:
        user = _fetch_user(conn, user_id)
        return BalanceResponse(
            user_id=str(user["id"]),
            name=user["name"],
            phone=user["phone"],
            balance=user["balance"],
        )
    finally:
        pool.putconn(conn)


@app.post("/transfer", response_model=TransferResponse, tags=["payments"])
def transfer(req: TransferRequest):
    pool = _get_pool()
    conn = pool.getconn()
    try:
        conn.autocommit = False
        # Lock both rows in a consistent order to prevent deadlocks
        ids = sorted([req.from_user, req.to_user])
        with conn.cursor() as cur:
            # Fetch and lock sender first (ordered)
            cur.execute(
                "SELECT id, phone, balance FROM users "
                "WHERE phone = %s OR id::text = %s "
                "FOR UPDATE",
                (ids[0], ids[0]),
            )
            row0 = cur.fetchone()

            cur.execute(
                "SELECT id, phone, balance FROM users "
                "WHERE phone = %s OR id::text = %s "
                "FOR UPDATE",
                (ids[1], ids[1]),
            )
            row1 = cur.fetchone()

        if row0 is None:
            raise HTTPException(404, detail=f"User '{ids[0]}' not found")
        if row1 is None:
            raise HTTPException(404, detail=f"User '{ids[1]}' not found")

        # Map back to sender/receiver
        lookup = {r[1]: r for r in [row0, row1]}
        # Try phone first, fall back to id
        sender   = lookup.get(req.from_user) or next(
            (r for r in [row0, row1] if str(r[0]) == req.from_user), None
        )
        receiver = lookup.get(req.to_user) or next(
            (r for r in [row0, row1] if str(r[0]) == req.to_user), None
        )

        if sender is None:
            raise HTTPException(404, detail=f"User '{req.from_user}' not found")
        if receiver is None:
            raise HTTPException(404, detail=f"User '{req.to_user}' not found")

        sender_balance = float(sender[2])
        if sender_balance < req.amount:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Insufficient balance: available {sender_balance:.2f} BDT",
            )

        txn_id    = str(uuid.uuid4())
        now       = datetime.now(timezone.utc)
        new_balance = round(sender_balance - req.amount, 2)

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET balance = balance - %s WHERE id = %s",
                (req.amount, sender[0]),
            )
            cur.execute(
                "UPDATE users SET balance = balance + %s WHERE id = %s",
                (req.amount, receiver[0]),
            )
            cur.execute(
                """INSERT INTO transactions
                     (id, from_user_id, to_user_id, amount, created_at)
                   VALUES (%s, %s, %s, %s, %s)""",
                (txn_id, sender[0], receiver[0], req.amount, now),
            )
        conn.commit()
        log.info("Transfer %s: %s → %s  %.2f BDT", txn_id, sender[0], receiver[0], req.amount)

        return TransferResponse(
            transaction_id=txn_id,
            from_user=req.from_user,
            to_user=req.to_user,
            amount=req.amount,
            new_balance=new_balance,
            timestamp=now.isoformat(),
        )

    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        log.exception("Unexpected error during transfer")
        raise HTTPException(status_code=500, detail="Internal error") from exc
    finally:
        conn.autocommit = True
        pool.putconn(conn)
