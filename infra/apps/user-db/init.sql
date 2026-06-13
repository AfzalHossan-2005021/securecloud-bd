-- SecureCloud-BD — bKash demo schema
-- Applied automatically by postgres:15 via /docker-entrypoint-initdb.d/

BEGIN;

-- ──────────────────────────────────────────────────────────────────────
-- Tables
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(120)   NOT NULL,
    phone      VARCHAR(20)    NOT NULL UNIQUE,  -- Bangladeshi 11-digit mobile number
    balance    NUMERIC(14, 2) NOT NULL DEFAULT 0.00
                              CHECK (balance >= 0),
    created_at TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    id           UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user_id INTEGER        NOT NULL REFERENCES users(id),
    to_user_id   INTEGER        NOT NULL REFERENCES users(id),
    amount       NUMERIC(14, 2) NOT NULL CHECK (amount > 0),
    created_at   TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────────
-- Indexes
-- ──────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_transactions_from_user ON transactions(from_user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_to_user   ON transactions(to_user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_created   ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_phone            ON users(phone);

-- ──────────────────────────────────────────────────────────────────────
-- Seed data — three demo accounts with Bangladeshi phone numbers
-- ──────────────────────────────────────────────────────────────────────

INSERT INTO users (name, phone, balance) VALUES
    ('Rahim Hossain',  '01711000001', 10000.00),
    ('Fatema Begum',   '01711000002',  5000.00),
    ('Karim Mia',      '01711000003', 25000.00)
ON CONFLICT (phone) DO NOTHING;

COMMIT;
