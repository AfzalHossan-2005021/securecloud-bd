"""
bKash-like frontend — Flask app with three routes.

Environment variables:
  PAYMENT_API_URL   URL of the payment-api service (default: http://payment-api:8000)
  PORT              Port to listen on (default: 5000)
  SECRET_KEY        Flask session secret
"""
from __future__ import annotations

import os
import logging

import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

PAYMENT_API_URL = os.environ.get("PAYMENT_API_URL", "http://payment-api:8000").rstrip("/")
REQUEST_TIMEOUT = 5  # seconds


def _api_get(path: str) -> tuple[dict, int]:
    try:
        r = requests.get(f"{PAYMENT_API_URL}{path}", timeout=REQUEST_TIMEOUT)
        return r.json(), r.status_code
    except requests.RequestException as exc:
        log.error("Payment API unreachable: %s", exc)
        return {"error": "Payment service unavailable"}, 503


def _api_post(path: str, payload: dict) -> tuple[dict, int]:
    try:
        r = requests.post(
            f"{PAYMENT_API_URL}{path}",
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        return r.json(), r.status_code
    except requests.RequestException as exc:
        log.error("Payment API unreachable: %s", exc)
        return {"error": "Payment service unavailable"}, 503


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/balance", methods=["GET", "POST"])
def balance():
    result = None
    error = None

    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        if not user_id:
            flash("Please enter a User ID.", "warning")
            return redirect(url_for("balance"))

        data, status = _api_get(f"/balance/{user_id}")
        if status == 200:
            result = data
        elif status == 404:
            error = f"User '{user_id}' not found."
        else:
            error = data.get("error", "Unexpected error from payment service.")

    return render_template("balance.html", result=result, error=error)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    receipt = None
    error = None

    if request.method == "POST":
        from_user = request.form.get("from_user", "").strip()
        to_user   = request.form.get("to_user", "").strip()
        amount_str = request.form.get("amount", "").strip()

        # Client-side validation
        if not from_user or not to_user or not amount_str:
            flash("All fields are required.", "warning")
            return redirect(url_for("transfer"))
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError
        except ValueError:
            flash("Amount must be a positive number.", "warning")
            return redirect(url_for("transfer"))

        data, status = _api_post(
            "/transfer",
            {"from_user": from_user, "to_user": to_user, "amount": amount},
        )
        if status == 200:
            receipt = data
        else:
            error = data.get("detail") or data.get("error") or "Transfer failed."

    return render_template("transfer.html", receipt=receipt, error=error)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "frontend"}), 200


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
