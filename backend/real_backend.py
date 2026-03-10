"""
real_backend.py — VaultNet Real Banking API
Only receives verified fresh requests from the gateway.
Part of: Honeypot-Based Replay Defense
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import secrets
import json

app = Flask(__name__)
CORS(app)

REAL_BACKEND_PORT = 8001

# ─────────────────────────────────────────
# FAKE DATABASE
# ─────────────────────────────────────────
USERS = {
    "alice": {
        "password": "alice123",
        "name": "Alice Mercer",
        "balance": 24750.00,
        "account": "VN-4821-9032",
        "transactions": [
            {"id": "txn_001", "desc": "Salary deposit",     "amount": +5000.00, "date": "2025-03-01"},
            {"id": "txn_002", "desc": "Rent payment",       "amount": -1200.00, "date": "2025-03-03"},
            {"id": "txn_003", "desc": "Netflix subscription","amount": -15.99,  "date": "2025-03-05"},
            {"id": "txn_004", "desc": "Grocery store",      "amount": -87.43,  "date": "2025-03-07"},
        ]
    },
    "bob": {
        "password": "bob456",
        "name": "Bob Tanner",
        "balance": 8320.50,
        "account": "VN-7743-1190",
        "transactions": [
            {"id": "txn_010", "desc": "Freelance payment",  "amount": +2000.00, "date": "2025-03-02"},
            {"id": "txn_011", "desc": "Electricity bill",   "amount": -145.00,  "date": "2025-03-04"},
        ]
    }
}

# Active sessions: token -> username
active_sessions = {}

def get_user_from_token(token: str):
    return active_sessions.get(token)

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    payload = json.loads(data.get("payload", "{}"))

    username = payload.get("username", "")
    password = payload.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({
            "status": "error",
            "message": "Invalid credentials"
        }), 401

    # Issue real session token
    token = "vn_" + secrets.token_hex(16)
    active_sessions[token] = username

    return jsonify({
        "status": "success",
        "message": f"Welcome back, {user['name']}",
        "token": token,
        "account": user["account"],
        "name": user["name"]
    })


@app.route("/api/balance", methods=["POST"])
def balance():
    data = request.get_json(silent=True) or {}
    payload = json.loads(data.get("payload", "{}"))
    token = payload.get("token", "")

    username = get_user_from_token(token)
    if not username:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    user = USERS[username]
    return jsonify({
        "status": "success",
        "balance": user["balance"],
        "account": user["account"],
        "name": user["name"],
        "as_of": time.strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/api/transactions", methods=["POST"])
def transactions():
    data = request.get_json(silent=True) or {}
    payload = json.loads(data.get("payload", "{}"))
    token = payload.get("token", "")

    username = get_user_from_token(token)
    if not username:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    user = USERS[username]
    return jsonify({
        "status": "success",
        "transactions": user["transactions"],
        "count": len(user["transactions"])
    })


@app.route("/api/transfer", methods=["POST"])
def transfer():
    data = request.get_json(silent=True) or {}
    payload = json.loads(data.get("payload", "{}"))
    token = payload.get("token", "")

    username = get_user_from_token(token)
    if not username:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    amount = float(payload.get("amount", 0))
    to     = payload.get("to", "")
    user   = USERS[username]

    if amount <= 0 or amount > user["balance"]:
        return jsonify({"status": "error", "message": "Invalid transfer amount"}), 400

    # Process transfer
    user["balance"] -= amount
    txn_id = "txn_" + secrets.token_hex(4)
    user["transactions"].append({
        "id": txn_id,
        "desc": f"Transfer to {to}",
        "amount": -amount,
        "date": time.strftime("%Y-%m-%d")
    })

    return jsonify({
        "status": "success",
        "message": f"Transferred ${amount:.2f} to {to}",
        "transaction_id": txn_id,
        "new_balance": user["balance"]
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.get_json(silent=True) or {}
    payload = json.loads(data.get("payload", "{}"))
    token = payload.get("token", "")

    if token in active_sessions:
        del active_sessions[token]

    return jsonify({"status": "success", "message": "Logged out"})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "real_backend", "port": REAL_BACKEND_PORT})


# ─────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"[Real Backend] VaultNet API starting on port {REAL_BACKEND_PORT}...")
    print(f"[Real Backend] Users: {list(USERS.keys())}")
    app.run(host="0.0.0.0", port=8001, debug=False)