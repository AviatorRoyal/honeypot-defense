"""
honeypot.py — VaultNet Honeypot Service
Mimics the real backend perfectly. Attackers never know they're here.
Novelty features:
  - Adaptive responses (evolve per attacker session)
  - Progressive deception (fake errors after repeated replays)
  - Canary token planting (track if attacker pivots)
  - Full attacker behavior logging
Part of: Honeypot-Based Replay Defense
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import secrets
import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'gateway'))
from crypto_utils import canary_registry, fingerprinter

app = Flask(__name__)
CORS(app)

HONEYPOT_PORT = 8002

# ─────────────────────────────────────────
# ATTACKER SESSION TRACKER
# ─────────────────────────────────────────
attacker_sessions = {}

def get_session(ip: str) -> dict:
    if ip not in attacker_sessions:
        attacker_sessions[ip] = {
            "replay_count": 0,
            "first_seen": time.time(),
            "tokens_issued": [],
            "last_endpoint": None,
            "degraded": False
        }
    return attacker_sessions[ip]


# ─────────────────────────────────────────
# FAKE DATA GENERATORS
# ─────────────────────────────────────────
FAKE_NAMES    = ["Alice Mercer", "Bob Tanner", "Carol Singh", "Dave Okonkwo"]
FAKE_ACCOUNTS = ["VN-4821-9032", "VN-7743-1190", "VN-3312-8874", "VN-9901-2255"]

def fake_balance(replay_count: int) -> float:
    base  = 24750.00
    drain = replay_count * 312.47
    return max(0.01, round(base - drain, 2))

def fake_txn_id() -> str:
    return "txn_" + secrets.token_hex(4)

def fake_token(ip: str, endpoint: str) -> str:
    token = canary_registry.issue(ip, endpoint)
    get_session(ip)["tokens_issued"].append(token)
    return token

def fake_transactions(replay_count: int) -> list:
    txns = [
        {"id": fake_txn_id(), "desc": "Salary deposit",       "amount": +5000.00, "date": "2025-03-01"},
        {"id": fake_txn_id(), "desc": "Rent payment",         "amount": -1200.00, "date": "2025-03-03"},
        {"id": fake_txn_id(), "desc": "Netflix subscription",  "amount": -15.99,  "date": "2025-03-05"},
    ]
    if replay_count > 4:
        txns.append({
            "id": fake_txn_id(),
            "desc": "Security hold — pending review",
            "amount": 0.00,
            "date": time.strftime("%Y-%m-%d")
        })
    return txns


# ─────────────────────────────────────────
# PROGRESSIVE DECEPTION ENGINE
# ─────────────────────────────────────────
def progressive_response(endpoint: str, ip: str, payload: dict):
    session = get_session(ip)
    session["replay_count"] += 1
    session["last_endpoint"] = endpoint
    count = session["replay_count"]

    fingerprinter.record_replay(ip, endpoint, payload.get("nonce", ""))

    if count <= 2:
        return _perfect_response(endpoint, ip, payload, count), 200
    elif count <= 5:
        time.sleep(0.3 + (count * 0.1))
        return _degraded_response(endpoint, ip, payload, count), 200
    elif count <= 9:
        time.sleep(0.8)
        return _soft_error_response(endpoint, count), 200
    else:
        return _lockout_response(endpoint, count), 200


def _perfect_response(endpoint, ip, payload, count):
    if endpoint == "login":
        return {
            "status": "success",
            "message": f"Welcome back, {FAKE_NAMES[0]}",
            "token": fake_token(ip, endpoint),
            "account": FAKE_ACCOUNTS[0],
            "name": FAKE_NAMES[0]
        }
    elif endpoint == "balance":
        return {
            "status": "success",
            "balance": fake_balance(count),
            "account": FAKE_ACCOUNTS[0],
            "name": FAKE_NAMES[0],
            "as_of": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    elif endpoint == "transactions":
        return {
            "status": "success",
            "transactions": fake_transactions(count),
            "count": 3
        }
    elif endpoint == "transfer":
        return {
            "status": "success",
            "message": "Transfer processed",
            "transaction_id": fake_txn_id(),
            "new_balance": fake_balance(count)
        }
    else:
        return {"status": "success", "message": "Request processed", "token": fake_token(ip, endpoint)}


def _degraded_response(endpoint, ip, payload, count):
    base = _perfect_response(endpoint, ip, payload, count)
    if "balance" in base:
        base["balance"] = fake_balance(count)
        base["as_of"] = "2025-03-07 23:59:59"
        base["_warning"] = "Data may be cached"
    return base


def _soft_error_response(endpoint, count):
    messages = [
        "Request throttled — please retry in a moment",
        "Session experiencing high latency",
        "Temporary service degradation detected",
        "Authentication service slow — request queued"
    ]
    return {
        "status": "warning",
        "message": messages[count % len(messages)],
        "retry_after": count * 2,
        "request_id": fake_txn_id()
    }


def _lockout_response(endpoint, count):
    return {
        "status": "error",
        "message": "Account temporarily suspended — unusual activity detected",
        "support_ref": "CASE-" + secrets.token_hex(3).upper(),
        "locked_until": time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3600)),
        "contact": "security@vaultnet.bank"
    }


# ─────────────────────────────────────────
# SITE ACTION LOGGER
# ─────────────────────────────────────────
site_action_log = []

@app.route("/site-log", methods=["POST", "OPTIONS"])
def site_log():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data   = request.get_json(silent=True) or {}
    action = data.get("action", "unknown")
    detail = data.get("detail", {})
    ip     = request.remote_addr
    entry  = {
        "time":   time.strftime("%H:%M:%S"),
        "ip":     ip,
        "action": action,
        "detail": detail
    }
    site_action_log.append(entry)
    session = get_session(ip)
    if "site_actions" not in session:
        session["site_actions"] = []
    session["site_actions"].append(entry)
    print(f"[Honeypot-Site] [{entry['time']}] IP={ip} ACTION={action} detail={detail}")
    return jsonify({"status": "ok"}), 200


# ─────────────────────────────────────────
# SITE-API ROUTES (called by honeypot website)
# These are simpler — no MAC/nonce needed,
# attacker is already inside the honeypot
# ─────────────────────────────────────────
@app.route("/site-api/<path:endpoint>", methods=["POST"])
def site_api(endpoint):
    data = request.get_json(silent=True) or {}
    ip   = request.remote_addr
    session = get_session(ip)
    session["replay_count"] += 1
    count = session["replay_count"]
    session["last_endpoint"] = endpoint

    fingerprinter.record_replay(ip, endpoint, "site")

    print(f"[Honeypot-Site-API] [{time.strftime('%H:%M:%S')}] IP={ip} /{endpoint} action#{count}")

    if count <= 2:
        resp = _perfect_response(endpoint, ip, data, count)
    elif count <= 5:
        time.sleep(0.4)
        resp = _degraded_response(endpoint, ip, data, count)
    elif count <= 9:
        time.sleep(0.8)
        resp = _soft_error_response(endpoint, count)
    else:
        resp = _lockout_response(endpoint, count)

    return jsonify(resp), 200


# ─────────────────────────────────────────
# SERVE HONEYPOT WEBSITE
# ─────────────────────────────────────────
@app.route("/", methods=["GET"])
@app.route("/site", methods=["GET"])
def honeypot_site():
    site_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot_site", "index.html")
    if not os.path.exists(site_path):
        return f"File not found at: {site_path}", 404
    with open(site_path, "r") as f:
        return f.read(), 200, {"Content-Type": "text/html"}


# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────
@app.route("/api/<path:endpoint>", methods=["POST", "GET"])
def honeypot_catch(endpoint):
    data        = request.get_json(silent=True) or {}
    ip          = data.get("_attacker_ip", request.remote_addr)
    payload_str = data.get("payload", "{}")

    try:
        payload = json.loads(payload_str)
    except Exception:
        payload = {}

    response, status = progressive_response(endpoint, ip, {**payload, "nonce": data.get("nonce", "")})

    session = get_session(ip)
    profile = fingerprinter.get_profile(ip)
    stage   = (
        "perfect"    if session["replay_count"] <= 2 else
        "degraded"   if session["replay_count"] <= 5 else
        "soft-error" if session["replay_count"] <= 9 else
        "lockout"
    )
    print(
        f"[Honeypot] [{time.strftime('%H:%M:%S')}] "
        f"IP={ip} endpoint=/{endpoint} "
        f"replay=#{session['replay_count']} "
        f"bot={'YES' if profile.get('is_bot') else 'NO'} "
        f"stage={stage}"
    )

    return jsonify(response), status


@app.route("/dashboard/attacker-sessions", methods=["GET"])
def get_attacker_sessions():
    return jsonify(attacker_sessions)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "honeypot", "port": HONEYPOT_PORT})


# ─────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"[Honeypot] VaultNet decoy starting on port {HONEYPOT_PORT}...")
    print(f"[Honeypot] Adaptive deception : ON")
    print(f"[Honeypot] Canary tokens      : ON")
    print(f"[Honeypot] Progressive stages : ON")
    app.run(host="0.0.0.0", port=8002, debug=False)