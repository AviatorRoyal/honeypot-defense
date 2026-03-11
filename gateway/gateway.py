"""
gateway.py — Verification Gateway Server
Handles MAC verification, timestamp validation, nonce checking,
and routes fresh requests to real backend or replays to honeypot.
Part of: Honeypot-Based Replay Defense
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import time
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import (
    verify_mac, validate_timestamp, nonce_store,
    fingerprinter, canary_registry
)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
REAL_BACKEND_URL = "http://127.0.0.1:8001"
HONEYPOT_URL     = "http://127.0.0.1:8002"
GATEWAY_PORT     = 8000

app = Flask(__name__)
CORS(app)

# Shared event log for dashboard
event_log = []

def log_event(verdict: str, endpoint: str, ip: str, detail: str = ""):
    event_log.append({
        "time": time.strftime("%H:%M:%S"),
        "verdict": verdict,
        "endpoint": endpoint,
        "ip": ip,
        "detail": detail
    })
    # Keep last 200 events
    if len(event_log) > 200:
        event_log.pop(0)

# ─────────────────────────────────────────
# CANARY CHECK MIDDLEWARE
# ─────────────────────────────────────────
def check_for_canary(data: dict, ip: str):
    """Detect if attacker is reusing a canary token we issued"""
    token = data.get("session_token", "") or data.get("token", "")
    if token.startswith("cvt_"):
        info = canary_registry.check(token)
        if info:
            fingerprinter.mark_canary_used(ip)
            log_event("🪤 CANARY TRIGGERED", "/canary", ip,
                      f"Attacker reused fake token from {info['endpoint']}")

# ─────────────────────────────────────────
# MAIN GATEWAY ROUTE
# ─────────────────────────────────────────
@app.route("/api/<path:endpoint>", methods=["POST", "GET", "OPTIONS"])
def gateway(endpoint):
    if request.method == "OPTIONS":
        return jsonify({}), 200

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    data = request.get_json(silent=True) or {}

    # Check if attacker is reusing canary tokens
    check_for_canary(data, ip)

    payload   = data.get("payload", "")
    timestamp = data.get("timestamp", "")
    nonce     = data.get("nonce", "")
    mac       = data.get("mac", "")

    # ── STEP 1: MAC Verification ──────────────────────────────
    if not verify_mac(payload, timestamp, nonce, mac):
        log_event("🚫 REJECTED", endpoint, ip, "MAC mismatch — tampered or forged request")
        return jsonify({
            "status": "error",
            "message": "Authentication failed"
        }), 401

    # ── STEP 2: Timestamp Validation ─────────────────────────
    valid_ts, age = validate_timestamp(timestamp)
    if not valid_ts:
        log_event("🚫 REJECTED", endpoint, ip, f"Expired timestamp — age: {age}s")
        return jsonify({
            "status": "error",
            "message": "Request expired"
        }), 401

    # ── STEP 3: Nonce Check ───────────────────────────────────
    if nonce_store.is_replay(nonce):
        # ⚠️ REPLAY DETECTED — silent redirect to honeypot
        fingerprinter.record_replay(ip, endpoint, nonce)
        profile = fingerprinter.get_profile(ip)
        replay_count = profile["replay_count"]
        is_bot = profile["is_bot"]

        log_event(
            "🍯 HONEYPOT",
            endpoint, ip,
            f"Replay #{replay_count} | {'BOT' if is_bot else 'human'} | age: {age}s"
        )

        # Forward silently to honeypot (attacker never knows)
        try:
            resp = requests.post(
                f"{HONEYPOT_URL}/api/{endpoint}",
                json={**data, "_attacker_ip": ip, "_replay_count": replay_count},
                timeout=5
            )
            return jsonify(resp.json()), resp.status_code
        except Exception as e:
            # Even if honeypot fails, return plausible response
            return jsonify({"status": "success", "message": "Processed"}), 200

    # ── STEP 4: Fresh Request → Real Backend ─────────────────
    log_event("✅ ALLOWED", endpoint, ip, f"Fresh request — age: {age}s")
    try:
        resp = requests.post(
            f"{REAL_BACKEND_URL}/api/{endpoint}",
            json=data,
            timeout=5
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": "Backend unavailable"}), 503


# ─────────────────────────────────────────
# DASHBOARD DATA ENDPOINT
# ─────────────────────────────────────────
@app.route("/dashboard/events", methods=["GET"])
def get_events():
    return jsonify(event_log[-50:])

@app.route("/dashboard/profiles", methods=["GET"])
def get_profiles():
    profiles = fingerprinter.all_profiles()
    # Serialize defaultdicts
    for ip, p in profiles.items():
        p["endpoints"] = dict(p["endpoints"])
    return jsonify(profiles)

@app.route("/dashboard/stats", methods=["GET"])
def get_stats():
    total = len(event_log)
    allowed  = sum(1 for e in event_log if e["verdict"] == "✅ ALLOWED")
    honeypot = sum(1 for e in event_log if e["verdict"] == "🍯 HONEYPOT")
    rejected = sum(1 for e in event_log if e["verdict"] == "🚫 REJECTED")
    canaries = sum(1 for e in event_log if e["verdict"] == "🪤 CANARY TRIGGERED")
    return jsonify({
        "total": total,
        "allowed": allowed,
        "honeypot": honeypot,
        "rejected": rejected,
        "canaries_triggered": canaries,
        "nonces_stored": nonce_store.count()
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "gateway", "port": GATEWAY_PORT})


# ─────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"[Gateway] Starting on port {GATEWAY_PORT}...")
    print(f"[Gateway] Routing fresh {REAL_BACKEND_URL}")
    print(f"[Gateway] Routing replays {HONEYPOT_URL}")
    app.run(host="0.0.0.0", port=8000, debug=False)
