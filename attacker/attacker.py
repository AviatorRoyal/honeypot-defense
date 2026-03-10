"""
attacker.py — Replay Attack Simulator
Simulates a real-world attacker who has captured valid requests
and attempts to replay them against the VaultNet gateway.

Attack scenarios:
  1. Basic replay       — same request sent multiple times
  2. Endpoint sweep     — replay across multiple endpoints
  3. Rapid-fire bot     — high-frequency automated replays
  4. Canary pivot       — tries to reuse tokens from honeypot responses
  5. Tamper attempt     — modifies payload (MAC will fail)

Part of: Honeypot-Based Replay Defense
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'gateway'))

import requests
import time
import json
import hmac
import hashlib
import secrets

from crypto_utils import build_request

GATEWAY = "http://127.0.0.1:8000"

# ─────────────────────────────────────────
# COLORS FOR TERMINAL OUTPUT
# ─────────────────────────────────────────
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
B  = "\033[94m"   # blue
DIM = "\033[2m"
BOLD = "\033[1m"
RST = "\033[0m"

def banner(text, color=Y):
    width = 58
    print(f"\n{color}{BOLD}{'─'*width}")
    print(f"  {text}")
    print(f"{'─'*width}{RST}")

def result_line(label, resp: dict, expected_honeypot=True):
    status  = resp.get("status", "?")
    message = resp.get("message", str(resp))[:55]
    token   = resp.get("token", resp.get("session_token", ""))
    is_canary = str(token).startswith("cvt_")

    if is_canary:
        icon = f"{Y}🪤 CANARY TOKEN ISSUED{RST}"
    elif expected_honeypot and status == "success":
        icon = f"{Y}🍯 Honeypot response{RST}"
    elif status == "success":
        icon = f"{G}✅ Real backend{RST}"
    elif status in ("error", "warning"):
        icon = f"{R}🚫 {status.upper()}{RST}"
    else:
        icon = f"{DIM}?  Unknown{RST}"

    print(f"  {DIM}{label:<22}{RST} → {icon}  {DIM}{message}{RST}")
    if is_canary:
        print(f"  {Y}     token={token}{RST}")

def post(endpoint: str, data: dict) -> dict:
    try:
        r = requests.post(
            f"{GATEWAY}/api/{endpoint}",
            json=data, timeout=6
        )
        return r.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─────────────────────────────────────────
# STEP 0 — Capture a valid request first
# ─────────────────────────────────────────
def capture_valid_request(endpoint: str, payload: dict) -> dict:
    """Send a fresh request and capture it for later replay"""
    req = build_request(payload)
    resp = post(endpoint, req)
    print(f"  {G}[capture]{RST} /{endpoint} → {resp.get('status','?')} — {resp.get('message', '')[:40]}")
    return req   # Return the signed request (attacker saves this)


# ─────────────────────────────────────────
# SCENARIO 1 — Basic Replay
# ─────────────────────────────────────────
def scenario_basic_replay():
    banner("SCENARIO 1 — Basic Replay Attack", R)
    print(f"  {DIM}Capturing one valid login request, then replaying 5 times…{RST}\n")

    captured = capture_valid_request("login", {
        "username": "alice", "password": "alice123"
    })
    time.sleep(0.3)

    for i in range(1, 6):
        resp = post("login", captured)
        result_line(f"Replay #{i}", resp)
        time.sleep(0.2)


# ─────────────────────────────────────────
# SCENARIO 2 — Endpoint Sweep
# ─────────────────────────────────────────
def scenario_endpoint_sweep():
    banner("SCENARIO 2 — Endpoint Sweep", R)
    print(f"  {DIM}Attacker replays captured requests across all endpoints…{RST}\n")

    endpoints = {
        "login":        {"username": "alice", "password": "alice123"},
        "balance":      {"token": "stolen-token-abc"},
        "transactions": {"token": "stolen-token-abc"},
        "transfer":     {"token": "stolen-token-abc", "to": "attacker", "amount": 9999},
    }

    captured = {}
    print(f"  {DIM}[capturing fresh requests…]{RST}")
    for ep, payload in endpoints.items():
        captured[ep] = capture_valid_request(ep, payload)
        time.sleep(0.15)

    print(f"\n  {DIM}[now replaying each captured request twice…]{RST}\n")
    for ep, req in captured.items():
        for i in range(1, 3):
            resp = post(ep, req)
            result_line(f"/{ep} replay #{i}", resp)
            time.sleep(0.15)


# ─────────────────────────────────────────
# SCENARIO 3 — Rapid-Fire Bot
# ─────────────────────────────────────────
def scenario_rapid_fire():
    banner("SCENARIO 3 — Rapid-Fire Bot Attack", R)
    print(f"  {DIM}Bot sends 12 replays with near-uniform timing (bot fingerprint)…{RST}\n")

    captured = capture_valid_request("transfer", {
        "token": "stolen-token", "to": "attacker_wallet", "amount": 5000
    })
    time.sleep(0.2)

    for i in range(1, 13):
        resp = post("transfer", captured)
        result_line(f"Bot replay #{i:02d}", resp)
        time.sleep(0.08)   # Uniform 80ms — triggers bot detection

    print(f"\n  {Y}→ Gateway fingerprinter should now flag this IP as a BOT{RST}")


# ─────────────────────────────────────────
# SCENARIO 4 — Canary Token Pivot
# ─────────────────────────────────────────
def scenario_canary_pivot():
    banner("SCENARIO 4 — Canary Token Pivot Attempt", R)
    print(f"  {DIM}Attacker uses a token received from honeypot to make new requests…{RST}\n")

    # First, trigger a replay to get a honeypot response with a canary token
    captured = capture_valid_request("login", {
        "username": "alice", "password": "alice123"
    })
    time.sleep(0.2)

    print(f"  {DIM}[replaying to get honeypot token…]{RST}")
    resp = post("login", captured)
    result_line("Replay → honeypot", resp)

    honey_token = resp.get("token", "")
    if not honey_token:
        print(f"  {R}No token in response — skipping pivot{RST}")
        return

    print(f"\n  {Y}Attacker received token: {honey_token[:30]}…{RST}")
    print(f"  {DIM}Attacker now tries to use this token for balance/transfer…{RST}\n")
    time.sleep(0.3)

    # Attacker builds fresh requests using the canary token
    for ep in ["balance", "transfer"]:
        payload = {"token": honey_token}
        if ep == "transfer":
            payload.update({"to": "attacker", "amount": 9999})
        fresh_req = build_request(payload)
        resp = post(ep, fresh_req)
        result_line(f"Pivot /{ep}", resp, expected_honeypot=False)
        time.sleep(0.2)

    print(f"\n  {Y}→ Gateway canary registry should now show this token as triggered{RST}")


# ─────────────────────────────────────────
# SCENARIO 5 — Tamper Attempt
# ─────────────────────────────────────────
def scenario_tamper():
    banner("SCENARIO 5 — Payload Tamper Attempt", R)
    print(f"  {DIM}Attacker tries to modify the transfer amount — MAC will fail…{RST}\n")

    original = capture_valid_request("transfer", {
        "token": "stolen-token", "to": "alice", "amount": 10
    })
    time.sleep(0.2)

    # Attacker modifies the payload but keeps the original MAC
    tampered_payload = json.loads(original["payload"])
    tampered_payload["amount"] = 99999
    tampered_payload["to"]     = "attacker_offshore"

    tampered = {
        **original,
        "payload": json.dumps(tampered_payload, sort_keys=True)
        # MAC stays the same — mismatch!
    }

    resp = post("transfer", tampered)
    result_line("Tampered request", resp, expected_honeypot=False)
    print(f"\n  {G}→ Correctly rejected — HMAC-SHA256 caught the tampering{RST}")


# ─────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────
def print_summary():
    banner("FETCHING GATEWAY STATS", B)
    try:
        stats = requests.get(f"{GATEWAY}/dashboard/stats", timeout=4).json()
        print(f"  {'Total requests':<28} {stats.get('total', '?')}")
        print(f"  {G}{'✅ Fresh → Real Backend':<28}{RST} {stats.get('allowed', '?')}")
        print(f"  {Y}{'🍯 Replays → Honeypot':<28}{RST} {stats.get('honeypot', '?')}")
        print(f"  {R}{'🚫 Rejected (bad MAC)':<28}{RST} {stats.get('rejected', '?')}")
        print(f"  {Y}{'🪤 Canary tokens triggered':<28}{RST} {stats.get('canaries_triggered', '?')}")
        print(f"  {DIM}{'Nonces in store':<28}{RST} {stats.get('nonces_stored', '?')}")
    except Exception as e:
        print(f"  {R}Could not fetch stats: {e}{RST}")

    banner("ATTACKER PROFILES", B)
    try:
        profiles = requests.get(f"{GATEWAY}/dashboard/profiles", timeout=4).json()
        if not profiles:
            print(f"  {DIM}No profiles recorded yet{RST}")
        for ip, p in profiles.items():
            bot_label = f"{R}BOT{RST}" if p.get("is_bot") else f"{G}human{RST}"
            print(f"\n  IP: {B}{ip}{RST}  [{bot_label}]")
            print(f"    Replays     : {p.get('replay_count', 0)}")
            print(f"    Endpoints   : {dict(p.get('endpoints', {}))}")
            print(f"    Canary used : {Y+'YES'+RST if p.get('canary_used') else 'no'}")
            intervals = p.get("intervals", [])
            if intervals:
                avg = sum(intervals)/len(intervals)
                print(f"    Avg interval: {avg:.3f}s  (uniform={'YES' if p.get('is_bot') else 'no'})")
    except Exception as e:
        print(f"  {R}Could not fetch profiles: {e}{RST}")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{R}{BOLD}{'='*58}")
    print(f"   VAULTNET REPLAY ATTACK SIMULATOR")
    print(f"   Target: {GATEWAY}")
    print(f"{'='*58}{RST}")

    # Check gateway is up
    try:
        requests.get(f"{GATEWAY}/health", timeout=3)
    except Exception:
        print(f"\n{R}[ERROR] Gateway not reachable at {GATEWAY}")
        print(f"        Start all services first with: python run_all.py{RST}\n")
        sys.exit(1)

    scenario_basic_replay()
    time.sleep(0.5)

    scenario_endpoint_sweep()
    time.sleep(0.5)

    scenario_rapid_fire()
    time.sleep(0.5)

    scenario_canary_pivot()
    time.sleep(0.5)

    scenario_tamper()
    time.sleep(0.5)

    print_summary()

    print(f"\n{G}{BOLD}{'='*58}")
    print(f"   Simulation complete.")
    print(f"   All replays were silently routed to the honeypot.")
    print(f"   Attacker never knew.{RST}")
    print(f"{G}{'='*58}{RST}\n")