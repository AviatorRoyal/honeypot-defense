"""
crypto_utils.py — MAC generation, nonce store, timestamp validation
Part of: Honeypot-Based Replay Defense
"""

import hmac
import hashlib
import time
import secrets
import threading
import json
from collections import defaultdict

# ─────────────────────────────────────────
# SHARED SECRET KEY
# ─────────────────────────────────────────
SECRET_KEY = b"vaultnet-super-secret-key-2025"
TIME_WINDOW = 300  # seconds (5 min freshness window)

# ─────────────────────────────────────────
# MAC COMPUTATION
# ─────────────────────────────────────────
def compute_mac(payload: str, timestamp: str, nonce: str) -> str:
    """Compute HMAC-SHA256 over payload|timestamp|nonce"""
    message = f"{payload}|{timestamp}|{nonce}".encode("utf-8")
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

def verify_mac(payload: str, timestamp: str, nonce: str, mac: str) -> bool:
    """Constant-time MAC verification (prevents timing attacks)"""
    expected = compute_mac(payload, timestamp, nonce)
    return hmac.compare_digest(expected, mac)

# ─────────────────────────────────────────
# REQUEST BUILDER (used by client)
# ─────────────────────────────────────────
def build_request(payload: dict) -> dict:
    """Build a fresh authenticated request"""
    payload_str = json.dumps(payload, sort_keys=True)
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    mac = compute_mac(payload_str, timestamp, nonce)
    return {
        "payload": payload_str,
        "timestamp": timestamp,
        "nonce": nonce,
        "mac": mac
    }

# ─────────────────────────────────────────
# NONCE STORE (thread-safe, in-memory)
# ─────────────────────────────────────────
class NonceStore:
    def __init__(self):
        self._store = {}       # nonce -> timestamp of first use
        self._lock = threading.Lock()

    def is_replay(self, nonce: str) -> bool:
        """Returns True if nonce was seen before (replay detected)"""
        with self._lock:
            if nonce in self._store:
                return True
            self._store[nonce] = time.time()
            return False

    def cleanup(self):
        """Remove expired nonces (older than TIME_WINDOW)"""
        cutoff = time.time() - TIME_WINDOW
        with self._lock:
            expired = [n for n, t in self._store.items() if t < cutoff]
            for n in expired:
                del self._store[n]

    def count(self) -> int:
        return len(self._store)

# ─────────────────────────────────────────
# TIMESTAMP VALIDATOR
# ─────────────────────────────────────────
def validate_timestamp(timestamp: str) -> tuple[bool, int]:
    """
    Returns (is_valid, age_in_seconds)
    Valid if within TIME_WINDOW of current time
    """
    try:
        ts = int(timestamp)
        age = int(time.time() - ts)
        return abs(age) <= TIME_WINDOW, age
    except (ValueError, TypeError):
        return False, -1

# ─────────────────────────────────────────
# ATTACKER FINGERPRINTER (Novelty Feature)
# ─────────────────────────────────────────
class AttackerFingerprinter:
    """
    Profiles replay attackers by:
    - Replay frequency (requests/minute)
    - Inter-request timing (uniform = bot)
    - Targeted endpoints
    - Persistence (how long they keep trying)
    """
    def __init__(self):
        self._profiles = defaultdict(lambda: {
            "first_seen": None,
            "last_seen": None,
            "replay_count": 0,
            "endpoints": defaultdict(int),
            "intervals": [],          # time between replays
            "last_replay_time": None,
            "is_bot": False,
            "canary_used": False,     # did they use a canary token?
        })
        self._lock = threading.Lock()

    def record_replay(self, ip: str, endpoint: str, nonce: str):
        with self._lock:
            p = self._profiles[ip]
            now = time.time()

            if p["first_seen"] is None:
                p["first_seen"] = now
            if p["last_replay_time"] is not None:
                interval = now - p["last_replay_time"]
                p["intervals"].append(round(interval, 3))

            p["last_seen"] = now
            p["last_replay_time"] = now
            p["replay_count"] += 1
            p["endpoints"][endpoint] += 1

            # Bot detection: uniform timing = automated
            if len(p["intervals"]) >= 3:
                avg = sum(p["intervals"]) / len(p["intervals"])
                variance = sum((x - avg) ** 2 for x in p["intervals"]) / len(p["intervals"])
                p["is_bot"] = variance < 0.05  # Very uniform = bot

    def get_profile(self, ip: str) -> dict:
        with self._lock:
            return dict(self._profiles[ip])

    def all_profiles(self) -> dict:
        with self._lock:
            return {ip: dict(p) for ip, p in self._profiles.items()}

    def mark_canary_used(self, ip: str):
        with self._lock:
            if ip in self._profiles:
                self._profiles[ip]["canary_used"] = True

# ─────────────────────────────────────────
# CANARY TOKEN REGISTRY (Novelty Feature)
# ─────────────────────────────────────────
class CanaryRegistry:
    """
    Issues fake tokens to attackers via honeypot.
    If token is used again → attacker is pivoting.
    """
    def __init__(self):
        self._tokens = {}  # token -> {"ip", "issued_at", "endpoint"}
        self._lock = threading.Lock()

    def issue(self, ip: str, endpoint: str) -> str:
        token = "cvt_" + secrets.token_hex(12)  # canary prefix
        with self._lock:
            self._tokens[token] = {
                "ip": ip,
                "endpoint": endpoint,
                "issued_at": time.time(),
                "triggered": False
            }
        return token

    def check(self, token: str) -> dict | None:
        """Returns canary info if triggered, None if not a canary"""
        with self._lock:
            if token in self._tokens:
                self._tokens[token]["triggered"] = True
                return self._tokens[token]
        return None

    def all_triggered(self) -> list:
        with self._lock:
            return [t for t, v in self._tokens.items() if v["triggered"]]


# ─────────────────────────────────────────
# GLOBAL INSTANCES (shared across modules)
# ─────────────────────────────────────────
nonce_store = NonceStore()
fingerprinter = AttackerFingerprinter()
canary_registry = CanaryRegistry()