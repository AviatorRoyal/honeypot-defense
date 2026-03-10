# 🛡️ VaultNet — Honeypot-Based Replay Defense

A cybersecurity project that detects replay attacks and silently redirects attackers to a honeypot instead of simply rejecting them — allowing us to observe, deceive, and profile attacker behavior in real time.

---

## 📌 What is a Replay Attack?

A replay attack occurs when an attacker captures a previously valid authenticated request and sends it again to gain unauthorized access or repeat an action — without ever breaking any cryptography.

**Traditional defense:** Replay detected → request rejected  
**Our approach:** Replay detected → request silently redirected to honeypot 🍯

---

## 🏗️ System Architecture

```
Legitimate User (Browser)
        │  fresh request (MAC + Timestamp + Nonce)
        ▼
┌─────────────────────────┐
│   Verification Gateway  │  :8000
│  1. MAC Verification    │
│  2. Timestamp Check     │──── fresh ────► Real Backend :8001
│  3. Nonce Check         │──── replay ───► Honeypot     :8002
└─────────────────────────┘
```

Every request is signed with **HMAC-SHA256** using a shared secret key:
```
MAC = H(Key || Payload || Timestamp || Nonce)
```

---

## ✨ Novelty Features

| Feature | Description |
|---|---|
| 🎭 Adaptive Honeypot | Responses evolve across 4 deception stages |
| 🤖 Bot Detection | Uniform request timing fingerprints automated attackers |
| 🪤 Canary Tokens | Fake tokens planted in responses — if reused, attacker is flagged |
| 📉 Progressive Deception | Balance drains, throttle warnings, then fake account lockout |
| 📊 Live Monitor | Real-time terminal dashboard showing all attack activity |
| 🌐 Honeypot Website | Full fake banking site served to attacker's browser |

### Deception Stages
| Actions | What Attacker Sees |
|---|---|
| 1–2 | Perfect response — looks completely real ✅ |
| 3–5 | Balance slowly draining, stale timestamps 🐢 |
| 6–9 | Rate limit warnings, throttled responses ⚠️ |
| 10+ | Account suspended screen 🔒 |

---

## 📁 Project Structure

```
honeypot-defense/
├── gateway/
│   ├── crypto_utils.py      # MAC, nonce store, fingerprinter, canary registry
│   └── gateway.py           # Routes fresh → backend, replays → honeypot
├── backend/
│   └── real_backend.py      # Real VaultNet banking API
├── honeypot/
│   ├── honeypot.py          # Adaptive deception engine
│   └── honeypot_site/
│       └── index.html       # Fake VaultNet website served to attacker
├── website/
│   └── index.html           # Real VaultNet website for legitimate users
├── attacker/
│   └── attacker.py          # Replay attack simulator (5 scenarios)
├── dashboard/
│   └── monitor.py           # Live terminal threat dashboard
├── requirements.txt
├── run_all.py               # One command to start everything
└── .gitignore
```

---

## 🚀 Setup & Running

### Prerequisites
- Python 3.10+
- pip

### Install
```bash
git clone https://github.com/YOUR_USERNAME/honeypot-defense.git
cd honeypot-defense

# Mac/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

### Run Everything
```bash
python run_all.py
```

Wait for `✅ ALL SERVICES RUNNING` then open `website/index.html` in your browser.

---

## 🎮 Demo Setup

For the best demo, use **4 windows simultaneously:**

| Window | Command | Role |
|---|---|---|
| Terminal 1 | `python run_all.py` | Starts all servers |
| Terminal 2 | `python dashboard/monitor.py` | Live threat monitor |
| Terminal 3 | `python attacker/attacker.py` | Runs attack scenarios |
| Browser | Open `website/index.html` | Legitimate user view |

### Two-Machine Demo
To simulate a real attacker on a separate machine:
1. Find your IP: `ipconfig getifaddr en0` (Mac) or `ipconfig` (Windows)
2. Attacker opens `http://YOUR_IP:8002` in their browser
3. They log in with stolen credentials: `alice / alice123`
4. Watch the monitor — every action they take is logged and deceived

Or use **ngrok** to expose across different networks:
```bash
ngrok http 8002   # gives attacker a public URL
```

---

## 👤 Demo Credentials

| User | Password | Role |
|---|---|---|
| alice | alice123 | Legitimate user |
| bob | bob456 | Legitimate user |

---

## 🔌 Service Ports

| Service | Port | Description |
|---|---|---|
| Gateway | 8000 | All traffic enters here |
| Real Backend | 8001 | Only receives verified fresh requests |
| Honeypot | 8002 | Receives all replayed requests |

---

## 🗂️ Attack Scenarios (attacker.py)

1. **Basic Replay** — same login request sent 5 times
2. **Endpoint Sweep** — replays across login, balance, transactions, transfer
3. **Rapid-Fire Bot** — 12 replays with uniform timing, triggers bot detection
4. **Canary Token Pivot** — attacker reuses fake token from honeypot response
5. **Tamper Attempt** — modified payload, MAC verification rejects it

---

## 🔒 Security Properties

| Property | Mechanism |
|---|---|
| Authenticity | HMAC-SHA256 with shared key |
| Freshness | ±5 minute timestamp window |
| Uniqueness | Per-request nonce stored server-side |
| Deception | Honeypot mimics real responses perfectly |
| Observation | Full attacker behavior logged silently |

---

## 🧠 Threat Model

The attacker **does not break cryptography**. Instead they obtain valid requests through:
- Compromised client devices
- Leaked logs
- Proxy interception
- Network sniffing

They replay the exact captured request — which our system detects via nonce reuse and silently diverts.

---

## 👥 Team

Built as part of a cybersecurity research project on active deception-based defenses.
