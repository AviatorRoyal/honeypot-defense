"""
monitor.py — Live Threat Monitoring Dashboard
Real-time terminal dashboard showing all gateway activity.
Polls the gateway every second and renders a live view.

Part of: Honeypot-Based Replay Defense
"""

import requests
import time
import os
import sys

GATEWAY = "http://127.0.0.1:8000"
REFRESH = 1.5  # seconds between polls

# ─────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────
R    = "\033[91m"
Y    = "\033[93m"
G    = "\033[92m"
B    = "\033[94m"
C    = "\033[96m"
M    = "\033[95m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"
CLR  = "\033[2J\033[H"   # clear screen + move to top

W = 72  # dashboard width

# ─────────────────────────────────────────
# DRAW HELPERS
# ─────────────────────────────────────────
def clear():
    print(CLR, end="")

def line(char="─", color=DIM):
    print(f"{color}{'─'*W}{RST}")

def header(title: str, color=BOLD):
    print(f"{color}{'─'*W}")
    print(f"  {title}")
    print(f"{'─'*W}{RST}")

def row(label: str, value: str, label_color=DIM, value_color=RST):
    print(f"  {label_color}{label:<28}{RST}{value_color}{value}{RST}")

def bar(value: int, total: int, width=30, color=G) -> str:
    if total == 0:
        return f"{DIM}{'░'*width}{RST}"
    filled = int((value / total) * width)
    empty  = width - filled
    return f"{color}{'█'*filled}{DIM}{'░'*empty}{RST} {value}"

def verdict_color(verdict: str) -> str:
    if "ALLOWED" in verdict or "FRESH" in verdict:  return G
    if "HONEYPOT" in verdict:                        return Y
    if "REJECTED" in verdict:                        return R
    if "CANARY" in verdict:                          return M
    return DIM

def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n-1] + "…"


# ─────────────────────────────────────────
# FETCH DATA
# ─────────────────────────────────────────
def fetch_stats() -> dict:
    try:
        return requests.get(f"{GATEWAY}/dashboard/stats", timeout=2).json()
    except Exception:
        return {}

def fetch_events() -> list:
    try:
        return requests.get(f"{GATEWAY}/dashboard/events", timeout=2).json()
    except Exception:
        return []

def fetch_profiles() -> dict:
    try:
        return requests.get(f"{GATEWAY}/dashboard/profiles", timeout=2).json()
    except Exception:
        return {}

def fetch_attacker_sessions() -> dict:
    try:
        return requests.get("http://127.0.0.1:8002/dashboard/attacker-sessions", timeout=2).json()
    except Exception:
        return {}


# ─────────────────────────────────────────
# RENDER SECTIONS
# ─────────────────────────────────────────
def render_header(stats: dict):
    now   = time.strftime("%Y-%m-%d  %H:%M:%S")
    total = stats.get("total", 0)

    print(f"{BOLD}{'━'*W}{RST}")
    print(f"{BOLD}  🛡  VAULTNET — HONEYPOT REPLAY DEFENSE  ·  LIVE MONITOR{RST}")
    print(f"{DIM}  {now}   ·   {total} total requests processed   ·   refresh {REFRESH}s{RST}")
    print(f"{BOLD}{'━'*W}{RST}")


def render_stats(stats: dict):
    total    = stats.get("total", 0)
    allowed  = stats.get("allowed", 0)
    honeypot = stats.get("honeypot", 0)
    rejected = stats.get("rejected", 0)
    canaries = stats.get("canaries_triggered", 0)
    nonces   = stats.get("nonces_stored", 0)

    print(f"\n{BOLD}  TRAFFIC OVERVIEW{RST}")
    line()
    row("✅  Fresh → Real Backend",  bar(allowed,  total, color=G), G)
    row("🍯  Replays → Honeypot",    bar(honeypot, total, color=Y), Y)
    row("🚫  Rejected (bad MAC)",    bar(rejected, total, color=R), R)
    row("🪤  Canary tokens used",    str(canaries),  M, M if canaries > 0 else DIM)
    row("🔑  Nonces in store",       str(nonces),    DIM)
    print()


def render_events(events: list):
    print(f"{BOLD}  RECENT GATEWAY EVENTS  {DIM}(last 12){RST}")
    line()
    if not events:
        print(f"  {DIM}No events yet — waiting for traffic…{RST}\n")
        return

    for e in reversed(events[-12:]):
        verdict = e.get("verdict", "?")
        vc      = verdict_color(verdict)
        t       = e.get("time", "--:--:--")
        ep      = "/" + e.get("endpoint", "?")
        ip      = e.get("ip", "?")
        detail  = truncate(e.get("detail", ""), 30)

        print(
            f"  {DIM}{t}{RST}  "
            f"{vc}{verdict:<22}{RST}  "
            f"{C}{ep:<18}{RST}  "
            f"{DIM}{ip:<16}{RST}  "
            f"{DIM}{detail}{RST}"
        )
    print()


def render_attacker_profiles(profiles: dict, sessions: dict):
    print(f"{BOLD}  ATTACKER PROFILES{RST}")
    line()

    if not profiles:
        print(f"  {DIM}No attackers detected yet.{RST}\n")
        return

    for ip, p in profiles.items():
        is_bot     = p.get("is_bot", False)
        count      = p.get("replay_count", 0)
        canary     = p.get("canary_used", False)
        endpoints  = dict(p.get("endpoints", {}))
        intervals  = p.get("intervals", [])
        avg_int    = f"{sum(intervals)/len(intervals):.3f}s" if intervals else "—"

        # Deception stage from honeypot sessions
        session    = sessions.get(ip, {})
        hp_count   = session.get("replay_count", 0)
        stage = (
            f"{G}perfect{RST}"    if hp_count <= 2 else
            f"{Y}degraded{RST}"   if hp_count <= 5 else
            f"{R}soft-error{RST}" if hp_count <= 9 else
            f"{R}{BOLD}lockout{RST}"
        )

        bot_badge  = f"{R}[BOT]{RST}" if is_bot else f"{G}[human]{RST}"
        can_badge  = f"  {M}🪤 CANARY TRIGGERED{RST}" if canary else ""

        print(f"  {B}{BOLD}{ip}{RST}  {bot_badge}{can_badge}")
        row("  Replays intercepted",  str(count),    DIM, Y if count > 0 else DIM)
        row("  Honeypot stage",       stage,         DIM)
        row("  Targeted endpoints",   str(endpoints),DIM, C)
        row("  Avg replay interval",  avg_int,       DIM)
        print()


def render_honeypot_log(sessions: dict):
    print(f"{BOLD}  HONEYPOT DECEPTION LOG{RST}")
    line()

    if not sessions:
        print(f"  {DIM}No attacker sessions yet.{RST}\n")
        return

    for ip, s in sessions.items():
        count      = s.get("replay_count", 0)
        tokens     = s.get("tokens_issued", [])
        first_seen = s.get("first_seen", 0)
        age        = int(time.time() - first_seen) if first_seen else 0
        last_ep    = s.get("last_endpoint", "—")

        stage_num  = count
        if   stage_num <= 2: stage_label = f"{G}Stage 1: Perfect deception{RST}"
        elif stage_num <= 5: stage_label = f"{Y}Stage 2: Subtle degradation{RST}"
        elif stage_num <= 9: stage_label = f"{R}Stage 3: Soft errors injected{RST}"
        else:                stage_label = f"{R}{BOLD}Stage 4: Fake lockout active{RST}"

        print(f"  {DIM}IP {ip}  ·  active for {age}s  ·  last endpoint: /{last_ep}{RST}")
        row("  Replays served",    str(count),           DIM, Y)
        row("  Deception stage",   stage_label,          DIM)
        row("  Canary tokens",     str(len(tokens)),     DIM, M if tokens else DIM)
        if tokens:
            for t in tokens[-2:]:
                print(f"      {M}{DIM}{t}{RST}")
        print()


def render_footer():
    print(f"{DIM}{'─'*W}")
    print(f"  Press Ctrl+C to exit monitor   ·   attacker: python attacker/attacker.py{RST}")
    print(f"{DIM}{'─'*W}{RST}")


# ─────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────
def run():
    print(f"{B}[Monitor] Connecting to gateway at {GATEWAY}…{RST}")

    # Wait for gateway
    for _ in range(10):
        try:
            requests.get(f"{GATEWAY}/health", timeout=2)
            break
        except Exception:
            time.sleep(1)
    else:
        print(f"{R}[Monitor] Cannot reach gateway. Start run_all.py first.{RST}")
        sys.exit(1)

    print(f"{G}[Monitor] Connected. Starting live dashboard…{RST}")
    time.sleep(0.5)

    while True:
        try:
            stats    = fetch_stats()
            events   = fetch_events()
            profiles = fetch_profiles()
            sessions = fetch_attacker_sessions()

            clear()
            render_header(stats)
            render_stats(stats)
            render_events(events)
            render_attacker_profiles(profiles, sessions)
            render_honeypot_log(sessions)
            render_footer()

            time.sleep(REFRESH)

        except KeyboardInterrupt:
            print(f"\n{G}[Monitor] Exiting.{RST}\n")
            break
        except Exception as e:
            print(f"{R}[Monitor] Error: {e}{RST}")
            time.sleep(2)


if __name__ == "__main__":
    run()
