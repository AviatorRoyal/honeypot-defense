"""
run_all.py — Master Launcher for VaultNet Honeypot Defense
Starts all services in order and keeps them running.

Usage:
  python run_all.py          → start all services
  python run_all.py attack   → start all + run attacker
  python run_all.py monitor  → start all + open live dashboard

Part of: Honeypot-Based Replay Defense
"""

import subprocess
import time
import sys
import os
import requests
import threading
import signal

# ─────────────────────────────────────────
# COLORS
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

BASE = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────
# SERVICE DEFINITIONS
# ─────────────────────────────────────────
SERVICES = [
    {
        "name":    "Real Backend",
        "color":   G,
        "icon":    "🏦",
        "script":  os.path.join(BASE, "backend", "real_backend.py"),
        "port":    8001,
        "health":  "http://127.0.0.1:8001/health",
    },
    {
        "name":    "Honeypot",
        "color":   Y,
        "icon":    "🍯",
        "script":  os.path.join(BASE, "honeypot", "honeypot.py"),
        "port":    8002,
        "health":  "http://127.0.0.1:8002/health",
    },
    {
        "name":    "Gateway",
        "color":   C,
        "icon":    "🔐",
        "script":  os.path.join(BASE, "gateway", "gateway.py"),
        "port":    8000,
        "health":  "http://127.0.0.1:8000/health",
    },
]

processes = []

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────
def wait_for_service(url: str, name: str, timeout: int = 15) -> bool:
    for i in range(timeout):
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False

def stream_logs(proc, name: str, color: str):
    """Stream service stdout to terminal with prefix"""
    for line in iter(proc.stdout.readline, b""):
        text = line.decode("utf-8", errors="replace").rstrip()
        if text:
            print(f"  {color}{DIM}[{name}]{RST} {DIM}{text}{RST}")

def kill_all():
    print(f"\n{Y}[Launcher] Shutting down all services…{RST}")
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(0.5)
    for p in processes:
        try:
            p.kill()
        except Exception:
            pass
    print(f"{G}[Launcher] All services stopped.{RST}\n")

# ─────────────────────────────────────────
# STARTUP BANNER
# ─────────────────────────────────────────
def print_banner():
    print(f"\n{BOLD}{'━'*62}{RST}")
    print(f"{BOLD}  🛡  VAULTNET — HONEYPOT-BASED REPLAY DEFENSE{RST}")
    print(f"{DIM}  Launching all services…{RST}")
    print(f"{BOLD}{'━'*62}{RST}\n")

# ─────────────────────────────────────────
# INSTRUCTIONS AFTER BOOT
# ─────────────────────────────────────────
def print_instructions():
    print(f"\n{BOLD}{'━'*62}{RST}")
    print(f"{G}{BOLD}  ✅ ALL SERVICES RUNNING{RST}")
    print(f"{BOLD}{'━'*62}{RST}\n")

    print(f"{BOLD}  SERVICE PORTS{RST}")
    print(f"  {DIM}{'─'*58}{RST}")
    print(f"  {C}🔐 Gateway       {RST}→  http://127.0.0.1:{C}8000{RST}")
    print(f"  {G}🏦 Real Backend  {RST}→  http://127.0.0.1:{G}8001{RST}")
    print(f"  {Y}🍯 Honeypot      {RST}→  http://127.0.0.1:{Y}8002{RST}")
    print(f"  {M}🌐 Website       {RST}→  open  {M}website/index.html{RST}  in your browser\n")

    print(f"{BOLD}  DEMO CREDENTIALS{RST}")
    print(f"  {DIM}{'─'*58}{RST}")
    print(f"  {G}alice{RST} / alice123     {G}bob{RST} / bob456\n")

    print(f"{BOLD}  WHAT TO DO NEXT{RST}")
    print(f"  {DIM}{'─'*58}{RST}")
    print(f"  1. Open {M}website/index.html{RST} in your browser")
    print(f"     Log in as alice — this hits the {G}real backend{RST}\n")
    print(f"  2. Open a {B}new terminal{RST} and run the attacker:")
    print(f"     {Y}python attacker/attacker.py{RST}\n")
    print(f"  3. Open {B}another terminal{RST} for the live dashboard:")
    print(f"     {C}python dashboard/monitor.py{RST}\n")
    print(f"  4. Watch replays get silently routed to the honeypot 🍯\n")

    print(f"{BOLD}{'━'*62}{RST}")
    print(f"{DIM}  Press Ctrl+C to stop all services{RST}")
    print(f"{BOLD}{'━'*62}{RST}\n")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "serve"
    print_banner()

    # Register shutdown handler
    signal.signal(signal.SIGINT,  lambda s, f: (kill_all(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (kill_all(), sys.exit(0)))

    # ── Launch each service ───────────────────────────────────
    for svc in SERVICES:
        color  = svc["color"]
        name   = svc["name"]
        icon   = svc["icon"]
        script = svc["script"]
        port   = svc["port"]

        print(f"  {icon}  Starting {color}{BOLD}{name}{RST} on port {color}{port}{RST}…", end=" ", flush=True)

        proc = subprocess.Popen(
            [sys.executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=BASE
        )
        processes.append(proc)

        # Stream logs in background thread
        t = threading.Thread(target=stream_logs, args=(proc, name, color), daemon=True)
        t.start()

        # Wait for health check
        ok = wait_for_service(svc["health"], name)
        if ok:
            print(f"{G}ready ✓{RST}")
        else:
            print(f"{R}TIMEOUT ✗{RST}")
            print(f"\n{R}[ERROR] {name} failed to start. Check the script.{RST}\n")
            kill_all()
            sys.exit(1)

        time.sleep(0.2)

    # ── All services up ───────────────────────────────────────
    print_instructions()

    # ── Optional modes ────────────────────────────────────────
    if mode == "attack":
        print(f"\n{Y}[Launcher] Running attacker in 2 seconds…{RST}\n")
        time.sleep(2)
        attacker = subprocess.run(
            [sys.executable, os.path.join(BASE, "attacker", "attacker.py")],
            cwd=BASE
        )

    elif mode == "monitor":
        print(f"\n{C}[Launcher] Opening live monitor…{RST}\n")
        time.sleep(1)
        subprocess.run(
            [sys.executable, os.path.join(BASE, "dashboard", "monitor.py")],
            cwd=BASE
        )

    else:
        # Just keep running until Ctrl+C
        try:
            while True:
                # Check all services are still alive
                for i, (svc, proc) in enumerate(zip(SERVICES, processes)):
                    if proc.poll() is not None:
                        print(f"\n{R}[Launcher] {svc['name']} crashed! Restarting…{RST}")
                        new_proc = subprocess.Popen(
                            [sys.executable, svc["script"]],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            cwd=BASE
                        )
                        processes[i] = new_proc
                        t = threading.Thread(
                            target=stream_logs,
                            args=(new_proc, svc["name"], svc["color"]),
                            daemon=True
                        )
                        t.start()
                time.sleep(3)
        except KeyboardInterrupt:
            kill_all()


if __name__ == "__main__":
    main()
