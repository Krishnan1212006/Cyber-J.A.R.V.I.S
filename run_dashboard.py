"""
run_dashboard.py — Standalone JARVIS Dashboard Launcher
Run this directly to start the web dashboard without needing the voice/AI session:

    python run_dashboard.py

The dashboard will be available at:
    https://127.0.0.1:8000  (local access)
    https://<your-LAN-IP>:8000  (phone access via same Wi-Fi)

Chrome will show a certificate warning on first visit — click Advanced → Proceed.
This is because a self-signed TLS certificate is used (required for microphone access).
"""

import sys
import asyncio
import platform
from pathlib import Path

# ── Suppress Windows asyncio ProactorEventLoop socket-cleanup noise ───────────
# WinError 10054 "An existing connection was forcibly closed" is emitted by the
# ProactorEventLoop when Chrome closes a TLS connection. It is harmless.
# Using the SelectorEventLoop avoids it entirely.
if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Make sure project root is on the path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main():
    from dashboard.server import DashboardServer, _DEPS_OK

    if not _DEPS_OK:
        print("ERROR: Required packages not installed.")
        print("Run:  pip install fastapi \"uvicorn[standard]\" cryptography")
        sys.exit(1)

    print("=" * 60)
    print("  JARVIS Web Dashboard")
    print("=" * 60)

    srv = DashboardServer()
    # Generate a convenience key so you can log in without the desktop app
    key = srv.new_key(expiry_secs=3600)
    local_url = srv.get_local_url()

    print()
    print(f"  Local URL   : {local_url}")
    print(f"  LAN URL     : {srv.get_url()}")
    print()
    print(f"  Quick login (click this link):")
    print(f"  {local_url}/auto-login?key={key}")
    print()
    print("  IMPORTANT: Chrome will show a certificate warning.")
    print("  Click:  Advanced  →  Proceed to 127.0.0.1 (unsafe)")
    print("  This is a one-time step for the self-signed cert.")
    print()
    print("  Press Ctrl+C to stop the dashboard.")
    print("=" * 60)

    try:
        asyncio.run(srv.serve())
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Stopped.")


if __name__ == "__main__":
    main()
