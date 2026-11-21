"""
api/index.py — Vercel Serverless ASGI Entrypoint for JARVIS 24 Web Dashboard.

Exposes a top-level FastAPI `app` instance without importing PyQt6 or desktop audio
libraries from `main.py`.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Ensure writable temp paths when running inside Vercel's read-only /var/task filesystem
if os.environ.get("VERCEL"):
    os.environ.setdefault("JARVIS_DATA_DIR", "/tmp/jarvis_data")
    Path("/tmp/jarvis_data").mkdir(parents=True, exist_ok=True)
    Path("/tmp/jarvis_uploads").mkdir(parents=True, exist_ok=True)

from dashboard.server import DashboardServer

_server = DashboardServer()
app = _server.app
