"""
interview/config.py — Configuration for AI Question Generation & Vapi Voice Interviewer.
"""

import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
API_KEYS_FILE = CONFIG_DIR / "api_keys.json"

def _load_keys() -> dict:
    if API_KEYS_FILE.exists():
        try:
            return json.loads(API_KEYS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

_keys = _load_keys()

# Groq API Configuration
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or _keys.get("groq_api_key", "")
GROQ_MODEL = "gpt-oss-120b"
GROQ_FALLBACK_MODEL = "llama-3.3-70b-versatile"
GROQ_TEMPERATURE = 1.0

# Vapi API Configuration
VAPI_API_KEY = os.environ.get("VAPI_API_KEY") or _keys.get("vapi_api_key", "")
VAPI_PUBLIC_KEY = os.environ.get("VAPI_PUBLIC_KEY") or _keys.get("vapi_public_key", "")

# Deepgram Nova-3 Configuration
DEEPGRAM_MODEL = "nova-3"
DEEPGRAM_LANGUAGE = "en-IN"
DEEPGRAM_ENDPOINTING_MS = 400

# ElevenLabs Configuration
ELEVENLABS_VOICE_ID = os.environ.get("ELEVENLABS_VOICE_ID") or _keys.get("elevenlabs_voice_id", "21m00Tcm4TlvDq8ikWAM")  # Rachel / Warm Professional
ELEVENLABS_MODEL = "eleven_turbo_v2_5"

# Turn-Taking & Endpointing
BASE_WAIT_SECONDS = 0.7
SMART_ENDPOINTING_TYPE = "sigmoid"

# Barge-In / Interruption
BARGE_IN_WORDS = 1
BARGE_IN_VOICE_DURATION = 0.4
BARGE_IN_BACKOFF_SECONDS = 1.0
