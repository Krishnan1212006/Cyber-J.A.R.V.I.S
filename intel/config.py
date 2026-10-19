"""
Configuration loader for JARVIS Cybersecurity Intelligence Subsystem.
Reads settings from config/api_keys.json or environment variables without hardcoding.
"""

from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from typing import Any


def get_base_dir() -> Path:
    """Return project root directory."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


BASE_DIR = get_base_dir()
CONFIG_FILE = BASE_DIR / "config" / "api_keys.json"
DEFAULT_DATA_DIR = BASE_DIR / "data"


def load_cyber_config() -> dict[str, Any]:
    """
    Load cyber intelligence configuration.
    Falls back to safe defaults if not specified in api_keys.json.
    """
    cfg: dict[str, Any] = {}
    raw_config: dict[str, Any] = {}
    if CONFIG_FILE.is_file():
        try:
            raw_config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            cfg = raw_config.get("cyber_intel", {})
        except Exception:
            cfg = {}

    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)

    db_path_str = cfg.get("db_path") or os.environ.get("JARVIS_CYBER_DB")
    if db_path_str:
        db_path = Path(db_path_str).expanduser()
    else:
        db_path = DEFAULT_DATA_DIR / "cyber_intel.db"

    # Determine default LLM provider & credentials
    # Priority: 1. cyber_intel.llm_provider, 2. gemini if gemini_api_key present, 3. global llm_provider, 4. ollama
    default_provider = "ollama"
    if raw_config.get("gemini_api_key"):
        default_provider = "gemini"
    elif raw_config.get("llm_provider"):
        default_provider = raw_config.get("llm_provider", "ollama")

    llm_provider = cfg.get("llm_provider") or os.environ.get("JARVIS_CYBER_LLM_PROVIDER") or default_provider
    llm_provider = llm_provider.strip().lower()

    # Determine default model
    default_model = "gemini-3.8-flash" if llm_provider == "gemini" else "llama3.2"
    llm_model = cfg.get("llm_model") or raw_config.get("llm_model") or default_model

    # Determine API key if applicable
    llm_api_key = cfg.get("api_key") or os.environ.get("JARVIS_CYBER_API_KEY")
    if not llm_api_key and llm_provider == "gemini":
        llm_api_key = raw_config.get("gemini_api_key", "")

    return {
        "db_path": str(db_path),
        "sync_interval_minutes": int(cfg.get("sync_interval_minutes", 30)),
        "rate_limit_delay_seconds": float(cfg.get("rate_limit_delay_seconds", 1.0)),
        "request_timeout_seconds": int(cfg.get("request_timeout_seconds", 15)),
        "max_retries": int(cfg.get("max_retries", 3)),
        "user_agent": cfg.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (JARVIS Cyber-Intel/1.0)",
        ),
        # Phase 2 LLM & Analysis settings
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "llm_url": cfg.get("llm_url") or raw_config.get("llm_url", "http://localhost:11434"),
        "llm_api_key": llm_api_key,
        "analysis_version": str(cfg.get("analysis_version", "v1")),
        "analysis_batch_size": int(cfg.get("analysis_batch_size", 10)),
        "max_content_chars": int(cfg.get("max_content_chars", 12000)),
        "temperature": float(cfg.get("temperature", 0.1)),
        "retry_delay_seconds": float(cfg.get("retry_delay_seconds", 2.0)),
    }

