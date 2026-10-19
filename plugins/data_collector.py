"""Collect bounded, non-executable data from a local file or public URL."""

import shutil
import urllib.request
from pathlib import Path

PLUGIN = {
    "name": "data_collector",
    "description": "Collect JSON, CSV, or text data from a local file or explicitly supplied URL and save it. Never execute collected content.",
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "source": {"type": "STRING", "description": "Local path or http/https URL"},
            "output_path": {"type": "STRING", "description": "Destination file path"},
            "max_bytes": {"type": "INTEGER", "description": "Maximum bytes to collect, default 5 MB"},
        },
        "required": ["source", "output_path"],
    },
}

MAX_BYTES = 5 * 1024 * 1024


def run(parameters: dict, player=None, session_memory=None) -> str:
    try:
        source = str(parameters.get("source", "")).strip()
        destination = Path(str(parameters.get("output_path", ""))).expanduser()
        if not source or not str(parameters.get("output_path", "")).strip():
            return "Provide both a source and an output path."
        limit = min(max(int(parameters.get("max_bytes", MAX_BYTES)), 1), MAX_BYTES)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.lower().startswith(("http://", "https://")):
            request = urllib.request.Request(source, headers={"User-Agent": "JARVIS data collector"})
            with urllib.request.urlopen(request, timeout=15) as response, destination.open("wb") as output:
                total = 0
                while total < limit and (chunk := response.read(min(64 * 1024, limit - total))):
                    output.write(chunk)
                    total += len(chunk)
        else:
            source_path = Path(source).expanduser()
            if not source_path.is_file():
                return f"Source file not found: {source_path}"
            if source_path.stat().st_size > limit:
                return f"Source exceeds the {limit} byte collection limit."
            shutil.copyfile(source_path, destination)
        return f"Collected data to {destination}. It was saved as inert data and not executed."
    except Exception as exc:
        return f"Data collection failed: {exc}"