"""
Local defensive checks: file hashing, system posture, secret exposure auditing, and HTTP defense headers.
"""

from __future__ import annotations

import hashlib
import json
import platform
import socket
import sys
from pathlib import Path

from plugins._sec_engine import SECRET_PATTERNS, audit_http_headers

PLUGIN = {
    "name": "defensive_audit",
    "description": (
        "Perform defensive security checks: calculate file SHA-256 hashes, report system posture, "
        "scan files/directories for exposed secrets and API tokens, or audit HTTP defensive headers."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {
                "type": "STRING",
                "description": "Defense action: 'file_hash', 'system_posture', 'secret_audit', or 'http_headers'.",
            },
            "file_path": {"type": "STRING", "description": "Target file or directory path for file_hash or secret_audit."},
            "target_url": {"type": "STRING", "description": "Target URL for http_headers check."},
            "expected_sha256": {"type": "STRING", "description": "Optional expected hash for file_hash verification."},
            "output_path": {"type": "STRING", "description": "Optional JSON report output file path."},
        },
        "required": ["action"],
    },
}


def _write_report(report: dict, output_path: str) -> None:
    if output_path:
        path = Path(output_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def run(parameters: dict, player=None, session_memory=None) -> str:
    try:
        action = str(parameters.get("action", "")).lower().strip()
        output_path = str(parameters.get("output_path", "")).strip()

        # 1. SHA-256 File Hashing
        if action == "file_hash":
            path = Path(str(parameters.get("file_path", ""))).expanduser()
            if not path.is_file():
                return f"File not found: {path}"
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual = digest.hexdigest()
            expected = str(parameters.get("expected_sha256", "")).strip().lower()
            report = {"file": str(path), "sha256": actual, "matches_expected": bool(expected) and actual == expected}
            _write_report(report, output_path)
            match = " and it matches the expected hash" if expected and actual == expected else ""
            return f"SHA-256 for {path.name}: {actual}{match}."

        # 2. Local System Posture
        if action == "system_posture":
            report = {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "home": str(Path.home()),
            }
            _write_report(report, output_path)
            return f"Local posture: {report['platform']}, Python {report['python']}, host {report['hostname']}."

        # 3. Secret & Credential Leak Audit
        if action in ("secret_audit", "secrets"):
            target_path = Path(str(parameters.get("file_path", "."))).expanduser()
            if not target_path.exists():
                return f"Path not found: {target_path}"

            leaks = []
            files_to_check = [target_path] if target_path.is_file() else list(target_path.rglob("*.py")) + list(target_path.rglob("*.env*")) + list(target_path.rglob("*.json"))

            # Filter out hidden or cache directories
            filtered_files = [f for f in files_to_check if not any(part.startswith(".") or part in ("__pycache__", "venv", "node_modules") for part in f.parts)]

            for f in filtered_files[:100]:
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    for pattern, _ in SECRET_PATTERNS:
                        matches = pattern.findall(content)
                        if matches:
                            leaks.append({"file": str(f.name), "path": str(f), "matches_count": len(matches)})
                            break
                except Exception:
                    continue

            report = {"target": str(target_path), "files_audited": len(filtered_files), "leaks": leaks}
            _write_report(report, output_path)

            if leaks:
                leak_names = ", ".join(l["file"] for l in leaks[:4])
                return f"Warning Sir: Potential secret / credential exposures detected in {len(leaks)} files ({leak_names})."
            return f"Sir, secret audit completed across {len(filtered_files)} files. Zero exposed credentials found."

        # 4. HTTP Defense Headers
        if action in ("http_headers", "headers"):
            target_url = str(parameters.get("target_url", "")).strip()
            if not target_url:
                return "Sir, please specify target_url for the defensive HTTP header check."
            res = audit_http_headers(target_url)
            findings = res.get("findings", [])
            _write_report(res, output_path)
            if findings:
                missing = ", ".join(f["title"] for f in findings[:3])
                return f"Sir, header audit for {target_url} flagged {len(findings)} defensive gaps: {missing}."
            return f"Sir, all recommended defense headers are actively enforced on {target_url}."

        return "Choose action: 'file_hash', 'system_posture', 'secret_audit', or 'http_headers'."
    except Exception as exc:
        return f"Defensive audit failed: {exc}"