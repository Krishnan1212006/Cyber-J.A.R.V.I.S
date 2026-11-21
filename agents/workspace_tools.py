"""
agents/workspace_tools.py — Workspace-confined coding, inspection, diff, checkpoint,
rollback, terminal, test runner, and static review tools for JARVIS CodingAgent.
"""
from __future__ import annotations

import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

from .models import RiskLevel, utc_now_iso
from .tool_registry import ToolDefinition, ToolRegistry, validate_workspace_path

IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", "node_modules",
    ".venv", "venv", "env", "dist", "build", ".jarvis_checkpoints", ".mypy_cache",
})

SENSITIVE_FILENAMES = frozenset({
    ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519",
    "credentials.json", "secrets.json", "api_keys.json", ".npmrc", ".pypirc",
})

SECRET_PATTERNS = (
    (r"AIza[0-9A-Za-z\-_]{35}", "Possible Google/Gemini API key"),
    (r"sk-[A-Za-z0-9]{20,}", "Possible OpenAI/Secret API key"),
    (r"gsk_[A-Za-z0-9]{20,}", "Possible Groq API key"),
    (r"AKIA[0-9A-Z]{16}", "Possible AWS Access Key ID"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key material"),
)


def _check_not_sensitive(path: Path) -> None:
    if path.name.lower() in SENSITIVE_FILENAMES:
        raise PermissionError(
            f"Access denied: '{path.name}' is a protected credential/secret file."
        )


def workspace_inspect(workspace: str, max_files: int = 200) -> dict[str, Any]:
    """Inspect a project workspace: structure, languages, frameworks, tests, and Git status."""
    root = Path(workspace).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Workspace does not exist: '{root}'")

    files: list[str] = []
    ext_counts: dict[str, int] = {}
    test_files: list[str] = []
    entry_points: list[str] = []
    config_files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            if len(files) < max_files:
                files.append(rel)
            ext = fpath.suffix.lower()
            if ext:
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
            low = fname.lower()
            if low.startswith("test_") or low.endswith("_test.py") or ".test." in low or ".spec." in low:
                test_files.append(rel)
            if low in ("main.py", "app.py", "server.py", "index.js", "index.ts", "manage.py"):
                entry_points.append(rel)
            if low in (
                "requirements.txt", "pyproject.toml", "setup.py", "package.json",
                "cargo.toml", "go.mod", "dockerfile", "docker-compose.yml",
            ):
                config_files.append(rel)

    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".html": "HTML", ".css": "CSS", ".json": "JSON",
        ".sql": "SQL", ".go": "Go", ".rs": "Rust", ".java": "Java",
    }
    languages = sorted({lang_map[e] for e in ext_counts if e in lang_map})

    frameworks: list[str] = []
    req_file = root / "requirements.txt"
    if req_file.exists():
        req_text = req_file.read_text(encoding="utf-8", errors="ignore").lower()
        for fw in ("fastapi", "flask", "django", "pyqt6", "pytest", "uvicorn", "sqlalchemy"):
            if fw in req_text:
                frameworks.append(fw)
    pkg_file = root / "package.json"
    if pkg_file.exists():
        pkg_text = pkg_file.read_text(encoding="utf-8", errors="ignore").lower()
        for fw in ("react", "next", "vue", "express", "vite", "jest", "vitest"):
            if fw in pkg_text:
                frameworks.append(fw)

    git_status = {"is_git_repo": (root / ".git").exists(), "branch": None, "dirty": False}
    if git_status["is_git_repo"]:
        try:
            br = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(root), capture_output=True, text=True, timeout=5,
            )
            if br.returncode == 0:
                git_status["branch"] = br.stdout.strip()
            st = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(root), capture_output=True, text=True, timeout=5,
            )
            if st.returncode == 0:
                git_status["dirty"] = bool(st.stdout.strip())
        except Exception:
            pass

    return {
        "workspace": str(root),
        "total_files_scanned": len(files),
        "file_tree": files,
        "languages": languages,
        "frameworks": sorted(set(frameworks)),
        "entry_points": entry_points,
        "config_files": config_files,
        "test_files": test_files,
        "git": git_status,
    }


def workspace_read_file(
    path: str,
    workspace: str,
    start_line: int = 1,
    end_line: int = 400,
) -> dict[str, Any]:
    """Read a text file strictly inside the workspace."""
    safe = validate_workspace_path(path, workspace)
    _check_not_sensitive(safe)
    if not safe.exists() or not safe.is_file():
        raise FileNotFoundError(f"File not found: '{safe}'")

    lines = safe.read_text(encoding="utf-8", errors="replace").splitlines()
    s = max(1, int(start_line))
    e = min(len(lines), max(s, int(end_line)))
    excerpt = "\n".join(f"{i}: {lines[i - 1]}" for i in range(s, e + 1))
    return {
        "path": str(safe.relative_to(Path(workspace).resolve())).replace("\\", "/"),
        "total_lines": len(lines),
        "start_line": s,
        "end_line": e,
        "content": excerpt,
    }


def workspace_search(
    query: str,
    workspace: str,
    max_matches: int = 50,
) -> dict[str, Any]:
    """Search text or regex pattern across files inside the workspace."""
    root = Path(workspace).resolve()
    pattern = re.compile(query, re.IGNORECASE)
    matches: list[dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if fname.lower() in SENSITIVE_FILENAMES:
                continue
            if fpath.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".db", ".pyc", ".zip", ".exe"):
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            for idx, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    matches.append({"file": rel, "line": idx, "text": line.strip()[:200]})
                    if len(matches) >= max_matches:
                        return {"query": query, "count": len(matches), "matches": matches, "truncated": True}
    return {"query": query, "count": len(matches), "matches": matches, "truncated": False}


def compute_unified_diff(old_text: str, new_text: str, rel_path: str) -> str:
    diff_lines = difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
    )
    return "".join(diff_lines)


def workspace_checkpoint(
    workspace: str,
    label: str = "pre-edit",
    files: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Create a rollback snapshot of specified files (or all non-ignored source files)
    inside `<workspace>/.jarvis_checkpoints/<checkpoint_id>/`.
    """
    root = Path(workspace).resolve()
    cp_id = f"cp_{uuid.uuid4().hex[:8]}"
    cp_dir = root / ".jarvis_checkpoints" / cp_id
    cp_dir.mkdir(parents=True, exist_ok=True)

    saved: list[str] = []
    non_existent: list[str] = []

    target_list = files or []
    if not target_list:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                if fname.lower() in SENSITIVE_FILENAMES:
                    continue
                if fpath.stat().st_size <= 512 * 1024:
                    target_list.append(str(fpath.relative_to(root)).replace("\\", "/"))

    for rel in target_list:
        safe = validate_workspace_path(rel, root)
        rel_norm = str(safe.relative_to(root)).replace("\\", "/")
        if safe.exists() and safe.is_file():
            dest = cp_dir / "files" / rel_norm
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(safe, dest)
            saved.append(rel_norm)
        else:
            non_existent.append(rel_norm)

    meta = {
        "checkpoint_id": cp_id,
        "label": label,
        "created_at": utc_now_iso(),
        "saved_files": saved,
        "created_later_files": non_existent,
    }
    (cp_dir / "manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def list_checkpoints(workspace: str) -> list[dict[str, Any]]:
    root = Path(workspace).resolve()
    base = root / ".jarvis_checkpoints"
    if not base.exists():
        return []
    out = []
    for child in sorted(base.iterdir(), reverse=True):
        mf = child / "manifest.json"
        if mf.exists():
            try:
                out.append(json.loads(mf.read_text(encoding="utf-8")))
            except Exception:
                pass
    return out


def workspace_rollback(workspace: str, checkpoint_id: str) -> dict[str, Any]:
    """Restore workspace files from a previously created checkpoint."""
    root = Path(workspace).resolve()
    cp_dir = validate_workspace_path(f".jarvis_checkpoints/{checkpoint_id}", root)
    mf = cp_dir / "manifest.json"
    if not mf.exists():
        raise FileNotFoundError(f"Checkpoint '{checkpoint_id}' not found.")

    meta = json.loads(mf.read_text(encoding="utf-8"))
    restored: list[str] = []
    removed: list[str] = []

    for rel in meta.get("saved_files", []):
        src = cp_dir / "files" / rel
        dst = validate_workspace_path(rel, root)
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            restored.append(rel)

    for rel in meta.get("created_later_files", []):
        dst = validate_workspace_path(rel, root)
        if dst.exists() and dst.is_file():
            dst.unlink()
            removed.append(rel)

    return {
        "checkpoint_id": checkpoint_id,
        "restored_files": restored,
        "removed_files": removed,
    }


def workspace_write_file(
    path: str,
    content: str,
    workspace: str,
) -> dict[str, Any]:
    """Create or overwrite a file strictly inside the workspace and return its unified diff."""
    root = Path(workspace).resolve()
    safe = validate_workspace_path(path, root)
    _check_not_sensitive(safe)
    rel = str(safe.relative_to(root)).replace("\\", "/")

    existed = safe.exists()
    old_text = safe.read_text(encoding="utf-8", errors="replace") if existed else ""
    safe.parent.mkdir(parents=True, exist_ok=True)
    safe.write_text(content, encoding="utf-8")
    diff = compute_unified_diff(old_text, content, rel)
    return {
        "path": rel,
        "action": "modified" if existed else "created",
        "bytes_written": len(content.encode("utf-8")),
        "diff": diff,
    }


def workspace_edit_file(
    path: str,
    target: str,
    replacement: str,
    workspace: str,
) -> dict[str, Any]:
    """Surgically replace exact target text in a workspace file and return unified diff."""
    root = Path(workspace).resolve()
    safe = validate_workspace_path(path, root)
    _check_not_sensitive(safe)
    if not safe.exists() or not safe.is_file():
        raise FileNotFoundError(f"File not found: '{safe}'")

    old_text = safe.read_text(encoding="utf-8", errors="replace")
    if target not in old_text:
        raise ValueError(f"Target snippet not found in '{safe.name}'. Read the file first.")

    new_text = old_text.replace(target, replacement, 1)
    safe.write_text(new_text, encoding="utf-8")
    rel = str(safe.relative_to(root)).replace("\\", "/")
    diff = compute_unified_diff(old_text, new_text, rel)
    return {
        "path": rel,
        "action": "modified",
        "diff": diff,
    }


def workspace_run_terminal(
    command: str,
    workspace: str,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Run a shell command strictly confined to cwd=workspace with bounded timeout."""
    root = Path(workspace).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Invalid workspace: '{root}'")

    proc = subprocess.run(
        command,
        cwd=str(root),
        shell=True,
        capture_output=True,
        text=True,
        timeout=min(int(timeout_seconds), 120),
    )
    return {
        "command": command,
        "cwd": str(root),
        "returncode": proc.returncode,
        "stdout": proc.stdout[-6000:],
        "stderr": proc.stderr[-4000:],
        "ok": proc.returncode == 0,
    }


def workspace_run_tests(
    workspace: str,
    test_command: Optional[str] = None,
) -> dict[str, Any]:
    """Auto-detect and execute project test suite inside workspace."""
    root = Path(workspace).resolve()
    if test_command:
        cmd = test_command
    elif (root / "package.json").exists() and not list(root.glob("**/test_*.py")):
        cmd = "npm test"
    else:
        cmd = f'"{sys.executable}" -m pytest -v'

    res = workspace_run_terminal(cmd, str(root), timeout_seconds=60)
    combined = (res["stdout"] or "") + "\n" + (res["stderr"] or "")
    passed = 0
    failed = 0
    m_pass = re.search(r"(\d+)\s+passed", combined)
    m_fail = re.search(r"(\d+)\s+failed", combined)
    if m_pass:
        passed = int(m_pass.group(1))
    if m_fail:
        failed = int(m_fail.group(1))

    return {
        **res,
        "tests_passed": passed,
        "tests_failed": failed,
    }


def workspace_code_review(
    workspace: str,
    files: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Static review of modified/workspace files: syntax, accidental secrets, basic quality."""
    root = Path(workspace).resolve()
    findings: list[dict[str, Any]] = []
    targets = files or []
    if not targets:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
            for fname in sorted(filenames):
                if fname.endswith(".py"):
                    targets.append(str((Path(dirpath) / fname).relative_to(root)).replace("\\", "/"))

    for rel in targets:
        safe = validate_workspace_path(rel, root)
        if not safe.exists() or not safe.is_file():
            continue
        text = safe.read_text(encoding="utf-8", errors="replace")

        # 1. Secret scan
        for pat, desc in SECRET_PATTERNS:
            if re.search(pat, text):
                findings.append({"file": rel, "severity": "CRITICAL", "issue": desc})

        # 2. Python AST syntax check
        if safe.suffix.lower() == ".py":
            try:
                ast.parse(text, filename=rel)
            except SyntaxError as se:
                findings.append({
                    "file": rel,
                    "severity": "HIGH",
                    "issue": f"SyntaxError at line {se.lineno}: {se.msg}",
                })

    has_blocking = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "files_reviewed": targets,
        "findings": findings,
        "passed": not has_blocking,
    }


def register_workspace_tools(registry: ToolRegistry) -> None:
    """Register all Phase 2 workspace tools into the central ToolRegistry."""
    tools = [
        ToolDefinition(
            name="workspace_inspect",
            description="Inspect project structure, languages, frameworks, tests, and Git status.",
            handler=workspace_inspect,
            risk_level=RiskLevel.LOW,
            is_mutating=False,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_read_file",
            description="Read a file strictly inside the authorized workspace.",
            handler=workspace_read_file,
            parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            risk_level=RiskLevel.LOW,
            is_mutating=False,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_search",
            description="Search text or regex across files inside the authorized workspace.",
            handler=workspace_search,
            parameters={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
            risk_level=RiskLevel.LOW,
            is_mutating=False,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_checkpoint",
            description="Create a rollback backup checkpoint before editing workspace files.",
            handler=workspace_checkpoint,
            risk_level=RiskLevel.LOW,
            is_mutating=False,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_rollback",
            description="Rollback workspace files to a saved checkpoint.",
            handler=workspace_rollback,
            parameters={"type": "object", "properties": {"checkpoint_id": {"type": "string"}}, "required": ["checkpoint_id"]},
            risk_level=RiskLevel.MEDIUM,
            is_mutating=True,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_write_file",
            description="Create or overwrite a file strictly inside the authorized workspace.",
            handler=workspace_write_file,
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
            },
            risk_level=RiskLevel.MEDIUM,
            is_mutating=True,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_edit_file",
            description="Surgically edit an existing file inside the authorized workspace.",
            handler=workspace_edit_file,
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "target": {"type": "string"},
                    "replacement": {"type": "string"},
                },
                "required": ["path", "target", "replacement"],
            },
            risk_level=RiskLevel.MEDIUM,
            is_mutating=True,
            workspace_scoped=True,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_run_terminal",
            description="Execute a command inside the authorized workspace directory.",
            handler=workspace_run_terminal,
            parameters={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            is_mutating=True,
            workspace_scoped=True,
            timeout_seconds=60.0,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_run_tests",
            description="Run the workspace test suite (pytest / npm test) and parse results.",
            handler=workspace_run_tests,
            risk_level=RiskLevel.LOW,
            is_mutating=False,
            workspace_scoped=True,
            timeout_seconds=60.0,
            category="coding",
        ),
        ToolDefinition(
            name="workspace_code_review",
            description="Run static syntax and secret-leak code review on workspace files.",
            handler=workspace_code_review,
            risk_level=RiskLevel.LOW,
            is_mutating=False,
            workspace_scoped=True,
            category="coding",
        ),
    ]
    for tool in tools:
        registry.register(tool)
