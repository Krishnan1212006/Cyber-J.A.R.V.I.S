"""
agents/tool_registry.py — Reusable, validated, timeout-bounded Tool Registry for JARVIS agents.
"""
from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .models import RiskLevel, ToolResult


@dataclass
class ToolDefinition:
    name: str
    description: str
    handler: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}, "required": []})
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    is_mutating: bool = False
    workspace_scoped: bool = False
    timeout_seconds: float = 30.0
    enabled: bool = True
    category: str = "general"

    def to_metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "risk_level": self.risk_level.value,
            "requires_approval": self.requires_approval,
            "is_mutating": self.is_mutating,
            "workspace_scoped": self.workspace_scoped,
            "timeout_seconds": self.timeout_seconds,
            "enabled": self.enabled,
            "category": self.category,
        }


def validate_workspace_path(target_path: str | Path, workspace_root: str | Path) -> Path:
    """
    Resolve target_path and guarantee it stays strictly inside workspace_root.
    Raises PermissionError on path traversal or outside-workspace access.
    """
    root = Path(workspace_root).resolve()
    raw = Path(target_path)
    resolved = (root / raw).resolve() if not raw.is_absolute() else raw.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise PermissionError(
            f"Access denied: '{resolved}' is outside authorized workspace '{root}'."
        )
    return resolved


class ToolRegistry:
    """Central registry of validated, permission-aware tools callable by agents."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        if not tool.name or not tool.name.replace("_", "").isalnum():
            raise ValueError(f"Invalid tool name: '{tool.name}'")
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> bool:
        return self._tools.pop(name, None) is not None

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        return name in self._tools

    def set_enabled(self, name: str, enabled: bool) -> bool:
        t = self._tools.get(name)
        if not t:
            return False
        t.enabled = enabled
        return True

    def list_tools(self, only_enabled: bool = False, category: Optional[str] = None) -> list[dict[str, Any]]:
        out = []
        for t in self._tools.values():
            if only_enabled and not t.enabled:
                continue
            if category and t.category != category:
                continue
            out.append(t.to_metadata())
        return sorted(out, key=lambda item: item["name"])

    def validate_params(self, tool: ToolDefinition, params: dict[str, Any]) -> Optional[str]:
        if not isinstance(params, dict):
            return "Tool parameters must be a dictionary."
        schema = tool.parameters or {}
        required = schema.get("required", [])
        for req_key in required:
            if req_key not in params or params[req_key] is None:
                return f"Missing required parameter '{req_key}' for tool '{tool.name}'."
        return None

    async def execute(
        self,
        name: str,
        params: Optional[dict[str, Any]] = None,
        workspace: Optional[str] = None,
    ) -> ToolResult:
        """Execute a registered tool with validation, workspace confinement, and timeout."""
        params = dict(params or {})
        t0 = time.perf_counter()

        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(ok=False, tool_name=name, error=f"Tool '{name}' does not exist.")
        if not tool.enabled:
            return ToolResult(ok=False, tool_name=name, error=f"Tool '{name}' is currently disabled.")

        val_err = self.validate_params(tool, params)
        if val_err:
            return ToolResult(ok=False, tool_name=name, error=val_err)

        # Enforce workspace scoping if required
        if tool.workspace_scoped:
            if not workspace:
                return ToolResult(
                    ok=False,
                    tool_name=name,
                    error=f"Tool '{name}' requires an authorized workspace path.",
                )
            for path_key in ("path", "file_path", "target_path", "directory"):
                if path_key in params and params[path_key]:
                    try:
                        safe_p = validate_workspace_path(params[path_key], workspace)
                        params[path_key] = str(safe_p)
                    except PermissionError as pe:
                        return ToolResult(ok=False, tool_name=name, error=str(pe))
            # Pass workspace if handler accepts it
            sig = inspect.signature(tool.handler)
            if "workspace" in sig.parameters and "workspace" not in params:
                params["workspace"] = workspace

        try:
            if inspect.iscoroutinefunction(tool.handler):
                coro = tool.handler(**params)
            else:
                coro = asyncio.to_thread(tool.handler, **params)
            output = await asyncio.wait_for(coro, timeout=tool.timeout_seconds)
            elapsed = (time.perf_counter() - t0) * 1000.0
            return ToolResult(ok=True, tool_name=name, output=output, duration_ms=elapsed)
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - t0) * 1000.0
            return ToolResult(
                ok=False,
                tool_name=name,
                error=f"Tool '{name}' timed out after {tool.timeout_seconds}s.",
                duration_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000.0
            return ToolResult(
                ok=False,
                tool_name=name,
                error=f"Tool '{name}' failed: {type(exc).__name__}: {exc}",
                duration_ms=elapsed,
            )
