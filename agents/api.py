"""
agents/api.py — FastAPI router for JARVIS 24 Agent Core (/api/agents/*).
"""
from __future__ import annotations

from typing import Any, Optional

try:
    from fastapi import APIRouter, HTTPException, Query, Request
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False

from .orchestrator import get_orchestrator
from .workspace_tools import (
    list_checkpoints,
    workspace_inspect,
    workspace_read_file,
    workspace_rollback,
)


if _FASTAPI_OK:
    router = APIRouter(prefix="/api/agents", tags=["JARVIS Agent Core"])

    @router.get("/status")
    async def agent_status_ep() -> dict[str, Any]:
        orch = get_orchestrator()
        return {"ok": True, **orch.status_summary()}

    @router.get("/autonomy")
    async def get_autonomy_ep() -> dict[str, Any]:
        orch = get_orchestrator()
        return {"ok": True, **orch.policy.describe_level()}

    @router.post("/autonomy")
    async def set_autonomy_ep(req: Request) -> dict[str, Any]:
        body = await req.json()
        raw_level = body.get("level")
        if raw_level is None or int(raw_level) not in (1, 2, 3, 4):
            raise HTTPException(status_code=400, detail="Autonomy level must be 1, 2, 3, or 4.")
        orch = get_orchestrator()
        orch.policy.set_level(int(raw_level))
        return {"ok": True, **orch.policy.describe_level()}

    @router.get("/workspace")
    async def get_workspace_ep() -> dict[str, Any]:
        orch = get_orchestrator()
        return {"ok": True, "workspace": orch.active_workspace}

    @router.post("/workspace")
    async def set_workspace_ep(req: Request) -> dict[str, Any]:
        body = await req.json()
        path = str(body.get("path", "")).strip()
        if not path:
            raise HTTPException(status_code=400, detail="Workspace path is required.")
        orch = get_orchestrator()
        try:
            resolved = orch.set_workspace(path)
            return {"ok": True, "workspace": resolved}
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    @router.get("/workspace/inspect")
    async def inspect_workspace_ep() -> dict[str, Any]:
        orch = get_orchestrator()
        if not orch.active_workspace:
            raise HTTPException(status_code=400, detail="No active workspace selected.")
        return {"ok": True, **workspace_inspect(orch.active_workspace)}

    @router.get("/workspace/file")
    async def read_workspace_file_ep(
        path: str = Query(...),
        start_line: int = Query(1, ge=1),
        end_line: int = Query(400, ge=1),
    ) -> dict[str, Any]:
        orch = get_orchestrator()
        if not orch.active_workspace:
            raise HTTPException(status_code=400, detail="No active workspace selected.")
        try:
            data = workspace_read_file(path, orch.active_workspace, start_line=start_line, end_line=end_line)
            return {"ok": True, **data}
        except (FileNotFoundError, PermissionError) as e:
            raise HTTPException(status_code=403 if isinstance(e, PermissionError) else 404, detail=str(e))

    @router.get("/workspace/checkpoints")
    async def list_checkpoints_ep() -> dict[str, Any]:
        orch = get_orchestrator()
        if not orch.active_workspace:
            raise HTTPException(status_code=400, detail="No active workspace selected.")
        cps = list_checkpoints(orch.active_workspace)
        return {"ok": True, "count": len(cps), "checkpoints": cps}

    @router.post("/workspace/rollback")
    async def rollback_workspace_ep(req: Request) -> dict[str, Any]:
        orch = get_orchestrator()
        if not orch.active_workspace:
            raise HTTPException(status_code=400, detail="No active workspace selected.")
        body = await req.json()
        cp_id = str(body.get("checkpoint_id", "")).strip()
        if not cp_id:
            raise HTTPException(status_code=400, detail="Field 'checkpoint_id' is required.")
        try:
            res = workspace_rollback(orch.active_workspace, cp_id)
            return {"ok": True, **res}
        except (FileNotFoundError, PermissionError) as e:
            raise HTTPException(status_code=404, detail=str(e))

    @router.get("/tools")
    async def list_tools_ep(category: Optional[str] = Query(None)) -> dict[str, Any]:
        orch = get_orchestrator()
        tools = orch.tools.list_tools(category=category)
        return {"ok": True, "count": len(tools), "tools": tools}

    @router.post("/tasks")
    async def submit_task_ep(req: Request) -> dict[str, Any]:
        body = await req.json()
        user_request = str(body.get("request") or body.get("query") or "").strip()
        if not user_request:
            raise HTTPException(status_code=400, detail="Field 'request' is required.")
        agent_name = body.get("agent")
        workspace = body.get("workspace")
        context = body.get("context") or {}
        orch = get_orchestrator()
        outcome = await orch.submit_task(
            user_request=user_request,
            agent_name=agent_name,
            workspace=workspace,
            context=context,
        )
        return {"ok": True, **outcome}

    @router.get("/tasks")
    async def list_tasks_ep(
        status: Optional[str] = Query(None),
        limit: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        orch = get_orchestrator()
        items = [t.to_dict() for t in orch.tasks.list_tasks(status=status, limit=limit)]
        return {"ok": True, "count": len(items), "tasks": items}

    @router.get("/tasks/{task_id}")
    async def get_task_ep(task_id: str) -> dict[str, Any]:
        orch = get_orchestrator()
        task = orch.tasks.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found.")
        return {"ok": True, "task": task.to_dict()}

    @router.post("/tasks/{task_id}/cancel")
    async def cancel_task_ep(task_id: str) -> dict[str, Any]:
        orch = get_orchestrator()
        ok = orch.tasks.cancel_task(task_id)
        if not ok:
            raise HTTPException(status_code=400, detail="Task not found or already finished.")
        task = orch.tasks.get_task(task_id)
        return {"ok": True, "task": task.to_dict() if task else None}

    @router.post("/tasks/{task_id}/pause")
    async def pause_task_ep(task_id: str) -> dict[str, Any]:
        orch = get_orchestrator()
        ok = orch.tasks.pause_task(task_id)
        if not ok:
            raise HTTPException(status_code=400, detail="Task cannot be paused in its current state.")
        task = orch.tasks.get_task(task_id)
        return {"ok": True, "task": task.to_dict() if task else None}

    @router.post("/tasks/{task_id}/resume")
    async def resume_task_ep(task_id: str) -> dict[str, Any]:
        orch = get_orchestrator()
        ok = orch.tasks.resume_task(task_id)
        if not ok:
            raise HTTPException(status_code=400, detail="Task is not paused.")
        task = orch.tasks.get_task(task_id)
        return {"ok": True, "task": task.to_dict() if task else None}

    @router.get("/approvals")
    async def list_approvals_ep(status: Optional[str] = Query("PENDING")) -> dict[str, Any]:
        orch = get_orchestrator()
        items = [a.to_dict() for a in orch.tasks.list_approvals(status=status)]
        return {"ok": True, "count": len(items), "approvals": items}

    @router.post("/approvals/{approval_id}")
    async def resolve_approval_ep(approval_id: str, req: Request) -> dict[str, Any]:
        body = await req.json()
        if "approved" not in body:
            raise HTTPException(status_code=400, detail="Boolean field 'approved' is required.")
        approved = bool(body["approved"])
        note = body.get("note")
        orch = get_orchestrator()
        res = await orch.resolve_approval_and_continue(approval_id, approved=approved, note=note)
        if not res.get("ok"):
            raise HTTPException(status_code=404, detail=res.get("error", "Approval failed."))
        return res
else:
    router = None
