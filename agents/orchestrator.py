"""
agents/orchestrator.py — Central JARVIS 24 Orchestrator.

Receives voice, text, file, and API task requests, determines intent & complexity,
selects the right agent, enforces autonomy & approvals, and manages task lifecycle.
"""
from __future__ import annotations

import platform
import re
from pathlib import Path
from typing import Any, Optional

from .autonomy import AutonomyPolicy
from .base_agent import BaseAgent, GeneralAssistantAgent
from .coding_agent import CodingAgent
from .models import (
    AgentResult,
    ApprovalRequest,
    AutonomyLevel,
    RiskLevel,
    TaskRecord,
    TaskStatus,
)
from .task_manager import TaskManager
from .tool_registry import ToolDefinition, ToolRegistry
from .workspace_tools import register_workspace_tools


class JarvisOrchestrator:
    """Central multi-agent orchestration layer for JARVIS 24."""

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        autonomy_level: AutonomyLevel = AutonomyLevel.EXECUTE_APPROVED,
    ):
        self.policy = AutonomyPolicy(level=autonomy_level)
        self.tools = ToolRegistry()
        self.tasks = TaskManager(db_path=db_path)
        self._agents: dict[str, BaseAgent] = {}
        self._active_workspace: Optional[str] = None

        self._register_core_tools()
        register_workspace_tools(self.tools)
        self.register_agent(GeneralAssistantAgent(self.tools, self.tasks, self.policy))
        self.register_agent(CodingAgent(self.tools, self.tasks, self.policy))

    # ── Workspace management ─────────────────────────────────────────────────

    @property
    def active_workspace(self) -> Optional[str]:
        return self._active_workspace

    def set_workspace(self, path: str | Path) -> str:
        p = Path(path).resolve()
        if not p.exists() or not p.is_dir():
            raise ValueError(f"Workspace path does not exist or is not a directory: '{p}'")
        self._active_workspace = str(p)
        return self._active_workspace

    # ── Agent registry ───────────────────────────────────────────────────────

    def register_agent(self, agent: BaseAgent) -> None:
        self._agents[agent.name] = agent

    def get_agent(self, name: str) -> Optional[BaseAgent]:
        return self._agents.get(name)

    def list_agents(self) -> list[dict[str, Any]]:
        return [a.info() for a in self._agents.values()]

    # ── Core Phase 1 tools ───────────────────────────────────────────────────

    def _register_core_tools(self) -> None:
        def _tool_system_status() -> dict[str, Any]:
            cpu_pct = None
            ram_pct = None
            try:
                import psutil
                cpu_pct = psutil.cpu_percent(interval=0.1)
                ram_pct = psutil.virtual_memory().percent
            except Exception:
                pass
            return {
                "os": platform.system(),
                "python": platform.python_version(),
                "autonomy": self.policy.describe_level(),
                "registered_agents": list(self._agents.keys()),
                "registered_tools_count": len(self.tools.list_tools(only_enabled=True)),
                "active_workspace": self._active_workspace,
                "cpu_percent": cpu_pct,
                "ram_percent": ram_pct,
            }

        def _tool_information_lookup(query: str) -> str:
            try:
                from intel.information_service import get_information_service
                svc = get_information_service()
                res = svc.process_request(query)
                return res.get("jarvis_response") or "Understood, Sir."
            except Exception:
                return f"Sir, I received your request '{query}' and logged it with the JARVIS orchestrator."

        self.tools.register(
            ToolDefinition(
                name="system_status",
                description="Return real system, orchestrator, autonomy, and agent status.",
                handler=_tool_system_status,
                risk_level=RiskLevel.LOW,
                requires_approval=False,
                is_mutating=False,
                category="system",
            )
        )
        self.tools.register(
            ToolDefinition(
                name="information_lookup",
                description="Query JARVIS InformationService for conversational or structured responses.",
                handler=_tool_information_lookup,
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
                risk_level=RiskLevel.LOW,
                requires_approval=False,
                is_mutating=False,
                category="information",
            )
        )

    # ── Intent classification & routing ──────────────────────────────────────

    def classify_intent(self, user_request: str) -> dict[str, Any]:
        """Classify user intent, task_type, complexity, and preferred agent."""
        q = user_request.strip().lower()

        routing_rules: list[tuple[str, str, list[str]]] = [
            (
                "coding",
                "CODING_TASK",
                [
                    r"\b(?:fix bug|fix this error|refactor|create a (?:file|page|endpoint|website|app))\b",
                    r"\b(?:build a|write tests?|inspect this folder|review (?:this )?code|modify (?:the )?schema)\b",
                    r"\b(?:coding agent|codebase|debug|add an api|implement feature)\b",
                ],
            ),
            (
                "cybersecurity",
                "CYBERSECURITY_TASK",
                [
                    r"\b(?:cyber\s*security|threat intel|cve-\d{4}-\d+|mitre|owasp|ransomware|malware)\b",
                    r"\b(?:vulnerability|security audit|incident response|soc analyst|cyber news|newspaper)\b",
                ],
            ),
            (
                "research",
                "RESEARCH_TASK",
                [
                    r"\b(?:research|compare|comparison of|official documentation|evaluate tools|cite sources)\b",
                ],
            ),
            (
                "learning",
                "LEARNING_TASK",
                [
                    r"\b(?:teach me|explain .* with example|quiz me|learning profile|study guide|lesson)\b",
                ],
            ),
            (
                "memory",
                "MEMORY_TASK",
                [
                    r"\b(?:remember this|recall|what did we decide|search memory|forget|project memory)\b",
                ],
            ),
            (
                "automation",
                "AUTOMATION_TASK",
                [
                    r"\b(?:schedule|automate|every morning|reminder|workflow|batch rename)\b",
                ],
            ),
        ]

        for preferred_agent, task_type, patterns in routing_rules:
            if any(re.search(p, q) for p in patterns):
                selected = preferred_agent if preferred_agent in self._agents else "general"
                return {
                    "preferred_agent": preferred_agent,
                    "selected_agent": selected,
                    "task_type": task_type,
                    "complexity": "MULTI_STEP" if len(q.split()) > 6 else "SINGLE_STEP",
                }

        return {
            "preferred_agent": "general",
            "selected_agent": "general",
            "task_type": "GENERAL_TASK",
            "complexity": "SINGLE_STEP",
        }

    # ── Execution & Approval Lifecycle ───────────────────────────────────────

    async def submit_task(
        self,
        user_request: str,
        agent_name: Optional[str] = None,
        workspace: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Create a task, route it to the appropriate agent, and execute it."""
        intent = self.classify_intent(user_request)
        chosen_agent_name = agent_name if (agent_name and agent_name in self._agents) else intent["selected_agent"]
        agent = self._agents[chosen_agent_name]
        ws = workspace or self._active_workspace

        task = self.tasks.create_task(
            user_request=user_request,
            task_type=intent["task_type"],
            selected_agent=chosen_agent_name,
            workspace=ws,
            autonomy_level=self.policy.level,
        )

        result = await agent.run(task, context=context)
        refreshed = self.tasks.get_task(task.task_id)
        return {
            "task": refreshed.to_dict() if refreshed else task.to_dict(),
            "result": result.to_dict(),
            "intent": intent,
        }

    async def resolve_approval_and_continue(
        self,
        approval_id: str,
        approved: bool,
        note: Optional[str] = None,
    ) -> dict[str, Any]:
        """Approve or reject a pending action; if approved, resume the task from that step."""
        appr = self.tasks.resolve_approval(approval_id, approved=approved, note=note)
        if not appr:
            return {"ok": False, "error": f"Approval '{approval_id}' not found or already resolved."}

        task = self.tasks.get_task(appr.task_id)
        if not task:
            return {"ok": False, "error": f"Task '{appr.task_id}' not found."}

        if not approved:
            return {
                "ok": True,
                "approval": appr.to_dict(),
                "task": task.to_dict(),
                "message": "Sir, the action was rejected and the task has been cancelled.",
            }

        agent = self._agents.get(task.selected_agent)
        if not agent:
            return {"ok": False, "error": f"Agent '{task.selected_agent}' is not registered."}

        step_index = int(appr.details.get("step_index", 0))
        step_id = appr.details.get("step_id")
        pre_approved = {step_id} if step_id else set()

        result = await agent.run(
            task,
            start_from_step=step_index,
            pre_approved_step_ids=pre_approved,
        )
        refreshed = self.tasks.get_task(task.task_id)
        return {
            "ok": True,
            "approval": appr.to_dict(),
            "task": refreshed.to_dict() if refreshed else task.to_dict(),
            "result": result.to_dict(),
        }

    def status_summary(self) -> dict[str, Any]:
        tasks = self.tasks.list_tasks(limit=100)
        pending_approvals = self.tasks.list_approvals(status="PENDING")
        by_status: dict[str, int] = {}
        for t in tasks:
            by_status[t.status.value] = by_status.get(t.status.value, 0) + 1
        return {
            "status": "READY",
            "autonomy": self.policy.describe_level(),
            "active_workspace": self._active_workspace,
            "agents": self.list_agents(),
            "tools_count": len(self.tools.list_tools(only_enabled=True)),
            "task_counts": by_status,
            "pending_approvals_count": len(pending_approvals),
        }


# ── Singleton accessor ───────────────────────────────────────────────────────

_orchestrator_singleton: Optional[JarvisOrchestrator] = None


def get_orchestrator() -> JarvisOrchestrator:
    global _orchestrator_singleton
    if _orchestrator_singleton is None:
        _orchestrator_singleton = JarvisOrchestrator()
    return _orchestrator_singleton


def set_orchestrator(orchestrator: Optional[JarvisOrchestrator]) -> None:
    global _orchestrator_singleton
    _orchestrator_singleton = orchestrator
