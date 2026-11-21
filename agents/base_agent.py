"""
agents/base_agent.py — Base contract for all specialized JARVIS 24 agents.

Enforces bounded steps, timeouts, retries, cancellation checks, and verification.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Optional

from .autonomy import AutonomyPolicy
from .models import AgentResult, ExecutionPlan, RiskLevel, TaskRecord, TaskStatus, TaskStep
from .task_manager import TaskManager
from .tool_registry import ToolRegistry


class BaseAgent(ABC):
    name: str = "base"
    description: str = "Base JARVIS agent"
    capabilities: list[str] = []
    max_steps: int = 12
    max_retries_per_step: int = 2

    def __init__(
        self,
        tool_registry: ToolRegistry,
        task_manager: TaskManager,
        autonomy_policy: AutonomyPolicy,
    ):
        self.tools = tool_registry
        self.tasks = task_manager
        self.policy = autonomy_policy

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "max_steps": self.max_steps,
        }

    @abstractmethod
    async def create_plan(self, task: TaskRecord, context: dict[str, Any]) -> ExecutionPlan:
        """Analyze the request and produce a bounded ExecutionPlan."""

    async def execute_step(
        self,
        task: TaskRecord,
        step: TaskStep,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Default step executor: invokes step.tool_name via ToolRegistry if specified.
        Subclasses may override for custom reasoning or multi-tool steps.
        """
        if not step.tool_name:
            return {"ok": True, "output": f"Completed step '{step.title}'."}

        res = await self.tools.execute(
            step.tool_name,
            params=step.tool_params,
            workspace=task.workspace,
        )
        if res.ok:
            return {"ok": True, "output": res.output}
        return {"ok": False, "error": res.error}

    async def verify_result(
        self,
        task: TaskRecord,
        step_outputs: list[dict[str, Any]],
    ) -> tuple[bool, str]:
        """Verify that all executed steps succeeded. Subclasses can add test/lint verification."""
        failed = [s for s in step_outputs if not s.get("ok")]
        if failed:
            return False, f"{len(failed)} step(s) failed verification."
        return True, "All planned steps executed and verified successfully."

    async def run(
        self,
        task: TaskRecord,
        context: Optional[dict[str, Any]] = None,
        start_from_step: int = 0,
        pre_approved_step_ids: Optional[set[str]] = None,
    ) -> AgentResult:
        """
        Bounded execution loop:
        1. Plan (or reuse existing plan on resume)
        2. Enforce max_steps
        3. Check cancellation, pause, and autonomy/approval gate per step
        4. Retry transient failures up to max_retries_per_step
        5. Verify and return structured AgentResult
        """
        context = dict(context or {})
        pre_approved = pre_approved_step_ids or set()

        if task.plan is None:
            self.tasks.update_status(task.task_id, TaskStatus.PLANNING)
            self.tasks.append_log(task.task_id, "INFO", f"Agent '{self.name}' is creating an execution plan.")
            plan = await self.create_plan(task, context)
            if len(plan.steps) > self.max_steps:
                plan.steps = plan.steps[: self.max_steps]
                self.tasks.append_log(
                    task.task_id,
                    "WARN",
                    f"Plan truncated to safety limit of {self.max_steps} steps.",
                )
            self.tasks.set_plan(task.task_id, plan)
            task.plan = plan
        else:
            plan = task.plan

        self.tasks.update_status(task.task_id, TaskStatus.EXECUTING)
        outputs: list[dict[str, Any]] = []
        commands_executed: list[str] = []

        for idx, step in enumerate(plan.steps):
            if idx < start_from_step:
                outputs.append({"ok": True, "step_id": step.step_id, "output": step.output})
                continue

            # Cancellation check
            if self.tasks.is_cancelled(task.task_id):
                return AgentResult(
                    ok=False,
                    agent_name=self.name,
                    summary="Task was cancelled by Sir before completion.",
                    error="CANCELLED",
                )

            # Pause check (bounded wait)
            pause_ticks = 0
            while self.tasks.is_paused(task.task_id):
                if self.tasks.is_cancelled(task.task_id):
                    return AgentResult(
                        ok=False,
                        agent_name=self.name,
                        summary="Task cancelled while paused.",
                        error="CANCELLED",
                    )
                await asyncio.sleep(0.1)
                pause_ticks += 1
                if pause_ticks > 3000:  # 5 min safety bound
                    self.tasks.update_status(task.task_id, TaskStatus.FAILED, error="Pause timeout exceeded.")
                    return AgentResult(
                        ok=False,
                        agent_name=self.name,
                        summary="Task timed out while paused.",
                        error="PAUSE_TIMEOUT",
                    )

            self.tasks.update_status(task.task_id, TaskStatus.EXECUTING, current_step=idx + 1)

            # Autonomy & Approval Gate
            if step.step_id not in pre_approved:
                tool_def = self.tools.get(step.tool_name) if step.tool_name else None
                decision = self.policy.evaluate_action(
                    action_name=step.tool_name or step.title,
                    risk_level=tool_def.risk_level if tool_def else step.risk_level,
                    explicit_requires_approval=bool(tool_def.requires_approval) if tool_def else False,
                    params=step.tool_params,
                    is_mutating=bool(tool_def.is_mutating) if tool_def else False,
                )
                if not decision.allowed:
                    step.status = "FAILED"
                    step.error = decision.reason
                    self.tasks.set_plan(task.task_id, plan)
                    self.tasks.update_status(task.task_id, TaskStatus.FAILED, error=decision.reason)
                    self.tasks.append_log(task.task_id, "ERROR", decision.reason)
                    return AgentResult(
                        ok=False,
                        agent_name=self.name,
                        summary=f"Sir, action blocked by autonomy policy: {decision.reason}",
                        error=decision.reason,
                    )
                if decision.requires_approval:
                    step.status = "WAITING_APPROVAL"
                    self.tasks.set_plan(task.task_id, plan)
                    appr = self.tasks.create_approval(
                        task_id=task.task_id,
                        action_type=step.tool_name or "step_execution",
                        summary=f"Approve step '{step.title}': {decision.reason}",
                        risk_level=decision.effective_risk,
                        details={
                            "step_index": idx,
                            "step_id": step.step_id,
                            "tool_name": step.tool_name,
                            "tool_params": step.tool_params,
                        },
                    )
                    return AgentResult(
                        ok=True,
                        agent_name=self.name,
                        summary=f"Sir, step '{step.title}' requires your approval ({appr.approval_id}) before proceeding.",
                        data={"approval_required": True, "approval": appr.to_dict()},
                        verified=False,
                    )

            # Execute step with bounded retries
            step.status = "RUNNING"
            self.tasks.append_log(task.task_id, "INFO", f"Step {idx + 1}/{len(plan.steps)}: {step.title}")
            step_res: dict[str, Any] = {"ok": False, "error": "Not executed"}

            for attempt in range(1, self.max_retries_per_step + 1):
                step.attempts = attempt
                step_res = await self.execute_step(task, step, context)
                if step_res.get("ok"):
                    break
                self.tasks.append_log(
                    task.task_id,
                    "WARN",
                    f"Step '{step.title}' attempt {attempt} failed: {step_res.get('error')}",
                )

            if step_res.get("ok"):
                step.status = "COMPLETED"
                step.output = str(step_res.get("output", ""))[:4000]
                if step.tool_name == "run_terminal" and step.tool_params.get("command"):
                    commands_executed.append(str(step.tool_params["command"]))
                outputs.append({"ok": True, "step_id": step.step_id, "output": step_res.get("output")})
                self.tasks.set_plan(task.task_id, plan)
            else:
                step.status = "FAILED"
                step.error = str(step_res.get("error", "Unknown error"))
                self.tasks.set_plan(task.task_id, plan)
                self.tasks.update_status(task.task_id, TaskStatus.FAILED, error=step.error)
                self.tasks.append_log(task.task_id, "ERROR", f"Step '{step.title}' failed permanently: {step.error}")
                return AgentResult(
                    ok=False,
                    agent_name=self.name,
                    summary=f"Sir, task failed at step '{step.title}': {step.error}",
                    data={"step_outputs": outputs},
                    commands_executed=commands_executed,
                    verified=False,
                    error=step.error,
                )

        # Verification phase
        self.tasks.update_status(task.task_id, TaskStatus.TESTING)
        verified, verify_msg = await self.verify_result(task, outputs)
        self.tasks.append_log(task.task_id, "INFO", f"Verification: {verify_msg}")

        final_summary = self._build_summary(task, outputs, verify_msg)
        result = AgentResult(
            ok=verified,
            agent_name=self.name,
            summary=final_summary,
            data={"step_outputs": outputs, "verification": verify_msg},
            commands_executed=commands_executed,
            verified=verified,
            error=None if verified else verify_msg,
        )
        self.tasks.update_status(
            task.task_id,
            TaskStatus.COMPLETED if verified else TaskStatus.FAILED,
            result=result.to_dict(),
            error=result.error,
        )
        return result

    def _build_summary(
        self,
        task: TaskRecord,
        outputs: list[dict[str, Any]],
        verify_msg: str,
    ) -> str:
        if outputs and outputs[-1].get("output") is not None:
            last_out = outputs[-1]["output"]
            if isinstance(last_out, str) and last_out.strip():
                return last_out.strip()
        return f"Sir, task '{task.user_request[:80]}' completed. {verify_msg}"


class GeneralAssistantAgent(BaseAgent):
    """Default Phase 1 agent for status, capability discovery, and informational routing."""

    name = "general"
    description = "General JARVIS assistant for system status, capability queries, and routing."
    capabilities = ["general", "status", "help", "conversation"]
    max_steps = 4

    async def create_plan(self, task: TaskRecord, context: dict[str, Any]) -> ExecutionPlan:
        req_lower = task.user_request.lower()
        steps: list[TaskStep] = []

        if any(k in req_lower for k in ("status", "health", "diagnostics", "agents", "tools")):
            steps.append(
                TaskStep(
                    step_id="step_status",
                    title="Inspect JARVIS Core Status",
                    description="Gather live orchestrator, autonomy, and system telemetry.",
                    tool_name="system_status",
                    tool_params={},
                    risk_level=RiskLevel.LOW,
                )
            )
        else:
            steps.append(
                TaskStep(
                    step_id="step_respond",
                    title="Process Request",
                    description="Handle conversational or informational request.",
                    tool_name="information_lookup",
                    tool_params={"query": task.user_request},
                    risk_level=RiskLevel.LOW,
                )
            )

        return ExecutionPlan(
            objective=task.user_request,
            agent_name=self.name,
            steps=steps,
            validation_approach="Verify tool output returned cleanly without errors.",
        )
