"""
agents/models.py — Core data models and enums for the JARVIS 24 Autonomous Agent system.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Optional
import uuid


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TaskStatus(str, Enum):
    QUEUED = "QUEUED"
    PLANNING = "PLANNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    TESTING = "TESTING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AutonomyLevel(IntEnum):
    ASSIST = 1               # Answers, teaches, researches, recommends only
    PREPARE = 2              # Creates plans, drafts, reports without executing changes
    EXECUTE_APPROVED = 3     # Executes approved file changes, coding, tests, workflows
    CONTROLLED_AUTONOMY = 4  # Completes low-risk predefined tasks independently; high-risk still gated


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class TaskStep:
    step_id: str
    title: str
    description: str
    tool_name: Optional[str] = None
    tool_params: dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    status: str = "PENDING"  # PENDING | RUNNING | COMPLETED | FAILED | SKIPPED | WAITING_APPROVAL
    output: Optional[str] = None
    error: Optional[str] = None
    attempts: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskStep":
        rl = data.get("risk_level", RiskLevel.LOW)
        if not isinstance(rl, RiskLevel):
            rl = RiskLevel(str(rl).upper())
        return cls(
            step_id=data.get("step_id", f"step_{uuid.uuid4().hex[:6]}"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            tool_name=data.get("tool_name"),
            tool_params=data.get("tool_params") or {},
            risk_level=rl,
            status=data.get("status", "PENDING"),
            output=data.get("output"),
            error=data.get("error"),
            attempts=int(data.get("attempts", 0)),
        )


@dataclass
class ExecutionPlan:
    objective: str
    agent_name: str
    steps: list[TaskStep] = field(default_factory=list)
    files_to_create: list[str] = field(default_factory=list)
    files_to_modify: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    validation_approach: str = ""
    requires_plan_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "agent_name": self.agent_name,
            "steps": [s.to_dict() for s in self.steps],
            "files_to_create": list(self.files_to_create),
            "files_to_modify": list(self.files_to_modify),
            "dependencies": list(self.dependencies),
            "risks": list(self.risks),
            "validation_approach": self.validation_approach,
            "requires_plan_approval": self.requires_plan_approval,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionPlan":
        return cls(
            objective=data.get("objective", ""),
            agent_name=data.get("agent_name", "general"),
            steps=[TaskStep.from_dict(s) for s in data.get("steps", [])],
            files_to_create=list(data.get("files_to_create", [])),
            files_to_modify=list(data.get("files_to_modify", [])),
            dependencies=list(data.get("dependencies", [])),
            risks=list(data.get("risks", [])),
            validation_approach=data.get("validation_approach", ""),
            requires_plan_approval=bool(data.get("requires_plan_approval", False)),
        )


@dataclass
class ApprovalRequest:
    approval_id: str
    task_id: str
    action_type: str
    summary: str
    risk_level: RiskLevel
    details: dict[str, Any] = field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: str = field(default_factory=utc_now_iso)
    resolved_at: Optional[str] = None
    resolver_note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "task_id": self.task_id,
            "action_type": self.action_type,
            "summary": self.summary,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level),
            "details": self.details,
            "status": self.status.value if isinstance(self.status, ApprovalStatus) else str(self.status),
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "resolver_note": self.resolver_note,
        }


@dataclass
class ToolResult:
    ok: bool
    tool_name: str
    output: Any = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "tool_name": self.tool_name,
            "output": self.output,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "metadata": self.metadata,
        }


@dataclass
class AgentResult:
    ok: bool
    agent_name: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    commands_executed: list[str] = field(default_factory=list)
    verified: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "agent_name": self.agent_name,
            "summary": self.summary,
            "data": self.data,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "commands_executed": self.commands_executed,
            "verified": self.verified,
            "error": self.error,
        }


@dataclass
class TaskRecord:
    task_id: str
    user_request: str
    task_type: str
    selected_agent: str
    status: TaskStatus = TaskStatus.QUEUED
    plan: Optional[ExecutionPlan] = None
    current_step: int = 0
    execution_log: list[dict[str, Any]] = field(default_factory=list)
    files_affected: list[str] = field(default_factory=list)
    approval_state: str = "NONE"  # NONE | PENDING | APPROVED | REJECTED
    start_time: str = field(default_factory=utc_now_iso)
    completion_time: Optional[str] = None
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    workspace: Optional[str] = None
    autonomy_level: int = AutonomyLevel.EXECUTE_APPROVED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "user_request": self.user_request,
            "task_type": self.task_type,
            "selected_agent": self.selected_agent,
            "status": self.status.value if isinstance(self.status, TaskStatus) else str(self.status),
            "plan": self.plan.to_dict() if self.plan else None,
            "current_step": self.current_step,
            "execution_log": self.execution_log,
            "files_affected": self.files_affected,
            "approval_state": self.approval_state,
            "start_time": self.start_time,
            "completion_time": self.completion_time,
            "result": self.result,
            "error": self.error,
            "workspace": self.workspace,
            "autonomy_level": self.autonomy_level,
        }
