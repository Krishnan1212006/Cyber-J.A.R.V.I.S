"""
agents/task_manager.py — Persistent SQLite-backed Task Manager for JARVIS 24.

Tracks every task's lifecycle, execution plan, step progress, logs, affected files,
approval requests, pause/resume, and cancellation state.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from .models import (
    ApprovalRequest,
    ApprovalStatus,
    AutonomyLevel,
    ExecutionPlan,
    RiskLevel,
    TaskRecord,
    TaskStatus,
    utc_now_iso,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_AGENT_DB = (
    Path("/tmp/jarvis_data/jarvis_agents.db")
    if __import__("os").environ.get("VERCEL")
    else BASE_DIR / "data" / "jarvis_agents.db"
)


class TaskManager:
    """Thread-safe SQLite-backed task & approval state store."""

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_AGENT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._cancelled_tasks: set[str] = set()
        self._paused_tasks: set[str] = set()
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=15)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_tasks (
                    task_id TEXT PRIMARY KEY,
                    user_request TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    selected_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    plan_json TEXT,
                    current_step INTEGER DEFAULT 0,
                    files_affected_json TEXT DEFAULT '[]',
                    approval_state TEXT DEFAULT 'NONE',
                    start_time TEXT NOT NULL,
                    completion_time TEXT,
                    result_json TEXT,
                    error TEXT,
                    workspace TEXT,
                    autonomy_level INTEGER DEFAULT 3
                );

                CREATE TABLE IF NOT EXISTS agent_task_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES agent_tasks(task_id)
                );

                CREATE TABLE IF NOT EXISTS agent_approvals (
                    approval_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolver_note TEXT,
                    FOREIGN KEY (task_id) REFERENCES agent_tasks(task_id)
                );

                CREATE INDEX IF NOT EXISTS idx_tasks_status ON agent_tasks(status);
                CREATE INDEX IF NOT EXISTS idx_logs_task ON agent_task_logs(task_id);
                CREATE INDEX IF NOT EXISTS idx_approvals_status ON agent_approvals(status);
                """
            )

    def create_task(
        self,
        user_request: str,
        task_type: str,
        selected_agent: str,
        workspace: Optional[str] = None,
        autonomy_level: AutonomyLevel = AutonomyLevel.EXECUTE_APPROVED,
    ) -> TaskRecord:
        task = TaskRecord(
            task_id=f"task_{uuid.uuid4().hex[:10]}",
            user_request=user_request,
            task_type=task_type,
            selected_agent=selected_agent,
            status=TaskStatus.QUEUED,
            workspace=workspace,
            autonomy_level=int(autonomy_level),
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO agent_tasks (
                    task_id, user_request, task_type, selected_agent, status,
                    plan_json, current_step, files_affected_json, approval_state,
                    start_time, completion_time, result_json, error, workspace, autonomy_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    task.user_request,
                    task.task_type,
                    task.selected_agent,
                    task.status.value,
                    None,
                    0,
                    "[]",
                    "NONE",
                    task.start_time,
                    None,
                    None,
                    None,
                    task.workspace,
                    task.autonomy_level,
                ),
            )
        self.append_log(task.task_id, "INFO", f"Task queued for agent '{selected_agent}' (type={task_type}).")
        return task

    def _row_to_task(self, row: sqlite3.Row, logs: list[dict[str, Any]]) -> TaskRecord:
        plan = ExecutionPlan.from_dict(json.loads(row["plan_json"])) if row["plan_json"] else None
        result = json.loads(row["result_json"]) if row["result_json"] else None
        files = json.loads(row["files_affected_json"] or "[]")
        return TaskRecord(
            task_id=row["task_id"],
            user_request=row["user_request"],
            task_type=row["task_type"],
            selected_agent=row["selected_agent"],
            status=TaskStatus(row["status"]),
            plan=plan,
            current_step=int(row["current_step"] or 0),
            execution_log=logs,
            files_affected=files,
            approval_state=row["approval_state"] or "NONE",
            start_time=row["start_time"],
            completion_time=row["completion_time"],
            result=result,
            error=row["error"],
            workspace=row["workspace"],
            autonomy_level=int(row["autonomy_level"] or 3),
        )

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM agent_tasks WHERE task_id = ?", (task_id,)).fetchone()
            if not row:
                return None
            log_rows = conn.execute(
                "SELECT timestamp, level, message FROM agent_task_logs WHERE task_id = ? ORDER BY id ASC",
                (task_id,),
            ).fetchall()
            logs = [dict(r) for r in log_rows]
            return self._row_to_task(row, logs)

    def list_tasks(self, status: Optional[str] = None, limit: int = 50) -> list[TaskRecord]:
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM agent_tasks WHERE status = ? ORDER BY start_time DESC LIMIT ?",
                    (status.upper(), limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM agent_tasks ORDER BY start_time DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            tasks = []
            for row in rows:
                log_rows = conn.execute(
                    "SELECT timestamp, level, message FROM agent_task_logs WHERE task_id = ? ORDER BY id ASC",
                    (row["task_id"],),
                ).fetchall()
                tasks.append(self._row_to_task(row, [dict(r) for r in log_rows]))
            return tasks

    def update_status(
        self,
        task_id: str,
        status: TaskStatus,
        current_step: Optional[int] = None,
        error: Optional[str] = None,
        result: Optional[dict[str, Any]] = None,
        approval_state: Optional[str] = None,
    ) -> None:
        fields = ["status = ?"]
        vals: list[Any] = [status.value]
        if current_step is not None:
            fields.append("current_step = ?")
            vals.append(current_step)
        if error is not None:
            fields.append("error = ?")
            vals.append(error)
        if result is not None:
            fields.append("result_json = ?")
            vals.append(json.dumps(result, ensure_ascii=False, default=str))
        if approval_state is not None:
            fields.append("approval_state = ?")
            vals.append(approval_state)
        if status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
            fields.append("completion_time = ?")
            vals.append(utc_now_iso())

        vals.append(task_id)
        with self._conn() as conn:
            conn.execute(f"UPDATE agent_tasks SET {', '.join(fields)} WHERE task_id = ?", tuple(vals))

    def set_plan(self, task_id: str, plan: ExecutionPlan) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE agent_tasks SET plan_json = ? WHERE task_id = ?",
                (json.dumps(plan.to_dict(), ensure_ascii=False), task_id),
            )

    def append_log(self, task_id: str, level: str, message: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO agent_task_logs (task_id, timestamp, level, message) VALUES (?, ?, ?, ?)",
                (task_id, utc_now_iso(), level.upper(), message),
            )

    def record_file_affected(self, task_id: str, file_path: str) -> None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT files_affected_json FROM agent_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if not row:
                return
            files = json.loads(row["files_affected_json"] or "[]")
            if file_path not in files:
                files.append(file_path)
                conn.execute(
                    "UPDATE agent_tasks SET files_affected_json = ? WHERE task_id = ?",
                    (json.dumps(files, ensure_ascii=False), task_id),
                )

    # ── Pause / Resume / Cancel ──────────────────────────────────────────────

    def cancel_task(self, task_id: str, reason: str = "Cancelled by Sir.") -> bool:
        task = self.get_task(task_id)
        if not task:
            return False
        if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
            return False
        self._cancelled_tasks.add(task_id)
        self._paused_tasks.discard(task_id)
        self.update_status(task_id, TaskStatus.CANCELLED, error=reason)
        self.append_log(task_id, "WARN", reason)
        return True

    def is_cancelled(self, task_id: str) -> bool:
        if task_id in self._cancelled_tasks:
            return True
        task = self.get_task(task_id)
        return bool(task and task.status == TaskStatus.CANCELLED)

    def pause_task(self, task_id: str) -> bool:
        task = self.get_task(task_id)
        if not task or task.status not in (TaskStatus.EXECUTING, TaskStatus.PLANNING, TaskStatus.QUEUED):
            return False
        self._paused_tasks.add(task_id)
        self.update_status(task_id, TaskStatus.PAUSED)
        self.append_log(task_id, "INFO", "Task paused by Sir.")
        return True

    def resume_task(self, task_id: str) -> bool:
        task = self.get_task(task_id)
        if not task or task.status != TaskStatus.PAUSED:
            return False
        self._paused_tasks.discard(task_id)
        self.update_status(task_id, TaskStatus.EXECUTING)
        self.append_log(task_id, "INFO", "Task resumed by Sir.")
        return True

    def is_paused(self, task_id: str) -> bool:
        return task_id in self._paused_tasks

    # ── Approvals ────────────────────────────────────────────────────────────

    def create_approval(
        self,
        task_id: str,
        action_type: str,
        summary: str,
        risk_level: RiskLevel,
        details: Optional[dict[str, Any]] = None,
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            approval_id=f"appr_{uuid.uuid4().hex[:10]}",
            task_id=task_id,
            action_type=action_type,
            summary=summary,
            risk_level=risk_level,
            details=details or {},
            status=ApprovalStatus.PENDING,
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO agent_approvals (
                    approval_id, task_id, action_type, summary, risk_level,
                    details_json, status, created_at, resolved_at, resolver_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.approval_id,
                    req.task_id,
                    req.action_type,
                    req.summary,
                    req.risk_level.value,
                    json.dumps(req.details, ensure_ascii=False, default=str),
                    req.status.value,
                    req.created_at,
                    None,
                    None,
                ),
            )
        self.update_status(task_id, TaskStatus.WAITING_APPROVAL, approval_state="PENDING")
        self.append_log(task_id, "WARN", f"Waiting for Sir's approval ({req.approval_id}): {summary}")
        return req

    def _row_to_approval(self, row: sqlite3.Row) -> ApprovalRequest:
        return ApprovalRequest(
            approval_id=row["approval_id"],
            task_id=row["task_id"],
            action_type=row["action_type"],
            summary=row["summary"],
            risk_level=RiskLevel(row["risk_level"]),
            details=json.loads(row["details_json"] or "{}"),
            status=ApprovalStatus(row["status"]),
            created_at=row["created_at"],
            resolved_at=row["resolved_at"],
            resolver_note=row["resolver_note"],
        )

    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM agent_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            return self._row_to_approval(row) if row else None

    def list_approvals(self, status: Optional[str] = "PENDING") -> list[ApprovalRequest]:
        with self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM agent_approvals WHERE status = ? ORDER BY created_at DESC",
                    (status.upper(),),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM agent_approvals ORDER BY created_at DESC").fetchall()
            return [self._row_to_approval(r) for r in rows]

    def resolve_approval(
        self, approval_id: str, approved: bool, note: Optional[str] = None
    ) -> Optional[ApprovalRequest]:
        req = self.get_approval(approval_id)
        if not req or req.status != ApprovalStatus.PENDING:
            return None
        new_status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        now = utc_now_iso()
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE agent_approvals
                SET status = ?, resolved_at = ?, resolver_note = ?
                WHERE approval_id = ?
                """,
                (new_status.value, now, note, approval_id),
            )
        if approved:
            self.update_status(req.task_id, TaskStatus.EXECUTING, approval_state="APPROVED")
            self.append_log(req.task_id, "INFO", f"Approval {approval_id} GRANTED by Sir.")
        else:
            self.update_status(
                req.task_id,
                TaskStatus.CANCELLED,
                approval_state="REJECTED",
                error=f"Approval {approval_id} rejected by Sir.",
            )
            self.append_log(req.task_id, "WARN", f"Approval {approval_id} REJECTED by Sir.")
        return self.get_approval(approval_id)
