"""
agents/coding_agent.py — Dedicated Workspace CodingAgent (Phase 2).

Follows the 8-step verified coding workflow:
1. Task Understanding
2. Workspace Inspection
3. Implementation Plan
4. Checkpoint & Code Generation / Surgical Edits
5. Controlled Execution & Test Runner
6. Code Review (AST syntax + secret scan)
7. Completion Report with diffs, test results, and rollback checkpoint ID
"""
from __future__ import annotations

from typing import Any, Optional

from .base_agent import BaseAgent
from .models import (
    AgentResult,
    ExecutionPlan,
    RiskLevel,
    TaskRecord,
    TaskStep,
)


class CodingAgent(BaseAgent):
    name = "coding"
    description = (
        "Autonomous workspace software engineer: inspects projects, plans changes, "
        "creates rollback checkpoints, writes/edits code, runs tests, and reviews diffs."
    )
    capabilities = [
        "inspect_workspace",
        "read_code",
        "search_code",
        "create_file",
        "edit_file",
        "run_tests",
        "code_review",
        "rollback",
    ]
    max_steps = 12
    max_retries_per_step = 2

    async def create_plan(self, task: TaskRecord, context: dict[str, Any]) -> ExecutionPlan:
        """
        Build a structured multi-step coding plan.
        Supports:
        - Read-only inspection / explanation / review requests
        - Structured file edits/creations passed via `context["operations"]`
        - Automated test & static code review verification
        """
        if not task.workspace:
            return ExecutionPlan(
                objective=task.user_request,
                agent_name=self.name,
                steps=[],
                risks=["No authorized workspace selected."],
                validation_approach="Select a workspace before running coding tasks.",
            )

        operations: list[dict[str, Any]] = list(context.get("operations") or [])
        run_tests_flag = bool(context.get("run_tests", True))
        steps: list[TaskStep] = []
        files_to_create: list[str] = []
        files_to_modify: list[str] = []

        # Step 1: Always inspect workspace first (never assume stack)
        steps.append(
            TaskStep(
                step_id="step_inspect",
                title="Inspect Workspace",
                description="Scan project structure, languages, frameworks, tests, and Git status.",
                tool_name="workspace_inspect",
                tool_params={},
                risk_level=RiskLevel.LOW,
            )
        )

        # If specific file operations are requested, create a rollback checkpoint first
        if operations:
            affected_paths = [op["path"] for op in operations if op.get("path")]
            steps.append(
                TaskStep(
                    step_id="step_checkpoint",
                    title="Create Rollback Checkpoint",
                    description="Snapshot affected files before applying any changes.",
                    tool_name="workspace_checkpoint",
                    tool_params={"label": task.task_id, "files": affected_paths},
                    risk_level=RiskLevel.LOW,
                )
            )

            for i, op in enumerate(operations, 1):
                op_type = op.get("type", "write")
                rel_path = op.get("path", "")
                if op_type == "edit":
                    files_to_modify.append(rel_path)
                    steps.append(
                        TaskStep(
                            step_id=f"step_edit_{i}",
                            title=f"Edit {rel_path}",
                            description=op.get("description", f"Apply targeted edit to {rel_path}"),
                            tool_name="workspace_edit_file",
                            tool_params={
                                "path": rel_path,
                                "target": op.get("target", ""),
                                "replacement": op.get("replacement", ""),
                            },
                            risk_level=RiskLevel.MEDIUM,
                        )
                    )
                elif op_type == "write":
                    files_to_create.append(rel_path)
                    steps.append(
                        TaskStep(
                            step_id=f"step_write_{i}",
                            title=f"Write {rel_path}",
                            description=op.get("description", f"Write file {rel_path}"),
                            tool_name="workspace_write_file",
                            tool_params={
                                "path": rel_path,
                                "content": op.get("content", ""),
                            },
                            risk_level=RiskLevel.MEDIUM,
                        )
                    )

            # Static Code Review on affected files
            steps.append(
                TaskStep(
                    step_id="step_review",
                    title="Static Code & Security Review",
                    description="Check modified files for AST syntax errors and accidental secrets.",
                    tool_name="workspace_code_review",
                    tool_params={"files": affected_paths},
                    risk_level=RiskLevel.LOW,
                )
            )

            # Run Project Tests
            if run_tests_flag:
                steps.append(
                    TaskStep(
                        step_id="step_test",
                        title="Run Project Test Suite",
                        description="Execute workspace test runner to verify changes and detect regressions.",
                        tool_name="workspace_run_tests",
                        tool_params={"test_command": context.get("test_command")},
                        risk_level=RiskLevel.LOW,
                    )
                )
        else:
            # Read-only analysis / review / test request
            req_l = task.user_request.lower()
            if any(k in req_l for k in ("review", "audit", "check code", "secrets")):
                steps.append(
                    TaskStep(
                        step_id="step_review",
                        title="Static Code & Security Review",
                        description="Check workspace Python files for syntax errors and accidental secrets.",
                        tool_name="workspace_code_review",
                        tool_params={},
                        risk_level=RiskLevel.LOW,
                    )
                )
            if any(k in req_l for k in ("test", "pytest", "run tests")):
                steps.append(
                    TaskStep(
                        step_id="step_test",
                        title="Run Project Test Suite",
                        description="Execute workspace test runner.",
                        tool_name="workspace_run_tests",
                        tool_params={},
                        risk_level=RiskLevel.LOW,
                    )
                )

        return ExecutionPlan(
            objective=task.user_request,
            agent_name=self.name,
            steps=steps,
            files_to_create=files_to_create,
            files_to_modify=files_to_modify,
            risks=["File modifications are protected by pre-edit rollback checkpoint and approval gates."],
            validation_approach="AST syntax check, secret scan, and automated project test suite.",
            requires_plan_approval=bool(operations),
        )

    async def execute_step(
        self,
        task: TaskRecord,
        step: TaskStep,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        res = await super().execute_step(task, step, context)
        if res.get("ok") and isinstance(res.get("output"), dict):
            out = res["output"]
            # Track affected files automatically in TaskManager
            if step.tool_name in ("workspace_write_file", "workspace_edit_file") and out.get("path"):
                self.tasks.record_file_affected(task.task_id, out["path"])
        return res

    async def verify_result(
        self,
        task: TaskRecord,
        step_outputs: list[dict[str, Any]],
    ) -> tuple[bool, str]:
        if not task.workspace:
            return False, "No workspace selected. Sir, please select a workspace folder first."

        for item in step_outputs:
            if not item.get("ok"):
                return False, f"Step '{item.get('step_id')}' failed."
            out = item.get("output")
            if isinstance(out, dict):
                # Check static code review
                if item.get("step_id") == "step_review" and out.get("passed") is False:
                    return False, f"Code review failed with {len(out.get('findings', []))} blocking finding(s)."
                # Check test runner outcome
                if item.get("step_id") == "step_test" and out.get("ok") is False:
                    return (
                        False,
                        f"Tests failed (passed={out.get('tests_passed', 0)}, failed={out.get('tests_failed', 0)}).",
                    )

        return True, "Workspace inspection, review, and tests verified cleanly."

    def _build_summary(
        self,
        task: TaskRecord,
        outputs: list[dict[str, Any]],
        verify_msg: str,
    ) -> str:
        created: list[str] = []
        modified: list[str] = []
        cp_id: Optional[str] = None
        test_line = ""

        for item in outputs:
            out = item.get("output")
            if not isinstance(out, dict):
                continue
            if item.get("step_id") == "step_checkpoint" and out.get("checkpoint_id"):
                cp_id = out["checkpoint_id"]
            if out.get("action") == "created" and out.get("path"):
                created.append(out["path"])
            elif out.get("action") == "modified" and out.get("path"):
                modified.append(out["path"])
            if item.get("step_id") == "step_test":
                test_line = f" Tests: {out.get('tests_passed', 0)} passed, {out.get('tests_failed', 0)} failed."

        parts = [f"Sir, coding task '{task.user_request[:80]}' completed."]
        if created:
            parts.append(f"Created: {', '.join(created)}.")
        if modified:
            parts.append(f"Modified: {', '.join(modified)}.")
        if cp_id:
            parts.append(f"Rollback checkpoint: {cp_id}.")
        if test_line:
            parts.append(test_line.strip())
        parts.append(verify_msg)
        return " ".join(parts)
