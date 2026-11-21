"""
tests/test_agent_core.py — Phase 1 Verification Suite for JARVIS 24 Agent Core.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from agents import (
    AutonomyLevel,
    AutonomyPolicy,
    BaseAgent,
    ExecutionPlan,
    JarvisOrchestrator,
    RiskLevel,
    TaskManager,
    TaskRecord,
    TaskStatus,
    TaskStep,
    ToolDefinition,
    ToolRegistry,
    set_orchestrator,
    validate_workspace_path,
)
from dashboard.server import DashboardServer


class _DemoMutatingAgent(BaseAgent):
    """Test agent with a mutating tool step to verify approvals, retries, and bounds."""

    name = "demo_coder"
    description = "Demo agent for Phase 1 testing."
    capabilities = ["demo"]
    max_steps = 3
    max_retries_per_step = 2

    async def create_plan(self, task: TaskRecord, context: dict) -> ExecutionPlan:
        if "overflow" in task.user_request.lower():
            steps = [
                TaskStep(step_id=f"s{i}", title=f"Step {i}", description="noop", tool_name="safe_echo", tool_params={"msg": str(i)})
                for i in range(10)
            ]
            return ExecutionPlan(objective=task.user_request, agent_name=self.name, steps=steps)

        if "retry_test" in task.user_request.lower():
            return ExecutionPlan(
                objective=task.user_request,
                agent_name=self.name,
                steps=[
                    TaskStep(step_id="s_retry", title="Flaky step", description="fails once then passes", tool_name="flaky_tool")
                ],
            )

        return ExecutionPlan(
            objective=task.user_request,
            agent_name=self.name,
            steps=[
                TaskStep(step_id="s1", title="Read info", description="safe read", tool_name="safe_echo", tool_params={"msg": "checked"}),
                TaskStep(step_id="s2", title="Write change", description="mutating op", tool_name="demo_write", tool_params={"content": "hello"}, risk_level=RiskLevel.MEDIUM),
            ],
        )


class TestAutonomyPolicy(unittest.TestCase):
    def test_level1_blocks_mutations(self):
        policy = AutonomyPolicy(AutonomyLevel.ASSIST)
        d = policy.evaluate_action("edit_file", RiskLevel.MEDIUM, is_mutating=True)
        self.assertFalse(d.allowed)
        self.assertTrue(d.requires_approval)

    def test_level1_allows_safe_read(self):
        policy = AutonomyPolicy(AutonomyLevel.ASSIST)
        d = policy.evaluate_action("read_file", RiskLevel.LOW, is_mutating=False)
        self.assertTrue(d.allowed)
        self.assertFalse(d.requires_approval)

    def test_level3_gates_mutating_actions(self):
        policy = AutonomyPolicy(AutonomyLevel.EXECUTE_APPROVED)
        d = policy.evaluate_action("write_file", RiskLevel.MEDIUM, is_mutating=True)
        self.assertTrue(d.allowed)
        self.assertTrue(d.requires_approval)

    def test_level4_still_gates_always_approval_and_risky_commands(self):
        policy = AutonomyPolicy(AutonomyLevel.CONTROLLED_AUTONOMY)
        d_del = policy.evaluate_action("delete_data", RiskLevel.LOW)
        self.assertTrue(d_del.requires_approval)

        d_cmd = policy.evaluate_action("run_terminal", RiskLevel.LOW, params={"command": "rm -rf /tmp/foo"})
        self.assertTrue(d_cmd.requires_approval)
        self.assertEqual(d_cmd.effective_risk, RiskLevel.HIGH)


class TestToolRegistryAndSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        self.registry = ToolRegistry()

    def tearDown(self):
        self.tmp.cleanup()

    def test_workspace_path_confinement(self):
        inside = validate_workspace_path("sub/file.txt", self.ws)
        self.assertTrue(str(inside).startswith(str(self.ws.resolve())))
        with self.assertRaises(PermissionError):
            validate_workspace_path("../outside.txt", self.ws)

    def test_param_validation_and_execution(self):
        self.registry.register(
            ToolDefinition(
                name="greet",
                description="Greet Sir",
                handler=lambda name: f"Hello, {name}",
                parameters={"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
            )
        )
        bad = asyncio.run(self.registry.execute("greet", {}))
        self.assertFalse(bad.ok)
        self.assertIn("Missing required parameter", bad.error)

        good = asyncio.run(self.registry.execute("greet", {"name": "Sir"}))
        self.assertTrue(good.ok)
        self.assertEqual(good.output, "Hello, Sir")

    def test_tool_timeout_enforcement(self):
        def _slow():
            time.sleep(1.5)
            return "late"

        self.registry.register(
            ToolDefinition(name="slow_tool", description="Too slow", handler=_slow, timeout_seconds=0.15)
        )
        res = asyncio.run(self.registry.execute("slow_tool"))
        self.assertFalse(res.ok)
        self.assertIn("timed out", res.error)

    def test_disabled_tool_cannot_execute(self):
        self.registry.register(ToolDefinition(name="ping", description="Ping", handler=lambda: "pong"))
        self.registry.set_enabled("ping", False)
        res = asyncio.run(self.registry.execute("ping"))
        self.assertFalse(res.ok)
        self.assertIn("disabled", res.error)


class TestOrchestratorAndApprovals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "agents_test.db"
        self.orch = JarvisOrchestrator(db_path=self.db_path, autonomy_level=AutonomyLevel.EXECUTE_APPROVED)
        self.flaky_calls = 0

        self.orch.tools.register(
            ToolDefinition(name="safe_echo", description="Echo", handler=lambda msg="ok": f"echo:{msg}", risk_level=RiskLevel.LOW)
        )
        self.orch.tools.register(
            ToolDefinition(
                name="demo_write",
                description="Mutating write",
                handler=lambda content="": f"wrote:{content}",
                risk_level=RiskLevel.MEDIUM,
                is_mutating=True,
            )
        )

        def _flaky():
            self.flaky_calls += 1
            if self.flaky_calls == 1:
                raise RuntimeError("transient glitch")
            return "recovered"

        self.orch.tools.register(ToolDefinition(name="flaky_tool", description="Flaky", handler=_flaky))
        self.orch.register_agent(_DemoMutatingAgent(self.orch.tools, self.orch.tasks, self.orch.policy))

    def tearDown(self):
        self.tmp.cleanup()

    def test_intent_classification(self):
        c1 = self.orch.classify_intent("JARVIS, fix this error in my login endpoint")
        self.assertEqual(c1["task_type"], "CODING_TASK")
        c2 = self.orch.classify_intent("analyze today's cybersecurity news and CVE-2026-1234")
        self.assertEqual(c2["task_type"], "CYBERSECURITY_TASK")
        c3 = self.orch.classify_intent("teach me async python with example")
        self.assertEqual(c3["task_type"], "LEARNING_TASK")

    def test_system_status_task_completes_and_persists(self):
        out = asyncio.run(self.orch.submit_task("check system status and diagnostics"))
        self.assertEqual(out["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertTrue(out["result"]["verified"])
        persisted = self.orch.tasks.get_task(out["task"]["task_id"])
        self.assertIsNotNone(persisted)
        self.assertGreaterEqual(len(persisted.execution_log), 2)

    def test_approval_pause_and_resume_flow(self):
        out = asyncio.run(self.orch.submit_task("apply demo change", agent_name="demo_coder"))
        self.assertEqual(out["task"]["status"], TaskStatus.WAITING_APPROVAL.value)
        appr = out["result"]["data"]["approval"]
        self.assertEqual(appr["status"], "PENDING")

        # Approve and continue
        resumed = asyncio.run(self.orch.resolve_approval_and_continue(appr["approval_id"], approved=True, note="Proceed"))
        self.assertTrue(resumed["ok"])
        self.assertEqual(resumed["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertEqual(resumed["task"]["approval_state"], "APPROVED")

    def test_approval_rejection_cancels_task(self):
        out = asyncio.run(self.orch.submit_task("apply demo change", agent_name="demo_coder"))
        appr_id = out["result"]["data"]["approval"]["approval_id"]
        rejected = asyncio.run(self.orch.resolve_approval_and_continue(appr_id, approved=False, note="No"))
        self.assertTrue(rejected["ok"])
        self.assertEqual(rejected["task"]["status"], TaskStatus.CANCELLED.value)

    def test_bounded_steps_truncation(self):
        out = asyncio.run(self.orch.submit_task("overflow plan test", agent_name="demo_coder"))
        self.assertEqual(out["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertEqual(len(out["task"]["plan"]["steps"]), 3)

    def test_step_retry_recovery(self):
        out = asyncio.run(self.orch.submit_task("retry_test", agent_name="demo_coder"))
        self.assertEqual(out["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertEqual(self.flaky_calls, 2)


class TestAgentCoreAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orch = JarvisOrchestrator(db_path=Path(self.tmp.name) / "api_test.db")
        set_orchestrator(self.orch)
        self.srv = DashboardServer(port=19890)
        self.client = TestClient(self.srv.app, raise_server_exceptions=False)

    def tearDown(self):
        set_orchestrator(None)
        self.tmp.cleanup()

    def test_status_autonomy_tools_and_task_endpoints(self):
        r_status = self.client.get("/api/agents/status")
        self.assertEqual(r_status.status_code, 200)
        self.assertEqual(r_status.json()["status"], "READY")

        r_auto = self.client.post("/api/agents/autonomy", json={"level": 2})
        self.assertEqual(r_auto.status_code, 200)
        self.assertEqual(r_auto.json()["level"], 2)

        r_tools = self.client.get("/api/agents/tools")
        self.assertEqual(r_tools.status_code, 200)
        self.assertGreaterEqual(r_tools.json()["count"], 2)

        r_task = self.client.post("/api/agents/tasks", json={"request": "show system status"})
        self.assertEqual(r_task.status_code, 200)
        task_id = r_task.json()["task"]["task_id"]

        r_get = self.client.get(f"/api/agents/tasks/{task_id}")
        self.assertEqual(r_get.status_code, 200)
        self.assertEqual(r_get.json()["task"]["status"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()
