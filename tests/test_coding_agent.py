"""
tests/test_coding_agent.py — Phase 2 Verification Suite for JARVIS Workspace CodingAgent.

Tests all capabilities on an isolated temporary sample Python project:
1. Workspace inspection (file tree, languages, frameworks, test detection)
2. Safe file read, search, path-traversal blocking, and secret-file blocking
3. End-to-end CodingAgent workflow: inspect -> checkpoint -> approval gate -> edit -> AST/secret review -> pytest
4. Failure detection: broken syntax or failing test fails verification (never claims false success)
5. Secret leak detection during static code review
6. Checkpoint & rollback restoring exact original file state
7. FastAPI /api/agents/workspace/* endpoints
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from agents import (
    AutonomyLevel,
    JarvisOrchestrator,
    TaskStatus,
    set_orchestrator,
)
from agents.workspace_tools import (
    list_checkpoints,
    workspace_code_review,
    workspace_inspect,
    workspace_read_file,
    workspace_rollback,
    workspace_search,
)
from dashboard.server import DashboardServer


def _create_sample_project(root: Path) -> None:
    """Create a small isolated Python sample project with an intentional bug."""
    (root / "requirements.txt").write_text("pytest\nfastapi\n", encoding="utf-8")
    (root / ".env").write_text("SECRET_TOKEN=super_secret_value\n", encoding="utf-8")
    (root / "calculator.py").write_text(
        "def add(a: int, b: int) -> int:\n"
        "    return a - b  # intentional bug\n",
        encoding="utf-8",
    )
    (root / "test_calculator.py").write_text(
        "from calculator import add\n\n"
        "def test_add():\n"
        "    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )


class TestWorkspaceToolsIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        _create_sample_project(self.ws)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inspect_detects_stack_and_tests(self):
        info = workspace_inspect(str(self.ws))
        self.assertIn("Python", info["languages"])
        self.assertIn("pytest", info["frameworks"])
        self.assertIn("fastapi", info["frameworks"])
        self.assertIn("test_calculator.py", info["test_files"])

    def test_read_blocks_secret_files_and_traversal(self):
        with self.assertRaises(PermissionError):
            workspace_read_file(".env", str(self.ws))
        with self.assertRaises(PermissionError):
            workspace_read_file("../outside.txt", str(self.ws))

        ok = workspace_read_file("calculator.py", str(self.ws))
        self.assertIn("def add", ok["content"])

    def test_search_finds_bug_and_skips_env(self):
        res = workspace_search("intentional bug", str(self.ws))
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["matches"][0]["file"], "calculator.py")

        secret_res = workspace_search("super_secret_value", str(self.ws))
        self.assertEqual(secret_res["count"], 0)


class TestCodingAgentEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "sample_proj"
        self.ws.mkdir()
        _create_sample_project(self.ws)
        self.db_path = Path(self.tmp.name) / "coding_test.db"
        self.orch = JarvisOrchestrator(db_path=self.db_path, autonomy_level=AutonomyLevel.EXECUTE_APPROVED)
        self.orch.set_workspace(self.ws)

    def tearDown(self):
        self.tmp.cleanup()

    def test_fix_bug_with_approval_and_rollback(self):
        # Submit bugfix task to CodingAgent in Level 3 (requires approval before mutating)
        out = asyncio.run(
            self.orch.submit_task(
                user_request="Fix the bug in calculator.py add function",
                agent_name="coding",
                context={
                    "operations": [
                        {
                            "type": "edit",
                            "path": "calculator.py",
                            "target": "return a - b  # intentional bug",
                            "replacement": "return a + b",
                            "description": "Fix subtraction bug to addition",
                        }
                    ],
                    "run_tests": True,
                },
            )
        )
        self.assertEqual(out["task"]["status"], TaskStatus.WAITING_APPROVAL.value)
        appr_id = out["result"]["data"]["approval"]["approval_id"]

        # Approve and resume — CodingAgent applies edit, runs review, runs pytest
        resumed = asyncio.run(self.orch.resolve_approval_and_continue(appr_id, approved=True))
        self.assertTrue(resumed["ok"])
        self.assertEqual(resumed["task"]["status"], TaskStatus.COMPLETED.value)
        self.assertTrue(resumed["result"]["verified"])
        self.assertIn("calculator.py", resumed["task"]["files_affected"])

        # Verify file was actually fixed
        self.assertIn("return a + b", (self.ws / "calculator.py").read_text(encoding="utf-8"))

        # Verify rollback restores original buggy file cleanly
        cps = list_checkpoints(str(self.ws))
        self.assertGreaterEqual(len(cps), 1)
        rb = workspace_rollback(str(self.ws), cps[0]["checkpoint_id"])
        self.assertIn("calculator.py", rb["restored_files"])
        self.assertIn("return a - b", (self.ws / "calculator.py").read_text(encoding="utf-8"))

    def test_failing_test_fails_verification(self):
        # Level 4 so edit runs without manual approval, but leaves bug unfixed -> pytest must fail
        self.orch.policy.set_level(AutonomyLevel.CONTROLLED_AUTONOMY)
        out = asyncio.run(
            self.orch.submit_task(
                user_request="Run tests on buggy calculator",
                agent_name="coding",
                context={
                    "operations": [
                        {
                            "type": "edit",
                            "path": "calculator.py",
                            "target": "return a - b  # intentional bug",
                            "replacement": "return a * b  # still wrong",
                        }
                    ],
                    "run_tests": True,
                },
            )
        )
        self.assertEqual(out["task"]["status"], TaskStatus.FAILED.value)
        self.assertFalse(out["result"]["verified"])

    def test_code_review_catches_syntax_and_secrets(self):
        (self.ws / "bad.py").write_text("KEY = 'AIzaSyA12345678901234567890123456789012345'\ndef broken(:\n", encoding="utf-8")
        rev = workspace_code_review(str(self.ws), files=["bad.py"])
        self.assertFalse(rev["passed"])
        self.assertGreaterEqual(len(rev["findings"]), 2)


class TestWorkspaceAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "api_proj"
        self.ws.mkdir()
        _create_sample_project(self.ws)
        self.orch = JarvisOrchestrator(db_path=Path(self.tmp.name) / "ws_api.db")
        set_orchestrator(self.orch)
        self.srv = DashboardServer(port=19895)
        self.client = TestClient(self.srv.app, raise_server_exceptions=False)

    def tearDown(self):
        set_orchestrator(None)
        self.tmp.cleanup()

    def test_workspace_endpoints(self):
        r_set = self.client.post("/api/agents/workspace", json={"path": str(self.ws)})
        self.assertEqual(r_set.status_code, 200)

        r_ins = self.client.get("/api/agents/workspace/inspect")
        self.assertEqual(r_ins.status_code, 200)
        self.assertIn("Python", r_ins.json()["languages"])

        r_file = self.client.get("/api/agents/workspace/file", params={"path": "calculator.py"})
        self.assertEqual(r_file.status_code, 200)
        self.assertIn("def add", r_file.json()["content"])

        r_env = self.client.get("/api/agents/workspace/file", params={"path": ".env"})
        self.assertEqual(r_env.status_code, 403)


if __name__ == "__main__":
    unittest.main()
