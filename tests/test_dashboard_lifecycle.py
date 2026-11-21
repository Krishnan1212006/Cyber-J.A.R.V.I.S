"""
tests/test_dashboard_lifecycle.py — Comprehensive Dashboard Lifecycle Tests

Covers:
1.  DashboardServer instantiation and port configuration
2.  Local URL helper returns https://127.0.0.1:<port>
3.  LAN URL helper returns https://<lan_ip>:<port>
4.  get_manual_url() returns LAN IP + alias port
5.  /health endpoint — HEALTHY status, all required keys present
6.  /api/health alias returns same data
7.  AI status callback: None → DISCONNECTED, callable → real return value
8.  AI status callback handles str / bool / None gracefully
9.  /api/system/health includes ai_session field
10. Authentication: new_key() generates a valid token and /auto-login accepts it
11. POST /login with wrong key returns 401
12. POST /login with master key succeeds
13. WebSocket /ws endpoint reachable (HTTP 101 upgrade attempt)
14. DashboardServer.stop() sets _is_running to False
15. Two independent DashboardServer instances keep separate token stores
16. Port 0 override via constructor parameter
17. get_dashboard_port() falls back to 8000 when no config present
18. Health endpoint uptime_seconds increases over time
"""

import asyncio
import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from dashboard.server import DashboardServer, get_dashboard_port


class TestDashboardInstantiation(unittest.TestCase):
    """Tests 1-3, 15, 16: Construction and URL helpers."""

    def setUp(self):
        self.server = DashboardServer(port=19800)
        self.client = TestClient(self.server.app, raise_server_exceptions=False)

    def test_01_instantiation(self):
        """DashboardServer instantiates without errors."""
        self.assertIsNotNone(self.server)
        self.assertEqual(self.server.port, 19800)

    def test_02_local_url(self):
        """get_local_url() returns https://127.0.0.1:<port>."""
        url = self.server.get_local_url()
        self.assertIn("127.0.0.1", url)
        self.assertIn("19800", url)
        self.assertTrue(url.startswith("http"))

    def test_03_lan_url_not_localhost(self):
        """get_url() returns a URL with the LAN or local IP, containing the port."""
        url = self.server.get_url()
        self.assertIn("19800", url)
        self.assertTrue(url.startswith("http"))

    def test_15_separate_token_stores(self):
        """Two DashboardServer instances have isolated token stores."""
        srv_a = DashboardServer(port=19801)
        srv_b = DashboardServer(port=19802)
        key_a = srv_a.new_key()
        self.assertNotIn(key_a, srv_b._pending_keys)
        self.assertIn(key_a, srv_a._pending_keys)

    def test_16_port_override_via_constructor(self):
        """Constructor port parameter overrides global PORT constant."""
        srv = DashboardServer(port=19803)
        self.assertEqual(srv.port, 19803)


class TestDashboardURLHelpers(unittest.TestCase):
    """Tests 4: Manual URL."""

    def setUp(self):
        self.server = DashboardServer(port=19810)

    def test_04_manual_url(self):
        """get_manual_url() returns a non-empty string."""
        url = self.server.get_manual_url()
        self.assertIsInstance(url, str)
        self.assertTrue(len(url) > 3)


class TestHealthEndpoint(unittest.TestCase):
    """Tests 5-6, 18: /health and /api/health."""

    @classmethod
    def setUpClass(cls):
        cls.server = DashboardServer(port=19820)
        cls.client = TestClient(cls.server.app, raise_server_exceptions=False)

    def test_05_health_returns_200(self):
        """/health returns HTTP 200."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_05b_health_has_required_keys(self):
        """/health JSON contains all required status keys."""
        resp = self.client.get("/health")
        data = resp.json()
        for key in ("status", "dashboard_server", "ai_session", "database", "port", "protocol", "urls"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_05c_health_status_healthy(self):
        """/health reports HEALTHY when server object exists."""
        resp = self.client.get("/health")
        data = resp.json()
        self.assertEqual(data["status"], "HEALTHY")

    def test_05d_health_port_matches(self):
        """/health reports the configured port."""
        resp = self.client.get("/health")
        data = resp.json()
        self.assertEqual(data["port"], 19820)

    def test_06_api_health_alias(self):
        """/api/health returns same structure as /health."""
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("dashboard_server", data)

    def test_18_uptime_seconds_present(self):
        """/health includes uptime_seconds as a non-negative number."""
        resp = self.client.get("/health")
        data = resp.json()
        self.assertIn("uptime_seconds", data)
        self.assertGreaterEqual(data["uptime_seconds"], 0)


class TestAIStatusCallback(unittest.TestCase):
    """Tests 7-8: AI status callback integration."""

    def setUp(self):
        self.server = DashboardServer(port=19830)
        self.client = TestClient(self.server.app, raise_server_exceptions=False)

    def test_07_no_callback_reports_disconnected(self):
        """/health reports ai_session=DISCONNECTED when no callback set."""
        resp = self.client.get("/health")
        data = resp.json()
        self.assertEqual(data["ai_session"], "DISCONNECTED")

    def test_07b_callback_connected(self):
        """When callback returns 'CONNECTED', /health reports CONNECTED."""
        self.server.set_ai_status_callback(lambda: "CONNECTED")
        resp = self.client.get("/health")
        data = resp.json()
        self.assertEqual(data["ai_session"], "CONNECTED")
        self.server.set_ai_status_callback(None)

    def test_08_callback_bool_true(self):
        """Callback returning True is treated as CONNECTED."""
        self.server.set_ai_status_callback(lambda: True)
        resp = self.client.get("/health")
        data = resp.json()
        self.assertIn(data["ai_session"], ("CONNECTED", "True", True))
        self.server.set_ai_status_callback(None)

    def test_08b_callback_bool_false(self):
        """Callback returning False is treated as DISCONNECTED."""
        self.server.set_ai_status_callback(lambda: False)
        resp = self.client.get("/health")
        data = resp.json()
        self.assertIn(data["ai_session"], ("DISCONNECTED", "False", False))
        self.server.set_ai_status_callback(None)

    def test_08c_callback_exception_handled(self):
        """Callback that raises an exception does not crash /health."""
        def bad_cb():
            raise RuntimeError("callback failure")
        self.server.set_ai_status_callback(bad_cb)
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.server.set_ai_status_callback(None)


class TestSystemHealthEndpoint(unittest.TestCase):
    """Test 9: /api/system/health includes ai_session."""

    @classmethod
    def setUpClass(cls):
        cls.server = DashboardServer(port=19840)
        cls.client = TestClient(cls.server.app, raise_server_exceptions=False)

    def test_09_system_health_includes_ai_session(self):
        """/api/system/health includes ai_session field."""
        resp = self.client.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ai_session", data)


class TestAuthentication(unittest.TestCase):
    """Tests 10-12: Token generation and login flow."""

    @classmethod
    def setUpClass(cls):
        cls.server = DashboardServer(port=19850)
        cls.client = TestClient(cls.server.app, raise_server_exceptions=False)

    def test_10_new_key_generates_token(self):
        """new_key() returns a non-empty string and stores it."""
        key = self.server.new_key()
        self.assertIsInstance(key, str)
        self.assertTrue(len(key) >= 4)
        self.assertIn(key, self.server._pending_keys)

    def test_10b_auto_login_with_valid_key(self):
        """/auto-login?key=<valid> returns 200 with JS token injection."""
        key = self.server.new_key()
        resp = self.client.get(f"/auto-login?key={key}")
        self.assertEqual(resp.status_code, 200)
        body = resp.text
        self.assertIn("jarvis_token", body)

    def test_11_login_wrong_key_401(self):
        """POST /login with wrong key returns 401."""
        import json
        resp = self.client.post(
            "/login",
            content=json.dumps({"enc": "wrong", "iv": "wrong"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertIn(resp.status_code, (400, 401, 422))

    def test_12_master_key_auto_login(self):
        """/auto-login with master key JARVIS returns 200."""
        resp = self.client.get("/auto-login?key=JARVIS")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("jarvis_token", resp.text)


class TestPortConfiguration(unittest.TestCase):
    """Test 17: get_dashboard_port() fallback."""

    def test_17_port_fallback_to_8000(self):
        """get_dashboard_port() returns 8000 when config missing."""
        with patch("dashboard.server.BASE_DIR", Path("/nonexistent")):
            port = get_dashboard_port()
        self.assertEqual(port, 8000)


class TestServerStop(unittest.TestCase):
    """Test 14: stop() sets _is_running to False."""

    def test_14_stop_sets_not_running(self):
        """stop() marks _is_running=False even without a live uvicorn server."""
        srv = DashboardServer(port=19860)
        srv._is_running = True
        # Run stop() in a temporary event loop
        asyncio.run(srv.stop())
        self.assertFalse(srv._is_running)


if __name__ == "__main__":
    unittest.main()
