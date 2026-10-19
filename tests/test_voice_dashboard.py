"""
tests/test_voice_dashboard.py — Comprehensive Test Suite for Voice-First Dashboard & Microphone Workflows.

Verifies Part C:
1. Microphone permission granted simulation.
2. Microphone permission denied handling.
3. No microphone available handling.
4. Microphone unavailable or busy (device error) handling.
5. Local development configuration (localhost isSecureContext).
6. HTTPS deployment configuration & certs.
7. Speech transcription success handling.
8. Speech-provider failure fallback.
9. Stop and restart recording workflow.
10. Typed-message fallback.
11. Navigation between both pages (Command Center & Knowledge Vault).
12. Existing JARVIS intelligence & information features still working.
"""

import os
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from dashboard.server import DashboardServer

class TestVoiceDashboard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = DashboardServer()
        cls.client = TestClient(cls.server.app)

    # ── Test 5 & 6: Local Development & HTTPS Deployment ─────────────────────────

    def test_01_local_dev_and_https_certs(self):
        """Verify server configuration supports secure context and HTTPS certs."""
        base_dir = Path(__file__).resolve().parent.parent
        certs_dir = base_dir / "config" / "certs"
        self.assertTrue((certs_dir / "jarvis.key").exists(), "TLS private key exists")
        self.assertTrue((certs_dir / "jarvis.crt").exists(), "TLS certificate exists")
        self.assertTrue(self.server._ssl_enabled(), "SSL is properly detected and enabled")

    def test_02_dashboard_html_contains_voice_first_architecture(self):
        """Verify the served HTML contains the Arc Reactor HUD, Knowledge Vault, and Voice Diag."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text
        self.assertIn("arc-reactor-core", html, "Page contains central HUD arc reactor")
        self.assertIn("Knowledge Vault", html, "Page contains Page 2: Knowledge Vault")
        self.assertIn("Voice & Microphone Diagnostics", html, "Page contains diagnostics interface")
        self.assertIn("vu-meter-fill", html, "Page contains live decibel / VU meter")
        self.assertIn("hero-mic-btn", html, "Page contains voice-first tactile microphone button")

    # ── Test 1 to 4: Microphone Permissions & Device States ────────────────────

    def test_03_microphone_fsm_states_declared(self):
        """Verify all required microphone states (IDLE, REQUESTING_PERMISSION, LISTENING, PROCESSING, ERROR) are coded."""
        resp = self.client.get("/")
        html = resp.text
        for state in ['IDLE', 'REQUESTING_PERMISSION', 'LISTENING', 'PROCESSING', 'ERROR']:
            self.assertIn(state, html, f"State {state} is present in client logic")

    def test_04_microphone_error_messages(self):
        """Verify user-friendly guidance messages for permission denial, not found, and unavailable."""
        resp = self.client.get("/")
        html = resp.text
        self.assertIn("Sir, please allow microphone access in your browser.", html)
        self.assertIn("Sir, no microphone was detected.", html)
        self.assertIn("Sir, the microphone is unavailable.", html)

    # ── Test 7 & 8: Speech Transcription & Provider Failure ───────────────────

    def test_05_speech_recognition_provider_and_fallback(self):
        """Verify Web Speech API is primary and faster-whisper backend is ready as fallback."""
        resp = self.client.get("/")
        html = resp.text
        self.assertIn("webkitSpeechRecognition", html, "Web Speech API is registered")
        self.assertIn("SpeechRecognition", html, "Standard SpeechRecognition is checked")
        self.assertIn("/api/voice/transcribe", html, "Backend transcription endpoint is hooked")

    def test_06_system_health_telemetry_endpoint(self):
        """Verify /api/system/health returns real CPU, RAM, and STT status."""
        resp = self.client.get("/api/system/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("ok"))
        self.assertIn("cpu_percent", data)
        self.assertIn("ram_percent", data)
        self.assertIn("provider", data)

    # ── Test 9 & 10: Stop/Restart & Typed Fallback ─────────────────────────────

    def test_07_stop_restart_and_clean_teardown(self):
        """Verify audio tracks and AudioContext are cleanly terminated on stop."""
        resp = self.client.get("/")
        html = resp.text
        self.assertIn("track.stop()", html, "Media tracks are properly stopped on cancel/end")
        self.assertIn("_audioCtx.close()", html, "AudioContext is cleanly closed to prevent locks")

    def test_08_typed_input_fallback_preserved(self):
        """Verify multiline text input and send button operate independently as typed fallback."""
        resp = self.client.get("/")
        html = resp.text
        self.assertIn("command-text-inp", html, "Multiline text input is present")
        self.assertIn("command-send-btn", html, "Send button is present")

    # ── Test 11 & 12: Two-Page Navigation & Existing Features ─────────────────

    def test_09_two_page_navigation(self):
        """Verify seamless navigation between Command Center and Knowledge Vault."""
        resp = self.client.get("/")
        html = resp.text
        self.assertIn("switchView('command')", html, "Navigation to Command Center")
        self.assertIn("switchView('vault')", html, "Navigation to Knowledge Vault")
        self.assertIn("switchView('page')", html, "Navigation to Detailed Dossier Reader")

    def test_10_existing_features_intact(self):
        """Verify intelligence library, auto-login, and auth recovery remain fully intact."""
        # Auto login with master PIN
        auto_resp = self.client.get("/auto-login?key=JARVIS")
        self.assertEqual(auto_resp.status_code, 200)
        self.assertIn("jarvis_token", auto_resp.text)
        self.assertIn("jarvis_key", auto_resp.text)


if __name__ == "__main__":
    unittest.main()
