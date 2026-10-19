"""
Unit tests for JARVIS DevSecOps & Cybersecurity Plugins:
- plugins._sec_engine (SSRF, redaction, risk scoring, OUI lookup, wireless IDS)
- plugins.vuln_scanner
- plugins.snid_wireless_guard
- plugins.devsecops_auditor
- plugins.defensive_audit
"""

import unittest
from pathlib import Path

from plugins._sec_engine import (
    SSRFProtectionError,
    WirelessIDSAnalyzer,
    compute_risk_score,
    lookup_mac_vendor,
    map_to_owasp,
    normalize_mac,
    redact_text,
    validate_target_safety,
)
import plugins.defensive_audit as defa
import plugins.devsecops_auditor as da
import plugins.snid_wireless_guard as swg
import plugins.vuln_scanner as vs


class TestSecEngine(unittest.TestCase):
    def test_ssrf_blocks_cloud_metadata(self):
        with self.assertRaises(SSRFProtectionError):
            validate_target_safety("http://169.254.169.254/latest/meta-data")

    def test_ssrf_private_network_requires_authorization(self):
        with self.assertRaises(SSRFProtectionError):
            validate_target_safety("192.168.1.1", allow_local_lab=False)

        sanitized, target_type = validate_target_safety("192.168.1.1", allow_local_lab=True)
        self.assertEqual(sanitized, "192.168.1.1")
        self.assertEqual(target_type, "private_ip")

    def test_redaction_masks_bearer_and_api_keys(self):
        raw = "Authorization: Bearer secret_token_xyz123 and api_key=abc1234567890abcdef"
        redacted = redact_text(raw)
        self.assertNotIn("secret_token_xyz123", redacted)
        self.assertIn("[REDACTED_BEARER_TOKEN]", redacted)

    def test_mac_vendor_lookup(self):
        # Espressif MAC
        vendor = lookup_mac_vendor("24:0A:C4:00:11:22")
        self.assertIn("Espressif", vendor)

        # Apple MAC
        vendor_apple = lookup_mac_vendor("48-E7-29-AA-BB-CC")
        self.assertIn("Apple", vendor_apple)

    def test_risk_scoring_engine(self):
        findings = [
            {"severity": "critical", "verification": "confirmed"},
            {"severity": "high", "verification": "potential"},
        ]
        result = compute_risk_score(findings, incomplete_scanners=1)
        # Base: 100 - 25.0 (confirmed crit) - 8.0 (potential high) - 4.0 (incomplete) = 63.0
        self.assertEqual(result["score"], 63.0)
        self.assertEqual(result["risk_level"], "ELEVATED RISK")

    def test_wireless_ids_deauth_flood(self):
        eval_result = WirelessIDSAnalyzer.evaluate_telemetry(
            deauth_count_last_minute=25,
            observed_aps=[],
        )
        self.assertEqual(eval_result["status"], "THREAT_DETECTED")
        self.assertTrue(any(a["type"] == "DEAUTH_FLOOD_DETECTED" for a in eval_result["alerts"]))

    def test_wireless_ids_evil_twin(self):
        aps = [
            {"ssid": "TargetCorp", "bssid": "AC:8B:A3:00:00:01", "channel": 1},  # Cisco
            {"ssid": "TargetCorp", "bssid": "24:0A:C4:00:00:02", "channel": 6},  # Espressif
        ]
        eval_result = WirelessIDSAnalyzer.evaluate_telemetry(
            deauth_count_last_minute=0,
            observed_aps=aps,
            known_authorized_ssids=["TargetCorp"],
        )
        self.assertTrue(any(a["type"] == "EVIL_TWIN_SUSPECTED" for a in eval_result["alerts"]))


class TestSecurityPlugins(unittest.TestCase):
    def test_plugin_declarations(self):
        for mod, expected_name in [
            (vs, "vuln_scanner"),
            (swg, "snid_wireless_guard"),
            (da, "devsecops_auditor"),
            (defa, "defensive_audit"),
        ]:
            self.assertIn("name", mod.PLUGIN)
            self.assertEqual(mod.PLUGIN["name"], expected_name)
            self.assertIn("description", mod.PLUGIN)
            self.assertIn("parameters", mod.PLUGIN)
            self.assertTrue(callable(mod.run))

    def test_defensive_audit_secret_audit(self):
        res = defa.run({"action": "secret_audit", "file_path": "."})
        self.assertIsInstance(res, str)
        self.assertIn("Sir", res)

    def test_devsecops_auditor_gate(self):
        res = da.run({"action": "evaluate_gate", "target": "test_system", "min_score": 90.0})
        self.assertIsInstance(res, str)

    def test_snid_device_discovery(self):
        res = swg.run({"action": "discover_devices"})
        self.assertIsInstance(res, str)
        self.assertIn("Sir", res)


if __name__ == "__main__":
    unittest.main()
