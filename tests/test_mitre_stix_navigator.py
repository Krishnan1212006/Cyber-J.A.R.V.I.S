"""
Unit tests for MITRE ATT&CK STIX, Navigator, ADM, and Workbench integration:
- intel.mitre_attack_stix (STIX 2.1 datasets)
- intel.mitre_navigator (ATT&CK Navigator v4.5 layers)
- intel.attack_data_model (ADM telemetry mappings)
- intel.mitre_workbench (TAXII 2.1 protocol endpoints)
- plugins.mitre_expert
"""

import json
import unittest
from pathlib import Path

from intel.attack_data_model import AttackDataModelEngine
from intel.mitre_attack_stix import MitreStixEngine
from intel.mitre_navigator import AttackNavigatorEngine
from intel.mitre_workbench import AttackWorkbenchEngine, TaxiiServerEngine
import plugins.mitre_expert as me


class TestMitreAttackStix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stix = MitreStixEngine.get_instance()

    def test_stix_loaded_dataset(self):
        stats = self.stix.get_statistics()
        self.assertGreater(stats["techniques_count"], 500)
        self.assertGreater(stats["groups_count"], 100)
        self.assertGreater(stats["relationships_count"], 10000)

    def test_query_technique(self):
        tech = self.stix.get_technique("T1059.001")
        self.assertIsNotNone(tech)
        self.assertEqual(tech["id"], "T1059.001")
        self.assertEqual(tech["name"], "PowerShell")
        self.assertIn("Windows", tech["platforms"])
        self.assertGreater(len(tech["mitigations"]), 0)

    def test_query_threat_group(self):
        apt = self.stix.get_group("APT29")
        self.assertIsNotNone(apt)
        self.assertEqual(apt["name"], "APT29")
        self.assertIn("IRON HEMLOCK", apt["aliases"])
        self.assertGreater(apt["techniques_count"], 20)


class TestAttackNavigator(unittest.TestCase):
    def test_layer_generation_schema(self):
        layer_dict = AttackNavigatorEngine.create_layer_dict(
            name="Test Layer",
            description="Unit test layer",
            technique_scores={"T1059": 80.0, "T1190": 100.0},
        )
        self.assertEqual(layer_dict["name"], "Test Layer")
        self.assertEqual(layer_dict["versions"]["navigator"], "4.5")
        self.assertEqual(len(layer_dict["techniques"]), 2)
        self.assertEqual(layer_dict["techniques"][1]["techniqueID"], "T1190")

    def test_adversary_layer_export(self):
        layer, path = AttackNavigatorEngine.generate_adversary_layer("APT29")
        self.assertTrue(path.exists())
        self.assertIn("APT29", layer["name"])


class TestAttackDataModel(unittest.TestCase):
    def test_detection_blueprint(self):
        bp = AttackDataModelEngine.get_detection_blueprint("T1059.001")
        self.assertEqual(bp["technique_id"], "T1059.001")
        self.assertGreater(len(bp["telemetry_prerequisites"]), 0)
        # Check Sysmon or Process Creation telemetry present
        telemetry_names = [t["data_source"] for t in bp["telemetry_prerequisites"]]
        self.assertTrue(any("Process" in name or "Command" in name for name in telemetry_names))


class TestTaxiiWorkbench(unittest.TestCase):
    def test_taxii_discovery_and_collections(self):
        taxii = TaxiiServerEngine()
        disc = taxii.get_server_discovery()
        self.assertIn("default", disc)
        colls = taxii.get_collections()
        self.assertGreater(len(colls["collections"]), 0)

    def test_taxii_query_objects(self):
        taxii = TaxiiServerEngine()
        objs = taxii.query_objects(collection_id="enterprise-attack", object_type="attack-pattern", limit=5)
        self.assertEqual(objs["count"], 5)
        self.assertEqual(len(objs["objects"]), 5)


class TestMitreExpertPlugin(unittest.TestCase):
    def test_plugin_metadata(self):
        self.assertEqual(me.PLUGIN["name"], "mitre_expert")
        self.assertTrue(callable(me.run))

    def test_plugin_technique_action(self):
        res = me.run({"action": "technique", "query": "T1190"})
        self.assertIsInstance(res, str)
        self.assertIn("Exploit Public-Facing Application", res)

    def test_plugin_threat_group_action(self):
        res = me.run({"action": "threat_group", "query": "Lazarus Group"})
        self.assertIsInstance(res, str)
        self.assertIn("Lazarus Group", res)

    def test_plugin_detection_action(self):
        res = me.run({"action": "detect", "query": "T1059.001"})
        self.assertIsInstance(res, str)
        self.assertIn("telemetry", res.lower())


if __name__ == "__main__":
    unittest.main()
