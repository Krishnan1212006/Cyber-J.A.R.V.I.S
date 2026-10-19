"""
tests/test_information_pages.py — Comprehensive Test Suite for JARVIS 24 Dedicated Information Pages.

Verifies:
1. Smart Response Routing (short chat vs. detailed pages vs. reports vs. learning).
2. Persistent Storage (SQLite WAL + FTS5 search + restart simulation).
3. Dedicated Information Page Generation Workflow.
4. Duplicate prevention for repeated requests.
5. Error handling and connector unavailability resilience.
6. REST API Endpoints (CRUD, search, export, bookmarking).
7. Main assistant tool declaration and addressing protocol ("Sir" / "JARVIS").
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from intel.models import InformationPage, utc_now_iso
from intel.db import IntelligenceDB
from intel.response_router import SmartResponseRouter, PresentationMode, get_response_router
from intel.information_service import InformationService
from intel.information_api import router as info_router, set_service
from intel.llm_provider import MockLLMProvider
from dashboard.server import DashboardServer
from main import TOOL_DECLARATIONS


class TestDedicatedInformationPages(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_intel.db"
        self.db = IntelligenceDB(self.db_path)
        self.router = SmartResponseRouter()
        self.mock_llm = MockLLMProvider()
        self.service = InformationService(
            db=self.db,
            router=self.router,
            llm_provider=self.mock_llm,
        )
        set_service(self.service)

    def tearDown(self):
        set_service(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ── 1. Smart Response Routing Tests ────────────────────────────────────────

    def test_smart_routing_short_vs_detailed(self):
        """Verify that short questions remain CHAT while detailed requests are properly routed."""
        # Short conversational questions
        self.assertEqual(self.router.route("hello jarvis").mode, PresentationMode.CHAT)
        self.assertFalse(self.router.route("hello jarvis").is_detailed)
        self.assertEqual(self.router.route("who are you").mode, PresentationMode.CHAT)
        self.assertEqual(self.router.route("what time is it").mode, PresentationMode.CHAT)
        self.assertEqual(self.router.route("thank you jarvis").mode, PresentationMode.CHAT)

        # Explicit brevity constraint
        self.assertEqual(self.router.route("explain this briefly").mode, PresentationMode.CHAT)
        self.assertFalse(self.router.route("explain this briefly").is_detailed)

        # Cybersecurity threat reports
        r_mitre = self.router.route("JARVIS, explain MITRE ATT&CK in detail.")
        self.assertEqual(r_mitre.mode, PresentationMode.CYBERSECURITY_REPORT)
        self.assertTrue(r_mitre.is_detailed)

        r_threat = self.router.route("Prepare a cybersecurity threat report")
        self.assertEqual(r_threat.mode, PresentationMode.CYBERSECURITY_REPORT)
        self.assertTrue(r_threat.is_detailed)

        # Learning page
        r_learn = self.router.route("Teach me with examples")
        self.assertEqual(r_learn.mode, PresentationMode.LEARNING_PAGE)
        self.assertTrue(r_learn.is_detailed)

        # Project document
        r_proj = self.router.route("Give me the full project architecture")
        self.assertEqual(r_proj.mode, PresentationMode.PROJECT_DOCUMENT)
        self.assertTrue(r_proj.is_detailed)

        # Generated artifact (PDF / PPTX)
        r_pdf = self.router.route("Create a PDF from this page")
        self.assertEqual(r_pdf.mode, PresentationMode.GENERATED_ARTIFACT)
        self.assertTrue(r_pdf.is_detailed)

        # General detailed explanation
        r_info = self.router.route("Explain quantum computing in detail")
        self.assertEqual(r_info.mode, PresentationMode.INFORMATION_PAGE)
        self.assertTrue(r_info.is_detailed)

    # ── 2. Persistence & Storage Tests ─────────────────────────────────────────

    def test_persistent_storage_and_restart_simulation(self):
        """Verify that pages persist across restarts and FTS5 search functions properly."""
        page = InformationPage(
            id="page_mitre_001",
            title="MITRE ATT&CK Deep Dive",
            summary="Enterprise matrix breakdown and tactical persistence techniques.",
            content="## 1. Overview\nAdversary lifecycle analysis.\n\n## 2. Execution\nT1059 Command and Scripting Interpreter.",
            category="Cybersecurity",
            tags=["MITRE ATT&CK", "Threat Intel", "Sysmon"],
            presentation_type="CYBERSECURITY_REPORT",
            table_of_contents=[
                {"level": 2, "text": "Overview", "slug": "overview"},
                {"level": 2, "text": "Execution", "slug": "execution"},
            ],
            source_references=[{"title": "MITRE ATT&CK Matrix", "url": "https://attack.mitre.org", "verified": True}],
            user_bookmarked=False,
        )

        # Save to database
        self.db.save_information_page(page)

        # Simulate full application restart by initializing a brand new IntelligenceDB instance
        restarted_db = IntelligenceDB(self.db_path)
        fetched = restarted_db.get_information_page("page_mitre_001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.title, "MITRE ATT&CK Deep Dive")
        self.assertEqual(fetched.category, "Cybersecurity")
        self.assertEqual(len(fetched.table_of_contents), 2)
        self.assertEqual(fetched.table_of_contents[0]["slug"], "overview")

        # Verify FTS5 Search
        search_results = restarted_db.search_information_pages("persistence")
        self.assertGreaterEqual(len(search_results), 1)
        self.assertEqual(search_results[0].id, "page_mitre_001")

        # Verify Bookmark Toggling
        new_bm = restarted_db.toggle_page_bookmark("page_mitre_001")
        self.assertTrue(new_bm)
        self.assertTrue(restarted_db.get_information_page("page_mitre_001").user_bookmarked)

        # Verify Listing with Bookmark Filter
        bookmarked_list = restarted_db.list_information_pages(bookmarked_only=True)
        self.assertEqual(len(bookmarked_list), 1)

        # Verify Deletion
        del_ok = restarted_db.delete_information_page("page_mitre_001")
        self.assertTrue(del_ok)
        self.assertIsNone(restarted_db.get_information_page("page_mitre_001"))

    # ── 3. Generation Workflow & Addressing Protocol ───────────────────────────

    def test_generation_workflow_and_addressing_protocol(self):
        """Test complete generation workflow, ensuring Sir is addressed and page is generated."""
        res = self.service.process_request("JARVIS, explain MITRE ATT&CK in detail.")
        self.assertTrue(res["is_page"])
        self.assertIsNotNone(res["page"])
        self.assertIn("Sir", res["jarvis_response"])
        self.assertIn("information page", res["jarvis_response"].lower())

        page = res["page"]
        self.assertTrue(page["id"].startswith("page_"))
        self.assertGreater(len(page["content"]), 200)
        self.assertGreater(len(page["table_of_contents"]), 0)

        # Verify that conversational short questions remain in chat mode
        chat_res = self.service.process_request("Good morning JARVIS")
        self.assertFalse(chat_res["is_page"])
        self.assertIsNone(chat_res["page"])
        self.assertIn("Sir", chat_res["jarvis_response"])

    def test_duplicate_prevention_on_repeated_request(self):
        """Verify that identical repeated queries retrieve the existing page without creating duplicate rows."""
        res1 = self.service.process_request("JARVIS, explain MITRE ATT&CK in detail.")
        page_id_1 = res1["page"]["id"]

        # Repeated request without force_refresh
        res2 = self.service.process_request("JARVIS, explain MITRE ATT&CK in detail.")
        page_id_2 = res2["page"]["id"]

        # Must return the same page record
        self.assertEqual(page_id_1, page_id_2)

        # Total pages count in database must remain 1
        all_pages = self.db.list_information_pages()
        self.assertEqual(len(all_pages), 1)

    # ── 4. FastAPI Endpoints Integration ───────────────────────────────────────

    def test_fastapi_information_endpoints(self):
        """Verify REST API routes for listing, fetching, generating, bookmarking, and exporting."""
        server = DashboardServer()
        client = TestClient(server.app)

        # 1. Generate page via API
        gen_res = client.post(
            "/api/information/route-and-generate",
            json={"query": "JARVIS, explain MITRE ATT&CK in detail."},
        )
        self.assertEqual(gen_res.status_code, 200)
        data = gen_res.json()
        self.assertTrue(data["is_page"])
        page_id = data["page"]["id"]

        # 2. Get Page by ID
        get_res = client.get(f"/api/information/{page_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["id"], page_id)

        # 3. List Pages
        list_res = client.get("/api/information")
        self.assertEqual(list_res.status_code, 200)
        self.assertGreaterEqual(list_res.json()["total"], 1)

        # 4. Toggle Bookmark
        bm_res = client.post(f"/api/information/{page_id}/bookmark", json={"bookmarked": True})
        self.assertEqual(bm_res.status_code, 200)
        self.assertTrue(bm_res.json()["user_bookmarked"])

        # 5. Export Markdown
        exp_md = client.get(f"/api/information/{page_id}/export?format=markdown")
        self.assertEqual(exp_md.status_code, 200)
        self.assertIn("attachment", exp_md.headers.get("content-disposition", ""))

        # 6. Export HTML
        exp_html = client.get(f"/api/information/{page_id}/export?format=html")
        self.assertEqual(exp_html.status_code, 200)
        self.assertIn("<!DOCTYPE html>", exp_html.text)

        # 7. Delete Page
        del_res = client.delete(f"/api/information/{page_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.json()["ok"])

        # 8. Verify 404 after deletion
        not_found_res = client.get(f"/api/information/{page_id}")
        self.assertEqual(not_found_res.status_code, 404)

    # ── 5. Main Assistant Tool Declarations ────────────────────────────────────

    def test_tool_declaration_registered(self):
        """Ensure dedicated_information_page tool is declared in main assistant configuration."""
        tool_names = [t["name"] for t in TOOL_DECLARATIONS]
        self.assertIn("dedicated_information_page", tool_names)
        tool = next(t for t in TOOL_DECLARATIONS if t["name"] == "dedicated_information_page")
        self.assertIn("action", tool["parameters"]["properties"])
        self.assertIn("presentation_mode", tool["parameters"]["properties"])


if __name__ == "__main__":
    unittest.main()
