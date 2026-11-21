"""
Unit and integration tests for Multi-Source Cyber News Connectors (Phase 1).
Tests HacklidoConnector, BleepingComputerConnector, TheHackerNewsConnector,
CybersecurityNewsConnector, and CyberNewsCollector orchestrator.
"""

from __future__ import annotations
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intel.config import load_cyber_config
from intel.connectors import (
    BaseCyberNewsConnector,
    HacklidoConnector,
    BleepingComputerConnector,
    TheHackerNewsConnector,
    CybersecurityNewsConnector,
)
from intel.collector_service import CyberNewsCollector, THNCollectorService
from intel.db import IntelligenceDB
from intel.models import (
    Article,
    ConnectorHealth,
    SOURCE_THEHACKERNEWS,
    SOURCE_HACKLIDO,
    SOURCE_BLEEPINGCOMPUTER,
    SOURCE_CYBERSECURITYNEWS,
    ALL_CYBER_SOURCES,
)
from intel.security import compute_content_hash, normalize_url, sanitize_text


class TestHacklidoConnector(unittest.TestCase):
    """Test Hacklido connector normalization, API parsing, and RSS fallback."""

    def setUp(self):
        self.connector = HacklidoConnector()

    def test_normalize_json_api_discussion(self):
        sample_entry = {
            "_source": "json_api",
            "disc": {
                "id": "1723",
                "attributes": {
                    "title": "BUG BOUNTY, DAY 5 : Broken Access Control and Privilege Escalation",
                    "slug": "1723-bug-bounty-day-5-broken-access-control-and-privilege-escalation",
                    "createdAt": "2026-10-30T02:55:24+00:00",
                    "lastPostedAt": "2026-10-30T03:10:00+00:00",
                },
                "relationships": {
                    "user": {"data": {"type": "users", "id": "42"}},
                    "firstPost": {"data": {"type": "posts", "id": "890"}},
                    "tags": {"data": [{"type": "tags", "id": "5"}]},
                },
            },
            "inc_users": {
                "42": {"id": "42", "attributes": {"username": "hacker_singh", "displayName": "Hacker Singh"}}
            },
            "inc_posts": {
                "890": {
                    "id": "890",
                    "attributes": {
                        "contentHtml": "<p>Day 5 of Bug Bounty focuses on Broken Access Control (BWoS).</p><p>Privilege escalation occurs when user access checks fail.</p>"
                    },
                }
            },
            "inc_tags": {
                "5": {"id": "5", "attributes": {"name": "Bug Bounty", "slug": "bug-bounty"}}
            },
        }

        article = self.connector.normalize_article(sample_entry)
        self.assertIsNotNone(article)
        self.assertEqual(article.article_id, "hacklido_1723")
        self.assertEqual(article.source, SOURCE_HACKLIDO)
        self.assertEqual(article.title, "BUG BOUNTY, DAY 5 : Broken Access Control and Privilege Escalation")
        self.assertEqual(article.author, "Hacker Singh")
        self.assertEqual(article.url, "https://hacklido.com/d/1723-bug-bounty-day-5-broken-access-control-and-privilege-escalation")
        self.assertEqual(article.published_at, "2026-10-30T02:55:24Z")
        self.assertEqual(article.category, "Bug Bounty")
        self.assertIn("Bug Bounty", article.tags)
        self.assertIn("Privilege escalation", article.content)
        self.assertEqual(article.content_accessible, "full")
        self.assertEqual(len(article.content_hash), 64)

    def test_normalize_rss_fallback(self):
        sample_rss_entry = {
            "_source": "rss",
            "title": "Runtime Detection and What to Log",
            "link": "https://hacklido.com/blog/1722-runtime-detection/1",
            "pubDate": "Fri, 30 Oct 2026 02:53:24 +0000",
            "description": "<p>Scoping limits what a landed prompt injection can reach.</p>",
        }

        article = self.connector.normalize_article(sample_rss_entry)
        self.assertIsNotNone(article)
        self.assertTrue(article.article_id.startswith("hacklido_"))
        self.assertEqual(article.source, SOURCE_HACKLIDO)
        self.assertEqual(article.title, "Runtime Detection and What to Log")
        self.assertEqual(article.url, "https://hacklido.com/blog/1722-runtime-detection/1")
        self.assertEqual(article.published_at, "2026-10-30T02:53:24Z")
        self.assertIn("prompt injection", article.content)
        self.assertEqual(article.content_accessible, "full")


class TestBleepingComputerConnector(unittest.TestCase):
    """Test BleepingComputer connector normalization, summary handling, and partial accessibility."""

    def setUp(self):
        self.connector = BleepingComputerConnector()

    def test_normalize_rss_entry_with_partial_accessibility(self):
        raw_data = {
            "title": "Critical Linux kernel flaw allows remote root attacks on MPTCP servers",
            "link": "https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/?utm_source=feed",
            "pubDate": "Fri, 30 Oct 2026 17:09:46 -0400",
            "creator": "Lawrence Abrams",
            "categories": ["Security", "Linux"],
            "description": "Security researchers at Anthropic have developed an exploit for a critical Linux kernel vulnerability.",
        }

        article = self.connector.normalize_article(raw_data)
        self.assertIsNotNone(article)
        self.assertTrue(article.article_id.startswith("bc_"))
        self.assertEqual(article.source, SOURCE_BLEEPINGCOMPUTER)
        self.assertEqual(article.title, "Critical Linux kernel flaw allows remote root attacks on MPTCP servers")
        # Canonical URL strips utm params
        self.assertEqual(
            article.url,
            "https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers",
        )
        self.assertEqual(article.author, "Lawrence Abrams")
        # -0400 offset converted to UTC Z (+4 hours -> 21:09:46)
        self.assertEqual(article.published_at, "2026-10-30T21:09:46Z")
        self.assertEqual(article.category, "Security")
        self.assertIn("Linux", article.tags)
        self.assertIn("Anthropic", article.summary)
        # Marked as partial since full HTML scraping is protected
        self.assertEqual(article.content_accessible, "partial")

    def test_fetch_article_respects_access_restrictions(self):
        # When remote server returns 403 / anti-bot, fetch_article should not raise and should return accessible: partial
        with patch.object(self.connector, "_http_get", return_value=(403, "Forbidden", {})):
            result = self.connector.fetch_article("https://www.bleepingcomputer.com/news/security/sample")
            self.assertEqual(result["accessible"], "partial")
            self.assertEqual(result["content"], "")


class TestTheHackerNewsConnector(unittest.TestCase):
    """Test The Hacker News connector."""

    def setUp(self):
        self.connector = TheHackerNewsConnector()

    def test_thehackernews_connector_inheritance(self):
        self.assertEqual(self.connector.source_name, SOURCE_THEHACKERNEWS)
        self.assertEqual(self.connector.display_name, "The Hacker News")

        sample_entry = {
            "title": {"$t": "Chinese Hackers Use AI-Powered ARTEX to Target 200 Orgs"},
            "link": [{"rel": "alternate", "href": "https://thehackernews.com/2026/10/chinese-hackers.html"}],
            "published": {"$t": "2026-10-30T16:58:44Z"},
            "author": [{"name": {"$t": "Ravie Lakshmanan"}}],
            "category": [{"term": "Cyber Attack"}, {"term": "AI"}],
            "summary": {"$t": "A sophisticated state-sponsored campaign was uncovered."},
        }

        article = self.connector.normalize_article(sample_entry)
        self.assertIsNotNone(article)
        self.assertEqual(article.source, SOURCE_THEHACKERNEWS)
        self.assertEqual(article.author, "Ravie Lakshmanan")
        self.assertEqual(article.content_accessible, "full")


class TestCybersecurityNewsConnector(unittest.TestCase):
    """Test Cybersecurity News connector with full content:encoded extraction."""

    def setUp(self):
        self.connector = CybersecurityNewsConnector()

    def test_normalize_rss_with_content_encoded(self):
        raw_data = {
            "title": "North Korean Hackers Steal Developer Credentials to Inject Malware",
            "link": "https://cybersecuritynews.com/north-korean-hackers-2/",
            "pubDate": "Fri, 30 Oct 2026 15:15:02 +0000",
            "creator": "Tushar Subhra Dutta",
            "categories": ["Cyber Security News", "Threats", "Malware"],
            "description": "A North Korea-aligned hacking group steals developer credentials.",
            "content_encoded": (
                "<p>A North Korea-aligned hacking group has moved beyond fake job interviews.</p>"
                "<p>Attackers planted malicious code into GitHub repos and PyPI packages.</p>"
            ),
        }

        article = self.connector.normalize_article(raw_data)
        self.assertIsNotNone(article)
        self.assertTrue(article.article_id.startswith("csn_"))
        self.assertEqual(article.source, SOURCE_CYBERSECURITYNEWS)
        self.assertEqual(article.title, "North Korean Hackers Steal Developer Credentials to Inject Malware")
        self.assertEqual(article.url, "https://cybersecuritynews.com/north-korean-hackers-2")
        self.assertEqual(article.author, "Tushar Subhra Dutta")
        self.assertEqual(article.published_at, "2026-10-30T15:15:02Z")
        self.assertEqual(article.category, "Cyber Security News")
        self.assertIn("Malware", article.tags)
        self.assertIn("fake job interviews", article.content)
        self.assertIn("PyPI packages", article.content)
        self.assertEqual(article.content_accessible, "full")


class TestCyberNewsCollector(unittest.TestCase):
    """Test multi-source collection orchestrator, deduplication, health monitoring, and checkpoints."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_cyber.db"
        self.db = IntelligenceDB(self.db_path)

        # Mock connectors
        self.mock_thn = MagicMock()
        self.mock_thn.source_name = SOURCE_THEHACKERNEWS
        self.mock_hacklido = MagicMock()
        self.mock_hacklido.source_name = SOURCE_HACKLIDO
        self.mock_bc = MagicMock()
        self.mock_bc.source_name = SOURCE_BLEEPINGCOMPUTER
        self.mock_csn = MagicMock()
        self.mock_csn.source_name = SOURCE_CYBERSECURITYNEWS

        self.connectors = {
            SOURCE_THEHACKERNEWS: self.mock_thn,
            SOURCE_HACKLIDO: self.mock_hacklido,
            SOURCE_BLEEPINGCOMPUTER: self.mock_bc,
            SOURCE_CYBERSECURITYNEWS: self.mock_csn,
        }

        self.collector = CyberNewsCollector(
            db=self.db,
            connectors=self.connectors,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_database_view_and_migration(self):
        """Verify cyber_news_articles view and new columns exist."""
        with self.db.connection() as conn:
            # Check view exists
            view_row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='view' AND name='cyber_news_articles'"
            ).fetchone()
            self.assertIsNotNone(view_row)

            # Test querying view
            count = conn.execute("SELECT COUNT(*) FROM cyber_news_articles").fetchone()[0]
            self.assertEqual(count, 0)

    def test_collect_source_latest_success(self):
        """Verify single source collection inserts new articles and logs telemetry."""
        sample_article = Article(
            article_id="hacklido_999",
            source=SOURCE_HACKLIDO,
            title="OAuth Flow Hijacking via Redirect URI",
            url="https://hacklido.com/d/999-oauth-flow",
            author="WhiteHat",
            published_at="2026-10-30T10:00:00Z",
            category="Web Security",
            tags=["OAuth", "Bug Bounty"],
            summary="Flaw in redirect_uri parameter parsing.",
            content="Detailed breakdown of how the OAuth flow was bypassed.",
            content_hash=compute_content_hash("Detailed breakdown of how the OAuth flow was bypassed."),
            content_accessible="full",
        )

        self.mock_hacklido.collect_latest.return_value = [{"raw": "data"}]
        self.mock_hacklido.normalize_article.return_value = sample_article

        stats = self.collector.collect_source_latest(SOURCE_HACKLIDO, limit=5)
        self.assertEqual(stats["source"], SOURCE_HACKLIDO)
        self.assertEqual(stats["discovered"], 1)
        self.assertEqual(stats["new_articles"], 1)
        self.assertEqual(stats["duplicates"], 0)
        self.assertEqual(stats["status"], "completed")

        # Verify persisted in DB
        fetched = self.db.get_article_by_id("hacklido_999")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.source, SOURCE_HACKLIDO)
        self.assertEqual(fetched.title, "OAuth Flow Hijacking via Redirect URI")
        self.assertEqual(fetched.content_accessible, "full")

        # Verify source health recorded
        health = self.db.get_connector_status(f"{SOURCE_HACKLIDO}_connector")
        self.assertIsNotNone(health)
        self.assertEqual(health.status, "CONNECTED")
        self.assertGreaterEqual(health.records_processed, 1)

    def test_collect_source_latest_duplicate_detection(self):
        """Verify second collection detects duplicate and skips re-download."""
        sample_article = Article(
            article_id="bc_777",
            source=SOURCE_BLEEPINGCOMPUTER,
            title="LockBit 4.0 Decryptor Released",
            url="https://www.bleepingcomputer.com/news/security/lockbit-decryptor",
            author="Lawrence Abrams",
            published_at="2026-10-29T12:00:00Z",
            summary="A working decryptor is now available.",
            content="Researchers reverse engineered the key generator.",
            content_hash=compute_content_hash("Researchers reverse engineered the key generator."),
        )

        # First insert
        self.db.insert_article(sample_article)
        self.assertEqual(self.db.get_article_count(source=SOURCE_BLEEPINGCOMPUTER), 1)

        self.mock_bc.collect_latest.return_value = [{"raw": "bc"}]
        self.mock_bc.normalize_article.return_value = sample_article

        stats = self.collector.collect_source_latest(SOURCE_BLEEPINGCOMPUTER, limit=1)
        self.assertEqual(stats["discovered"], 1)
        self.assertEqual(stats["new_articles"], 0)
        self.assertEqual(stats["duplicates"], 1)
        self.assertEqual(self.db.get_article_count(source=SOURCE_BLEEPINGCOMPUTER), 1)

    def test_collect_latest_multi_source_aggregation(self):
        """Verify collect_latest gathers and aggregates statistics across all 4 sources."""
        for name, mock_conn in self.connectors.items():
            art = Article(
                article_id=f"{name}_1",
                source=name,
                title=f"Sample Incident from {name}",
                url=f"https://{name}.com/article1",
                published_at="2026-10-30T12:00:00Z",
                content=f"Content for {name}",
                content_hash=compute_content_hash(f"Content for {name}"),
            )
            mock_conn.collect_latest.return_value = [{"raw": name}]
            mock_conn.normalize_article.return_value = art

        overall = self.collector.collect_latest(source=None, limit=5)
        self.assertEqual(overall["total_discovered"], 4)
        self.assertEqual(overall["total_new"], 4)
        self.assertEqual(overall["total_duplicates"], 0)
        self.assertEqual(len(overall["sources"]), 4)

        # Verify database has articles from all 4 sources
        self.assertEqual(self.db.get_article_count(), 4)
        stats = self.db.get_source_stats()
        self.assertIn(SOURCE_THEHACKERNEWS, stats)
        self.assertIn(SOURCE_HACKLIDO, stats)
        self.assertIn(SOURCE_BLEEPINGCOMPUTER, stats)
        self.assertIn(SOURCE_CYBERSECURITYNEWS, stats)

    def test_source_filtering_in_db_queries(self):
        """Verify IntelligenceDB filtering by source."""
        for src in ALL_CYBER_SOURCES:
            for i in range(2):
                self.db.insert_article(
                    Article(
                        article_id=f"{src}_{i}",
                        source=src,
                        title=f"{src} news {i}",
                        url=f"https://example.com/{src}/{i}",
                        published_at=f"2026-10-{20+i:02d}T10:00:00Z",
                        content=f"Content {src} {i}",
                        content_hash=compute_content_hash(f"Content {src} {i}"),
                    )
                )

        self.assertEqual(self.db.get_article_count(), 8)
        self.assertEqual(self.db.get_article_count(source=SOURCE_HACKLIDO), 2)
        self.assertEqual(self.db.get_article_count(source=SOURCE_CYBERSECURITYNEWS), 2)

        hacklido_articles = self.db.get_articles(source=SOURCE_HACKLIDO)
        self.assertEqual(len(hacklido_articles), 2)
        for a in hacklido_articles:
            self.assertEqual(a.source, SOURCE_HACKLIDO)

    def test_retry_failed_jobs(self):
        """Verify retry_failed_jobs triggers collection on degraded or error sources."""
        # Record an ERROR status for Hacklido
        self.collector.update_source_health(
            source=SOURCE_HACKLIDO,
            status="ERROR",
            last_error="Simulated network failure",
        )

        health_before = self.collector.get_source_health(SOURCE_HACKLIDO)[0]
        self.assertEqual(health_before.status, "ERROR")

        # Mock recovery
        recovered_art = Article(
            article_id="hacklido_recovered",
            source=SOURCE_HACKLIDO,
            title="Recovered Hacklido Advisory",
            url="https://hacklido.com/recovered",
            published_at="2026-10-30T18:00:00Z",
            content="Recovered advisory content",
            content_hash=compute_content_hash("Recovered advisory content"),
        )
        self.mock_hacklido.collect_latest.return_value = [{"raw": "recovered"}]
        self.mock_hacklido.normalize_article.return_value = recovered_art

        retry_result = self.collector.retry_failed_jobs()
        self.assertEqual(retry_result["retried"], 1)
        self.assertIn(SOURCE_HACKLIDO, retry_result["results"])

        health_after = self.collector.get_source_health(SOURCE_HACKLIDO)[0]
        self.assertEqual(health_after.status, "CONNECTED")

    def test_thn_collector_service_backward_compatibility(self):
        """Verify existing THNCollectorService continues functioning identically."""
        mock_provider = MagicMock()
        mock_provider.collect_latest.return_value = [{"entry": 1}]
        mock_provider.normalize_article.return_value = Article(
            article_id="thn_compat_1",
            source=SOURCE_THEHACKERNEWS,
            title="Compatibility Advisory",
            url="https://thehackernews.com/2026/10/compat.html",
            published_at="2026-10-30T12:00:00Z",
            content="Compatible content",
            content_hash=compute_content_hash("Compatible content"),
        )

        legacy_service = THNCollectorService(db=self.db, provider=mock_provider)
        res = legacy_service.collect_latest(limit=1)
        self.assertEqual(res["new_articles"], 1)
        self.assertEqual(res["discovered"], 1)

        fetched = self.db.get_article_by_id("thn_compat_1")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.source, SOURCE_THEHACKERNEWS)

    def test_module2_briefings_investigations_bookmarks_reading_history(self):
        """Verify Module 2 database tables: briefings, investigations, bookmarks, reading history."""
        # 1. Briefings
        bid = self.db.save_briefing(
            title="Daily Cyber Briefing",
            content="Top stories across 4 sources.",
            time_window="24h",
            sources_included=list(ALL_CYBER_SOURCES),
            article_ids=["thn_1", "bc_1"],
            critical_alerts=["CVE-2026-1001 in Linux Kernel"],
            emerging_threats=["AI-powered phishing"],
            recommended_actions=["Patch Linux MPTCP servers"],
        )
        briefings = self.db.get_briefings(limit=5)
        self.assertEqual(len(briefings), 1)
        self.assertEqual(briefings[0]["briefing_id"], bid)
        self.assertEqual(briefings[0]["sources_included"], list(ALL_CYBER_SOURCES))

        # 2. Investigations
        iid = self.db.save_investigation(
            title="Deep Dive: Linux MPTCP Vulnerability",
            content="Detailed technical breakdown...",
            article_id="bc_1",
            sources_referenced=["bleepingcomputer", "thehackernews"],
            mitre_techniques=["T1190"],
            cves=["CVE-2026-1001"],
            language="en",
        )
        investigations = self.db.get_investigations(limit=5)
        self.assertEqual(len(investigations), 1)
        self.assertEqual(investigations[0]["investigation_id"], iid)
        self.assertEqual(investigations[0]["cves"], ["CVE-2026-1001"])

        # 3. Bookmarks
        self.db.add_bookmark(
            item_id="bc_1",
            title="Critical Linux Kernel Flaw",
            item_type="article",
            source=SOURCE_BLEEPINGCOMPUTER,
            url="https://www.bleepingcomputer.com/news/security/linux-flaw/",
            notes="Review for lab exercise",
        )
        bms = self.db.get_bookmarks(item_type="article")
        self.assertEqual(len(bms), 1)
        self.assertEqual(bms[0]["item_id"], "bc_1")
        self.assertTrue(self.db.remove_bookmark("bc_1", item_type="article"))
        self.assertEqual(len(self.db.get_bookmarks(item_type="article")), 0)

        # 4. Reading History
        self.db.record_reading_history(
            article_id="bc_1",
            title="Critical Linux Kernel Flaw",
            source=SOURCE_BLEEPINGCOMPUTER,
            url="https://www.bleepingcomputer.com/news/security/linux-flaw/",
            mode="technical_detail",
        )
        history = self.db.get_reading_history(limit=5)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["article_id"], "bc_1")
        self.assertEqual(history[0]["mode"], "technical_detail")


if __name__ == "__main__":
    unittest.main()

