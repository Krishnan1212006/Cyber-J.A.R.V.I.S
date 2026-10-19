"""
Unit tests for JARVIS Cybersecurity Intelligence Ingestion Pipeline (Phase 1).
Covers normalization, canonicalization, deduplication, storage, FTS search,
checkpointing, error resilience, and provider mocks.
"""

from __future__ import annotations
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from intel.db import IntelligenceDB
from intel.models import Article, CollectionCheckpoint
from intel.security import (
    sanitize_text,
    normalize_url,
    compute_content_hash,
    wrap_untrusted,
)
from intel.thn_provider import BaseDataProvider, THNDataProvider
from intel.collector_service import THNCollectorService


class TestSecurityAndNormalization(unittest.TestCase):
    """Test sanitization, URL canonicalization, and content hashing."""

    def test_sanitize_text_strips_control_characters(self):
        malicious = "Malware analysis\x00\x08\x0b\x1f with harmless text"
        clean = sanitize_text(malicious)
        self.assertEqual(clean, "Malware analysis with harmless text")
        self.assertNotIn("\x00", clean)
        self.assertNotIn("\x08", clean)

    def test_url_canonicalization(self):
        # 1. Strips tracking params
        url1 = "https://thehackernews.com/2026/10/critical-flaw.html?utm_source=twitter&utm_medium=social"
        expected = "https://thehackernews.com/2026/10/critical-flaw.html"
        self.assertEqual(normalize_url(url1), expected)

        # 2. Strips Blogger mobile param (?m=1) and fragments (#section)
        url2 = "http://TheHackerNews.com/2026/10/critical-flaw.html?m=1#comments"
        self.assertEqual(normalize_url(url2), expected)

        # 3. Canonicalizes protocol to https and lowercases domain
        url3 = "HTTP://THEHACKERNEWS.COM/2026/10/critical-flaw.html/"
        self.assertEqual(normalize_url(url3), expected)

    def test_content_hashing_consistency(self):
        text_a = "Critical Zero-Day in OpenSSH allows RCE."
        text_b = "Critical  Zero-Day   in OpenSSH allows RCE. \n"
        # Hashing normalizes whitespace and case
        hash_a = compute_content_hash(text_a)
        hash_b = compute_content_hash(text_b)
        self.assertEqual(hash_a, hash_b)
        self.assertEqual(len(hash_a), 64)

    def test_wrap_untrusted_enclosure(self):
        text = "Drop database commands or injection payloads"
        wrapped = wrap_untrusted(text, source="thehackernews")
        self.assertIn('<untrusted_cyber_article source="thehackernews">', wrapped)
        self.assertIn("</untrusted_cyber_article>", wrapped)


class TestDatabaseAndDeduplication(unittest.TestCase):
    """Test database schema, WAL mode, deduplication tiers, and FTS5 search."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_intel.db"
        self.db = IntelligenceDB(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_database_initialization(self):
        self.assertTrue(self.db_path.exists())
        self.assertEqual(self.db.get_article_count(), 0)

    def test_article_insertion_and_retrieval(self):
        article = Article(
            article_id="thn_1001",
            source="thehackernews",
            title="Massive Ransomware Outbreak",
            url="https://thehackernews.com/2026/10/ransomware-outbreak.html",
            author="Security Researcher",
            published_at="2026-10-01T12:00:00Z",
            category="Ransomware",
            tags=["LockBit", "Ransomware"],
            summary="A new variant has hit enterprise servers.",
            content="Full detailed forensic writeup regarding the incident.",
            content_hash=compute_content_hash("Full detailed forensic writeup regarding the incident."),
        )

        inserted = self.db.insert_article(article)
        self.assertTrue(inserted)
        self.assertEqual(self.db.get_article_count(), 1)

        fetched = self.db.get_article_by_id("thn_1001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.title, "Massive Ransomware Outbreak")
        self.assertEqual(fetched.tags, ["LockBit", "Ransomware"])

    def test_deduplication_tier_1_canonical_url(self):
        article1 = Article(
            article_id="thn_1001",
            title="Article One",
            url="https://thehackernews.com/2026/10/article-one.html",
            published_at="2026-10-01T12:00:00Z",
            content="Some initial content",
            content_hash=compute_content_hash("Some initial content"),
        )
        self.assertTrue(self.db.insert_article(article1))

        # Attempt to insert article with different ID and hash, but same URL
        article2 = Article(
            article_id="thn_1002",
            title="Article One Alternate Title",
            url="https://thehackernews.com/2026/10/article-one.html",
            published_at="2026-10-02T12:00:00Z",
            content="Different content entirely",
            content_hash=compute_content_hash("Different content entirely"),
        )

        is_dup, reason = self.db.check_duplicate(article2.url, article2.content_hash, article2.article_id)
        self.assertTrue(is_dup)
        self.assertEqual(reason, "url")
        self.assertFalse(self.db.insert_article(article2))

    def test_deduplication_tier_2_article_id(self):
        article1 = Article(
            article_id="thn_unique_id_99",
            title="Article A",
            url="https://thehackernews.com/2026/10/article-a.html",
            published_at="2026-10-01T12:00:00Z",
            content="Content A",
            content_hash=compute_content_hash("Content A"),
        )
        self.assertTrue(self.db.insert_article(article1))

        # Same article_id but different URL
        is_dup, reason = self.db.check_duplicate(
            url="https://thehackernews.com/2026/10/article-b.html",
            article_id="thn_unique_id_99",
            content_hash=compute_content_hash("Content B"),
        )
        self.assertTrue(is_dup)
        self.assertEqual(reason, "article_id")

    def test_deduplication_tier_3_content_hash(self):
        article1 = Article(
            article_id="thn_2001",
            title="Syndicated Story Original",
            url="https://thehackernews.com/2026/10/original.html",
            published_at="2026-10-01T12:00:00Z",
            content="Identical syndicated wire reporting word for word.",
            content_hash=compute_content_hash("Identical syndicated wire reporting word for word."),
        )
        self.assertTrue(self.db.insert_article(article1))

        # Different ID and different URL, but identical content hash
        is_dup, reason = self.db.check_duplicate(
            url="https://thehackernews.com/2026/10/repost.html",
            article_id="thn_2002",
            content_hash=compute_content_hash("Identical syndicated wire reporting word for word."),
        )
        self.assertTrue(is_dup)
        self.assertEqual(reason, "content_hash")

    def test_fts5_full_text_search(self):
        article = Article(
            article_id="thn_3001",
            title="SolarWinds Supply Chain Cyberattack",
            url="https://thehackernews.com/2026/10/solarwinds.html",
            published_at="2026-10-01T12:00:00Z",
            summary="State-sponsored hackers inserted a backdoor into Orion software.",
            content="Detailed forensic breakdown of SUNBURST malware payload and C2 infrastructure.",
            content_hash=compute_content_hash("SUNBURST payload"),
        )
        self.db.insert_article(article)

        # Search for unique keyword
        results = self.db.search_articles_fts("SUNBURST")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].article_id, "thn_3001")

        # Search with no match
        no_results = self.db.search_articles_fts("NonExistentExploitXYZ")
        self.assertEqual(len(no_results), 0)

    def test_checkpoint_persistence_and_resume(self):
        cp = CollectionCheckpoint(
            job_name="thn_historical_test",
            last_run_at="2026-10-01T10:00:00Z",
            last_article_id="thn_9999",
            cursor_offset=150,
            articles_collected=45,
            status="running",
        )
        self.db.save_checkpoint(cp)

        loaded = self.db.get_checkpoint("thn_historical_test")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.cursor_offset, 150)
        self.assertEqual(loaded.articles_collected, 45)


class TestProviderAndService(unittest.TestCase):
    """Test data normalization, mocked collection workflows, and error handling."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_service.db"
        self.db = IntelligenceDB(self.db_path)
        self.provider = THNDataProvider(config={"db_path": str(self.db_path)})

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_article_normalization_from_blogger_format(self):
        raw_blogger_entry = {
            "id": {"$t": "tag:blogger.com,1999:blog-4802841478634147276.post-5873586575544573402"},
            "published": {"$t": "2026-10-03T14:38:00.000Z"},
            "updated": {"$t": "2026-10-03T14:40:00.000Z"},
            "title": {"$t": "Critical Flaw in OpenSSL Allows Remote Code Execution"},
            "summary": {"$t": "A high-severity buffer overflow flaw has been disclosed in OpenSSL versions..."},
            "link": [
                {
                    "rel": "alternate",
                    "href": "https://thehackernews.com/2026/10/critical-flaw-in-openssl.html?utm_source=feed",
                }
            ],
            "author": [{"name": {"$t": "Ravie Lakshmanan"}}],
            "category": [{"term": "Vulnerability"}, {"term": "Encryption"}],
            "georss$featurename": {"$t": "Vulnerability / Encryption"},
        }

        article = self.provider.normalize_article(raw_blogger_entry)
        self.assertIsNotNone(article)
        self.assertEqual(article.article_id, "thn_5873586575544573402")
        self.assertEqual(article.title, "Critical Flaw in OpenSSL Allows Remote Code Execution")
        self.assertEqual(article.url, "https://thehackernews.com/2026/10/critical-flaw-in-openssl.html")
        self.assertEqual(article.author, "Ravie Lakshmanan")
        self.assertEqual(article.published_at, "2026-10-03T14:38:00Z")
        self.assertIn("Vulnerability", article.tags)
        self.assertTrue(len(article.content_hash) == 64)

    def test_malformed_article_handling(self):
        # Missing title
        bad_entry_1 = {
            "id": {"$t": "post-1"},
            "published": {"$t": "2026-10-01T00:00:00Z"},
            "link": [{"rel": "alternate", "href": "https://thehackernews.com/test.html"}],
        }
        self.assertIsNone(self.provider.normalize_article(bad_entry_1))

        # Missing URL
        bad_entry_2 = {
            "id": {"$t": "post-2"},
            "title": {"$t": "Some title"},
            "published": {"$t": "2026-10-01T00:00:00Z"},
        }
        self.assertIsNone(self.provider.normalize_article(bad_entry_2))

        # Invalid date
        bad_entry_3 = {
            "id": {"$t": "post-3"},
            "title": {"$t": "Some title"},
            "published": {"$t": "NOT_A_DATE"},
            "link": [{"rel": "alternate", "href": "https://thehackernews.com/test.html"}],
        }
        self.assertIsNone(self.provider.normalize_article(bad_entry_3))

    def test_latest_collection_orchestrator_and_deduplication(self):
        # Mock provider returning 3 entries: 2 valid and 1 malformed
        mock_provider = MagicMock(spec=BaseDataProvider)
        mock_provider.collect_latest.return_value = [
            {
                "id": "post-1",
                "title": "Article 1",
                "published_at": "2026-10-01T10:00:00Z",
                "url": "https://thehackernews.com/art1.html",
                "summary": "Summary 1",
            },
            {
                "id": "post-2",
                "title": "Article 2",
                "published_at": "2026-10-02T10:00:00Z",
                "url": "https://thehackernews.com/art2.html",
                "summary": "Summary 2",
            },
            {
                "id": "post-invalid",
                # missing title & url
            },
        ]
        # normalize_article mock
        def fake_normalize(entry):
            if "title" not in entry:
                return None
            return Article(
                article_id=entry["id"],
                title=entry["title"],
                url=entry["url"],
                published_at=entry["published_at"],
                summary=entry["summary"],
                content=entry["summary"],
                content_hash=compute_content_hash(entry["summary"]),
            )

        mock_provider.normalize_article.side_effect = fake_normalize
        mock_provider.fetch_article.return_value = {"content": "Full body text"}

        service = THNCollectorService(db=self.db, provider=mock_provider)

        # 1st Collection Run
        stats1 = service.collect_latest(limit=3, fetch_full_body=False)
        self.assertEqual(stats1["discovered"], 3)
        self.assertEqual(stats1["new_articles"], 2)
        self.assertEqual(stats1["duplicates"], 0)
        self.assertEqual(stats1["failed"], 1)
        self.assertEqual(self.db.get_article_count(), 2)

        # 2nd Collection Run with same data: all valid items should be detected as duplicates
        stats2 = service.collect_latest(limit=3, fetch_full_body=False)
        self.assertEqual(stats2["discovered"], 3)
        self.assertEqual(stats2["new_articles"], 0)
        self.assertEqual(stats2["duplicates"], 2)
        self.assertEqual(stats2["failed"], 1)
        self.assertEqual(self.db.get_article_count(), 2)

    def test_historical_collection_date_filtering(self):
        # Mock historical generator yielding 2 batches
        mock_provider = MagicMock(spec=BaseDataProvider)
        batch1 = [
            {
                "id": "hist-1",
                "title": "Historical 1",
                "published_at": "2026-09-15T12:00:00Z",
                "url": "https://thehackernews.com/hist1.html",
                "summary": "Hist Summary 1",
            }
        ]
        batch2 = [
            {
                "id": "hist-2",
                "title": "Historical 2",
                "published_at": "2026-09-10T12:00:00Z",
                "url": "https://thehackernews.com/hist2.html",
                "summary": "Hist Summary 2",
            }
        ]
        mock_provider.collect_historical.return_value = iter([batch1, batch2])

        def fake_normalize(entry):
            return Article(
                article_id=entry["id"],
                title=entry["title"],
                url=entry["url"],
                published_at=entry["published_at"],
                summary=entry["summary"],
                content=entry["summary"],
                content_hash=compute_content_hash(entry["summary"]),
            )

        mock_provider.normalize_article.side_effect = fake_normalize

        service = THNCollectorService(db=self.db, provider=mock_provider)
        stats = service.collect_historical(
            start_date="2026-09-01",
            end_date="2026-09-30",
            max_articles=10,
            resume=False,
            fetch_full_body=False,
        )

        self.assertEqual(stats["new_articles"], 2)
        self.assertEqual(stats["duplicates"], 0)
        self.assertEqual(self.db.get_article_count(), 2)


if __name__ == "__main__":
    unittest.main()
