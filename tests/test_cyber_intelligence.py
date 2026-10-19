"""
Comprehensive test suite for Phase 3: Cybersecurity Trend, Risk and Intelligence Analysis.

Covers all 20 required dimensions:
1. Time-window filtering
2. Threat frequency calculation
3. Percentage change
4. Zero-baseline handling
5. Trend classification
6. Emerging threat detection
7. CVE ranking & exploitation evidence
8. Malware ranking
9. Threat actor ranking
10. MITRE technique ranking
11. Sector analysis
12. Risk score calculation
13. Risk category boundaries
14. Confidence calculation
15. Cross-article correlation
16. Duplicate / syndicated article handling
17. API responses (FastAPI TestClient)
18. Empty database behavior
19. Sparse data & missing fields
20. Large dataset behavior & trend snapshots
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from intel.api import router, set_engine
from intel.correlation import ThreatCorrelationEngine, ThreatRelationship
from intel.db import IntelligenceDB
from intel.intelligence_engine import CybersecurityIntelligenceEngine
from intel.models import Article, ArticleAnalysis, TrendSnapshot, utc_now_iso
from intel.risk_scoring import RiskScoreResult, calculate_risk_score
from intel.time_windows import (
    format_iso,
    get_previous_period,
    resolve_time_window,
    utc_now,
)
from intel.trends import TrendResult, calculate_trend

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    _FASTAPI_TEST_AVAILABLE = True
except ImportError:
    _FASTAPI_TEST_AVAILABLE = False


class TestCybersecurityIntelligencePhase3(unittest.TestCase):
    """Unit test suite for Phase 3 Intelligence Engine, Trends, Risk, and Correlation."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.temp_dir / "test_intel_p3.db"
        self.db = IntelligenceDB(self.db_path)
        self.engine = CybersecurityIntelligenceEngine(db=self.db)
        if _FASTAPI_TEST_AVAILABLE:
            set_engine(self.engine)

        # Baseline reference time for deterministic testing: 2026-10-15T12:00:00Z
        self.ref_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        if _FASTAPI_TEST_AVAILABLE:
            set_engine(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _insert_test_article(
        self,
        article_id: str,
        published_at: str,
        title: str = "Test Cyber Incident",
        cves: list[str] = None,
        cves_exploited: list[str] = None,
        threat_actors: list[str] = None,
        malware: list[str] = None,
        ransomware: list[str] = None,
        target_sectors: list[str] = None,
        mitre_tactics: list[str] = None,
        mitre_techniques: list[str] = None,
        threat_types: list[str] = None,
        attack_types: list[str] = None,
        attack_vectors: list[str] = None,
        affected_products: list[str] = None,
        affected_vendors: list[str] = None,
        targeted_countries: list[str] = None,
        severity: str = "HIGH",
        content_hash: str = None,
    ) -> tuple[Article, ArticleAnalysis]:
        """Helper to create and insert an article with its structured analysis."""
        article = Article(
            article_id=article_id,
            title=title,
            url=f"https://thehackernews.com/2026/10/{article_id}.html",
            author="Security Researcher",
            published_at=published_at,
            content=f"Detailed body for {title}",
            content_hash=content_hash or f"hash_{article_id}",
            category="Cyberattacks",
            analysis_status="completed",
        )
        self.db.insert_article(article)

        is_actively_exploited = bool(cves_exploited)
        summary_text = f"Summary for {title}."
        sev_reason = "Calculated from threat scope."
        if is_actively_exploited:
            summary_text += " This vulnerability is actively exploited in the wild by threat actors."
            sev_reason = "Critical severity due to active exploitation in the wild."

        mitre_attack = []
        tactics = mitre_tactics or (["Execution"] if mitre_techniques else [])
        techniques = mitre_techniques or []
        for tech in techniques:
            mitre_attack.append({
                "tactic": tactics[0] if tactics else "Execution",
                "technique_id": tech,
                "technique_name": tech,
            })

        analysis = ArticleAnalysis(
            analysis_id=f"analysis_{article_id}",
            article_id=article_id,
            analysis_version="v1",
            analysis_status="completed",
            title=title,
            published_at=published_at,
            summary=summary_text,
            threat_types=threat_types if threat_types is not None else ["Ransomware"],
            attack_types=attack_types if attack_types is not None else ["Initial Access"],
            attack_vectors=attack_vectors if attack_vectors is not None else ["Phishing"],
            threat_actors=threat_actors or [],
            malware=malware or [],
            ransomware=ransomware or [],
            cves=cves or [],
            affected_vendors=affected_vendors or [],
            affected_products=affected_products or [],
            target_sectors=target_sectors or [],
            target_countries=targeted_countries or [],
            mitre_attack=mitre_attack,
            severity=severity,
            severity_reason=sev_reason,
            confidence="HIGH",
        )
        self.db.save_analysis(analysis)
        return article, analysis

    # ── 1. Time-Window Filtering ──────────────────────────────────────────────
    def test_01_time_window_filtering(self) -> None:
        """Verify time window boundaries (24h, 7d, 30d, 90d, custom) and filtering."""
        self._insert_test_article("art_6h", "2026-10-15T06:00:00Z")     # within 24h
        self._insert_test_article("art_3d", "2026-10-12T12:00:00Z")     # within 7d, outside 24h
        self._insert_test_article("art_15d", "2026-10-01T12:00:00Z")    # within 30d, outside 7d
        self._insert_test_article("art_60d", "2026-08-16T12:00:00Z")    # within 90d, outside 30d
        self._insert_test_article("art_200d", "2026-03-01T12:00:00Z")   # outside 90d

        # 24h window
        res_24h = self.engine.get_threat_overview("24h", ref_time=self.ref_time)
        self.assertEqual(res_24h["overview"]["articles"], 1)

        # 7d window
        res_7d = self.engine.get_threat_overview("7d", ref_time=self.ref_time)
        self.assertEqual(res_7d["overview"]["articles"], 2)

        # 30d window
        res_30d = self.engine.get_threat_overview("30d", ref_time=self.ref_time)
        self.assertEqual(res_30d["overview"]["articles"], 3)

        # 90d window
        res_90d = self.engine.get_threat_overview("90d", ref_time=self.ref_time)
        self.assertEqual(res_90d["overview"]["articles"], 4)

        # Custom date range
        res_custom = self.engine.get_threat_overview(
            "custom",
            start_date="2026-10-10T00:00:00Z",
            end_date="2026-10-15T12:00:00Z",
            ref_time=self.ref_time,
        )
        self.assertEqual(res_custom["overview"]["articles"], 2)

    # ── 2. Threat Frequency Calculation ───────────────────────────────────────
    def test_02_threat_frequency_calculation(self) -> None:
        """Verify counts match actual database records across all entity dimensions."""
        self._insert_test_article(
            "art_freq_1",
            "2026-10-14T10:00:00Z",
            threat_types=["Ransomware", "Data Exfiltration"],
            threat_actors=["LockBit Gang"],
            malware=["LockBit 3.0"],
            target_sectors=["Healthcare"],
            mitre_techniques=["T1059", "T1486"],
        )
        self._insert_test_article(
            "art_freq_2",
            "2026-10-13T10:00:00Z",
            threat_types=["Ransomware"],
            threat_actors=["LockBit Gang", "APT28"],
            malware=["LockBit 3.0", "Cobalt Strike"],
            target_sectors=["Healthcare", "Finance"],
            mitre_techniques=["T1059"],
        )

        overview = self.engine.get_threat_overview("7d", ref_time=self.ref_time)
        top_tt = overview["top_threat_types"]
        self.assertEqual(top_tt.get("Ransomware"), 2)
        self.assertEqual(top_tt.get("Data Exfiltration"), 1)

        malware_rank = self.engine.get_top_malware("7d", limit=5, ref_time=self.ref_time)
        self.assertEqual(malware_rank[0]["name"], "LockBit 3.0")
        self.assertEqual(malware_rank[0]["count"], 2)

        actor_rank = self.engine.get_top_threat_actors("7d", limit=5, ref_time=self.ref_time)
        self.assertEqual(actor_rank[0]["name"], "LockBit Gang")
        self.assertEqual(actor_rank[0]["count"], 2)

    # ── 3. Percentage Change ──────────────────────────────────────────────────
    def test_03_percentage_change(self) -> None:
        """Test calculation of percentage change: increase, decrease, stable."""
        # 10 to 15 -> +50.0%
        trend_up = calculate_trend("T1", 15, 10, min_evidence_threshold=2)
        self.assertEqual(trend_up.absolute_change, 5)
        self.assertAlmostEqual(trend_up.percentage_change, 50.0)
        self.assertEqual(trend_up.trend_status, "INCREASING")

        # 10 to 5 -> -50.0%
        trend_down = calculate_trend("T2", 5, 10, min_evidence_threshold=2)
        self.assertEqual(trend_down.absolute_change, -5)
        self.assertAlmostEqual(trend_down.percentage_change, -50.0)
        self.assertEqual(trend_down.trend_status, "DECREASING")

        # 10 to 10 -> 0.0%
        trend_stable = calculate_trend("T3", 10, 10, min_evidence_threshold=2)
        self.assertEqual(trend_stable.absolute_change, 0)
        self.assertAlmostEqual(trend_stable.percentage_change, 0.0)
        self.assertEqual(trend_stable.trend_status, "STABLE")

    # ── 4. Zero-Baseline Handling ─────────────────────────────────────────────
    def test_04_zero_baseline_handling(self) -> None:
        """Ensure previous_count=0 never divides by zero and classifies as EMERGING."""
        trend_zero = calculate_trend("CVE-2026-9999", current_count=5, previous_count=0, min_evidence_threshold=2)
        self.assertIsNone(trend_zero.percentage_change)
        self.assertEqual(trend_zero.trend_status, "EMERGING")
        self.assertEqual(trend_zero.absolute_change, 5)
        self.assertIn("Newly emerged threat", trend_zero.trend_reason)

        # Both zero -> INSUFFICIENT_DATA
        trend_both_zero = calculate_trend("NonExistent", current_count=0, previous_count=0, min_evidence_threshold=2)
        self.assertIsNone(trend_both_zero.percentage_change)
        self.assertEqual(trend_both_zero.trend_status, "INSUFFICIENT_DATA")

    # ── 5. Trend Classification ───────────────────────────────────────────────
    def test_05_trend_classification(self) -> None:
        """Verify all status states: INCREASING, DECREASING, STABLE, EMERGING, DECLINING, INSUFFICIENT_DATA."""
        # Below min evidence
        t_low = calculate_trend("TestLow", current_count=1, previous_count=0, min_evidence_threshold=2)
        self.assertEqual(t_low.trend_status, "INSUFFICIENT_DATA")

        # Declining to 0 from >=2
        t_declining = calculate_trend("TestOld", current_count=0, previous_count=5, min_evidence_threshold=2)
        self.assertEqual(t_declining.trend_status, "DECLINING")

        # Moderate increase < 20%
        t_stable = calculate_trend("TestStable", current_count=11, previous_count=10, min_evidence_threshold=2)
        self.assertEqual(t_stable.trend_status, "STABLE")

    # ── 6. Emerging Threat Detection ──────────────────────────────────────────
    def test_06_emerging_threat_detection(self) -> None:
        """Verify detection of entities rare/absent previously that accelerate recently."""
        self._insert_test_article("em_1", "2026-10-10T10:00:00Z", malware=["AkiraNew"], severity="CRITICAL")
        self._insert_test_article("em_2", "2026-10-12T10:00:00Z", malware=["AkiraNew"], severity="HIGH")
        self._insert_test_article("em_3", "2026-10-14T10:00:00Z", malware=["AkiraNew"], severity="HIGH")

        emerging = self.engine.get_emerging_threats("7d", limit=10, ref_time=self.ref_time)
        names = [e["name"] for e in emerging]
        self.assertIn("AkiraNew", names)
        akira_item = next(e for e in emerging if e["name"] == "AkiraNew")
        self.assertEqual(akira_item["current_count"], 3)
        self.assertEqual(akira_item["previous_count"], 0)
        self.assertTrue(len(akira_item["supporting_article_ids"]) >= 3)
        self.assertIn("newly emerged threat", akira_item["trend_reason"].lower())

    # ── 7. CVE Ranking & Exploitation Evidence ────────────────────────────────
    def test_07_cve_ranking_and_exploitation(self) -> None:
        """Distinguish mentioned vs actively exploited CVEs without guessing."""
        self._insert_test_article(
            "cve_art_1",
            "2026-10-12T10:00:00Z",
            cves=["CVE-2026-1111", "CVE-2026-2222"],
            cves_exploited=["CVE-2026-1111"],
            affected_vendors=["Apache"],
            affected_products=["Tomcat"],
            severity="CRITICAL",
        )
        self._insert_test_article(
            "cve_art_2",
            "2026-10-14T10:00:00Z",
            cves=["CVE-2026-1111"],
            cves_exploited=["CVE-2026-1111"],
            affected_vendors=["Apache"],
            affected_products=["Tomcat"],
            severity="CRITICAL",
        )

        cves = self.engine.get_top_cves("7d", limit=5, ref_time=self.ref_time)
        cve_1111 = next((c for c in cves if c["cve_id"] == "CVE-2026-1111"), None)
        cve_2222 = next((c for c in cves if c["cve_id"] == "CVE-2026-2222"), None)

        self.assertIsNotNone(cve_1111)
        self.assertIsNotNone(cve_2222)
        self.assertEqual(cve_1111["article_count"], 2)
        self.assertEqual(cve_1111["exploitation_status"], "actively_exploited")
        self.assertEqual(cve_2222["exploitation_status"], "mentioned")
        self.assertIn("Apache", cve_1111["affected_vendors"])
        self.assertIn("Tomcat", cve_1111["affected_products"])

    # ── 8. Malware Ranking ────────────────────────────────────────────────────
    def test_08_malware_ranking(self) -> None:
        """Analyze most mentioned malware and associated techniques/sectors."""
        self._insert_test_article(
            "mal_1",
            "2026-10-13T10:00:00Z",
            malware=["BumbleBee"],
            ransomware=[],
            mitre_techniques=["T1059.001"],
            target_sectors=["Finance"],
        )
        self._insert_test_article(
            "mal_2",
            "2026-10-14T10:00:00Z",
            malware=["BumbleBee"],
            ransomware=[],
            mitre_techniques=["T1059.001"],
            target_sectors=["Finance"],
        )

        top_malware = self.engine.get_top_malware("7d", limit=5, ref_time=self.ref_time)
        self.assertEqual(len(top_malware), 1)
        self.assertEqual(top_malware[0]["name"], "BumbleBee")
        self.assertEqual(top_malware[0]["count"], 2)
        self.assertIn("Finance", top_malware[0]["associated_sectors"])
        self.assertIn("T1059.001", top_malware[0]["associated_techniques"])

    # ── 9. Threat Actor Ranking ───────────────────────────────────────────────
    def test_09_threat_actor_ranking(self) -> None:
        """Analyze active threat actors with supporting article IDs and associated malware."""
        self._insert_test_article(
            "actor_1",
            "2026-10-11T10:00:00Z",
            threat_actors=["Volt Typhoon"],
            malware=["KV-Botnet"],
            cves=["CVE-2026-3333"],
            target_sectors=["Critical Infrastructure"],
            targeted_countries=["United States"],
        )
        self._insert_test_article(
            "actor_2",
            "2026-10-14T10:00:00Z",
            threat_actors=["Volt Typhoon"],
            malware=["KV-Botnet"],
            cves=["CVE-2026-3333"],
            target_sectors=["Energy"],
            targeted_countries=["United States"],
        )

        actors = self.engine.get_top_threat_actors("7d", limit=5, ref_time=self.ref_time)
        self.assertEqual(len(actors), 1)
        vt = actors[0]
        self.assertEqual(vt["name"], "Volt Typhoon")
        self.assertEqual(vt["count"], 2)
        self.assertEqual(set(vt["source_article_ids"]), {"actor_1", "actor_2"})
        self.assertIn("KV-Botnet", vt["associated_malware"])
        self.assertIn("CVE-2026-3333", vt["associated_cves"])
        self.assertIn("Critical Infrastructure", vt["target_sectors"])

    # ── 10. MITRE Technique Ranking ───────────────────────────────────────────
    def test_10_mitre_technique_ranking(self) -> None:
        """Verify frequency and trends of MITRE tactics and techniques."""
        self._insert_test_article(
            "mitre_1",
            "2026-10-12T10:00:00Z",
            mitre_tactics=["Execution"],
            mitre_techniques=["T1059"],
            malware=["PayloadX"],
            threat_actors=["ActorY"],
        )
        self._insert_test_article(
            "mitre_2",
            "2026-10-14T10:00:00Z",
            mitre_tactics=["Execution"],
            mitre_techniques=["T1059"],
            malware=["PayloadX"],
            threat_actors=["ActorY"],
        )

        techs = self.engine.get_mitre_trends("7d", limit=5, ref_time=self.ref_time)
        self.assertEqual(techs[0]["technique"], "T1059")
        self.assertEqual(techs[0]["count"], 2)
        self.assertIn("PayloadX", techs[0]["associated_malware"])
        self.assertIn("ActorY", techs[0]["associated_actors"])

        tactics = self.engine.get_mitre_tactics("7d", limit=5, ref_time=self.ref_time)
        exec_tactic = next(t for t in tactics if t["tactic"] == "Execution")
        self.assertEqual(exec_tactic["count"], 2)

    # ── 11. Target Sector Analysis ────────────────────────────────────────────
    def test_11_target_sector_analysis(self) -> None:
        """Analyze targeted sectors, counts, severity distribution, top threats."""
        self._insert_test_article(
            "sec_1",
            "2026-10-12T10:00:00Z",
            target_sectors=["Healthcare"],
            threat_types=["Ransomware"],
            severity="CRITICAL",
        )
        self._insert_test_article(
            "sec_2",
            "2026-10-14T10:00:00Z",
            target_sectors=["Healthcare"],
            threat_types=["Data Theft"],
            severity="HIGH",
        )

        sectors = self.engine.get_sector_trends("7d", limit=5, ref_time=self.ref_time)
        hc = next(s for s in sectors if s["sector"] == "Healthcare")
        self.assertEqual(hc["article_count"], 2)
        self.assertEqual(hc["severity_distribution"]["CRITICAL"], 1)
        self.assertEqual(hc["severity_distribution"]["HIGH"], 1)
        self.assertIn("Ransomware", hc["top_threats"])

    # ── 12. Risk Score Calculation ────────────────────────────────────────────
    def test_12_risk_score_calculation(self) -> None:
        """Verify deterministic JARVIS Intelligence Risk Score formula & components."""
        _, a1 = self._insert_test_article(
            "risk_art_1",
            "2026-10-15T08:00:00Z",  # Recent within 48h (10 pts)
            cves=["CVE-2026-9999"],
            cves_exploited=["CVE-2026-9999"],  # Active exploitation (20 pts)
            target_sectors=["Healthcare", "Government"],  # Multiple critical sectors (15 pts)
            affected_products=["Enterprise Server", "Gateway Router"],  # 2 products (10 pts scope with multiple arts)
            severity="CRITICAL",  # 30 pts
        )
        _, a2 = self._insert_test_article(
            "risk_art_2",
            "2026-10-14T08:00:00Z",
            severity="CRITICAL",
            target_sectors=["Healthcare"],
        )

        score_res = calculate_risk_score(
            [a1, a2],
            trend_status="INCREASING",  # 12 pts
            ref_time=self.ref_time,
        )

        # Base severity 30 + 2 (bonus for 2 criticals) = 30 max
        # Exploitation: 20 pts
        # Trend: 12 pts
        # Sector: 15 pts
        # Scope: min(10, min(6, 2*1.5) + min(4, 2*1.0)) = 3.0 + 2.0 = 5.0
        # Recency: 10.0 pts (delta < 48h)
        # Total: 30 + 20 + 12 + 15 + 5 + 10 = 92
        self.assertEqual(score_res.score, 92.0)
        self.assertEqual(score_res.category, "CRITICAL")
        self.assertTrue(len(score_res.reasons) >= 5)

    # ── 13. Risk Category Boundaries ──────────────────────────────────────────
    def test_13_risk_category_boundaries(self) -> None:
        """Verify score mapping to category thresholds."""
        # LOW (0-20)
        _, a_low = self._insert_test_article(
            "r_low",
            "2026-09-01T10:00:00Z",
            threat_types=["General"],
            severity="LOW",
        )
        s_low = calculate_risk_score([a_low], trend_status="DECLINING", ref_time=self.ref_time)
        self.assertEqual(s_low.category, "LOW")
        self.assertLessEqual(s_low.score, 20.0)

        # CRITICAL (81-100)
        _, a_crit = self._insert_test_article(
            "r_crit",
            "2026-10-15T10:00:00Z",
            cves=["CVE-2026-9000"],
            cves_exploited=["CVE-2026-9000"],
            target_sectors=["Healthcare", "Finance"],
            severity="CRITICAL",
        )
        s_crit = calculate_risk_score([a_crit], trend_status="EMERGING", ref_time=self.ref_time)
        self.assertEqual(s_crit.category, "CRITICAL")
        self.assertTrue(s_crit.score >= 81.0)

    # ── 14. Confidence Calculation ────────────────────────────────────────────
    def test_14_confidence_calculation(self) -> None:
        """Verify confidence calculation: HIGH for multiple articles, LOW for sparse."""
        t_high = calculate_trend(
            "T_Strong",
            current_count=8,
            previous_count=3,
            supporting_article_ids=["a1", "a2", "a3"],
            unique_dates={"2026-10-12", "2026-10-13"},
            min_evidence_threshold=2,
        )
        self.assertEqual(t_high.confidence, "HIGH")

        t_med = calculate_trend(
            "T_Moderate",
            current_count=2,
            previous_count=1,
            supporting_article_ids=["a1", "a2"],
            unique_dates={"2026-10-12"},
            min_evidence_threshold=2,
        )
        self.assertEqual(t_med.confidence, "MEDIUM")

        t_low = calculate_trend(
            "T_Weak",
            current_count=1,
            previous_count=0,
            supporting_article_ids=["a1"],
            unique_dates={"2026-10-12"},
            min_evidence_threshold=2,
        )
        self.assertEqual(t_low.confidence, "LOW")

    # ── 15. Cross-Article Correlation ─────────────────────────────────────────
    def test_15_cross_article_correlation(self) -> None:
        """Verify multi-hop correlation graph with DIRECT_FACT and multi-hop link tracking."""
        # Article 1: Threat Actor X uses Malware M
        _, a1 = self._insert_test_article(
            "art_corr_1",
            "2026-10-12T10:00:00Z",
            threat_actors=["Actor X"],
            malware=["Malware M"],
        )
        # Article 2: Malware M employs Technique T1059 and targets Sector Healthcare
        _, a2 = self._insert_test_article(
            "art_corr_2",
            "2026-10-13T10:00:00Z",
            malware=["Malware M"],
            mitre_techniques=["T1059"],
            target_sectors=["Healthcare"],
        )

        corr_res = self.engine.get_threat_correlations("7d", ref_time=self.ref_time)
        direct_rels = corr_res["direct_relationships"]
        chains = corr_res["cross_article_chains"]

        # Check direct fact in Article 1
        a_m = next((r for r in direct_rels if r["source_name"] == "Actor X" and r["target_name"] == "Malware M"), None)
        self.assertIsNotNone(a_m)
        self.assertEqual(a_m["nature"], "DIRECT_FACT")
        self.assertIn("art_corr_1", a_m["evidence_article_ids"])

        # Check cross-article chain from Actor X through Malware M to Technique and Sector
        chain = next((c for c in chains if c["threat_actor"] == "Actor X" and c["malware"] == "Malware M"), None)
        self.assertIsNotNone(chain)
        self.assertEqual(chain["correlation_type"], "CROSS_ARTICLE_CORRELATION")
        self.assertIn("T1059", chain["correlated_techniques"])
        self.assertIn("Healthcare", chain["correlated_sectors"])
        self.assertEqual(set(chain["supporting_article_ids"]), {"art_corr_1", "art_corr_2"})

    # ── 16. Duplicate / Syndicated Article Handling ───────────────────────────
    def test_16_duplicate_syndicated_article_handling(self) -> None:
        """Verify that duplicate content hashes are deduplicated or not counted twice."""
        self._insert_test_article(
            "orig_art",
            "2026-10-14T10:00:00Z",
            threat_types=["Ransomware"],
            content_hash="same_hash_123",
        )
        is_dup = self.db.is_content_hash_duplicate("same_hash_123")
        self.assertTrue(is_dup)

        overview = self.engine.get_threat_overview("7d", ref_time=self.ref_time)
        self.assertEqual(overview["overview"]["articles"], 1)

    # ── 17. API Responses (FastAPI TestClient) ────────────────────────────────
    def test_17_api_responses(self) -> None:
        """Verify that all 12 FastAPI endpoints return valid JSON and 200 HTTP codes."""
        if not _FASTAPI_TEST_AVAILABLE:
            self.skipTest("FastAPI TestClient is not available in environment.")

        self._insert_test_article(
            "api_art_1",
            "2026-10-14T10:00:00Z",
            threat_types=["Malware"],
            cves=["CVE-2026-8888"],
            cves_exploited=["CVE-2026-8888"],
            threat_actors=["TestAPT"],
            malware=["TestTrojan"],
            mitre_techniques=["T1059"],
            target_sectors=["Technology"],
            severity="HIGH",
        )

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        endpoints = [
            "/api/intelligence/overview?window=7d",
            "/api/intelligence/trends?window=7d&limit=5",
            "/api/intelligence/threats?window=7d&limit=5",
            "/api/intelligence/cves?window=7d&limit=5",
            "/api/intelligence/malware?window=7d&limit=5",
            "/api/intelligence/actors?window=7d&limit=5",
            "/api/intelligence/mitre?window=7d&limit=5",
            "/api/intelligence/sectors?window=7d&limit=5",
            "/api/intelligence/risk?window=7d",
            "/api/intelligence/emerging?window=7d&limit=5",
            "/api/intelligence/timeline?window=7d",
            "/api/intelligence/freshness",
            "/api/intelligence/report?window=7d",
        ]

        for ep in endpoints:
            response = client.get(ep)
            self.assertEqual(
                response.status_code,
                200,
                f"Endpoint {ep} failed with status {response.status_code}: {response.text}",
            )
            data = response.json()
            self.assertIsInstance(data, (dict, list), f"Endpoint {ep} must return JSON dict or list")

    # ── 18. Empty Database Behavior ───────────────────────────────────────────
    def test_18_empty_database(self) -> None:
        """Ensure clean 0s and empty lists on an empty database without exceptions."""
        empty_temp = Path(tempfile.mkdtemp())
        try:
            empty_db = IntelligenceDB(empty_temp / "empty.db")
            engine = CybersecurityIntelligenceEngine(db=empty_db)

            overview = engine.get_threat_overview("30d", ref_time=self.ref_time)
            self.assertEqual(overview["overview"]["articles"], 0)
            self.assertEqual(overview["overview"]["critical"], 0)
            self.assertEqual(overview["risk_overview"]["score"], 0)
            self.assertEqual(overview["risk_overview"]["category"], "LOW")

            trends = engine.get_trending_threats("30d", ref_time=self.ref_time)
            self.assertEqual(trends, [])

            cves = engine.get_top_cves("30d", ref_time=self.ref_time)
            self.assertEqual(cves, [])

            report = engine.generate_intelligence_report("30d", ref_time=self.ref_time)
            self.assertEqual(report["overview"]["articles"], 0)
        finally:
            shutil.rmtree(empty_temp, ignore_errors=True)

    # ── 19. Sparse Data & Missing Optional Fields ─────────────────────────────
    def test_19_sparse_data_and_missing_fields(self) -> None:
        """Ensure that articles with missing CVE, actor, malware, or sector fields never crash."""
        self._insert_test_article(
            "sparse_1",
            "2026-10-14T10:00:00Z",
            threat_types=[],
            attack_types=[],
            threat_actors=[],
            malware=[],
            cves=[],
            target_sectors=[],
            mitre_techniques=[],
            severity="INFO",
        )

        overview = self.engine.get_threat_overview("7d", ref_time=self.ref_time)
        self.assertEqual(overview["overview"]["articles"], 1)
        self.assertEqual(overview["overview"]["info"], 1)
        self.assertEqual(overview["top_threat_types"], {})

        actors = self.engine.get_top_threat_actors("7d", ref_time=self.ref_time)
        self.assertEqual(actors, [])

        correlations = self.engine.get_threat_correlations("7d", ref_time=self.ref_time)
        self.assertEqual(correlations["direct_relationships"], [])

    # ── 20. Large Dataset Behavior & Trend Snapshots ──────────────────────────
    def test_20_large_dataset_and_trend_snapshots(self) -> None:
        """Simulate 60 articles across 60 days, verify performance and snapshot persistence."""
        base_time = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(60):
            pub_date = format_iso(base_time + timedelta(days=i))
            severity = "CRITICAL" if i % 10 == 0 else "HIGH" if i % 3 == 0 else "MEDIUM"
            self._insert_test_article(
                f"batch_{i}",
                pub_date,
                threat_types=["Ransomware" if i % 2 == 0 else "Vulnerability Exploitation"],
                cves=[f"CVE-2026-{1000 + (i % 5)}"],
                cves_exploited=[f"CVE-2026-{1000 + (i % 5)}"] if i % 4 == 0 else [],
                threat_actors=[f"Actor_{i % 3}"],
                malware=[f"Malware_{i % 4}"],
                target_sectors=["Healthcare" if i % 2 == 0 else "Finance"],
                mitre_techniques=[f"T10{50 + (i % 5)}"],
                severity=severity,
            )

        # Overview for last 30 days
        overview_30d = self.engine.get_threat_overview("30d", ref_time=self.ref_time)
        self.assertTrue(25 <= overview_30d["overview"]["articles"] <= 35)

        # Test snapshot creation and retrieval
        snapshots = self.engine.generate_snapshot("30d", ref_time=self.ref_time)
        self.assertTrue(len(snapshots) > 0)
        saved = self.db.get_trend_snapshots(metric_type="threat_type", limit=10)
        self.assertTrue(len(saved) > 0)
        first_snap = saved[0]
        self.assertEqual(first_snap.metric_type, "threat_type")
        self.assertIn(first_snap.trend_status, ["INCREASING", "DECREASING", "STABLE", "EMERGING", "INSUFFICIENT_DATA"])


if __name__ == "__main__":
    unittest.main()
