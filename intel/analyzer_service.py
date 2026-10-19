"""
Cybersecurity Intelligence Analyzer Service for JARVIS.

Coordinates:
STORED THN ARTICLES
        ↓
CONTENT PREPROCESSING & INJECTION SANITIZATION
        ↓
AI CYBERSECURITY EXTRACTION (LLMProvider)
        ↓
SCHEMA VALIDATION & HEURISTIC REPAIR
        ↓
STRUCTURED ARTICLE ANALYSIS
        ↓
SQLITE PERSISTENCE & ENTITY INDEXING
"""

from __future__ import annotations
import logging
import time
from typing import Any, Optional

from .config import load_cyber_config
from .db import IntelligenceDB
from .llm_provider import BaseLLMProvider, get_llm_provider
from .models import Article, ArticleAnalysis, utc_now_iso
from .preprocessor import preprocess_article
from .prompts import CYBER_ANALYST_SYSTEM_PROMPT, CYBER_EXTRACTION_PROMPT_TEMPLATE
from .validator import ValidationError, validate_and_repair_analysis

logger = logging.getLogger(__name__)


class CybersecurityAnalyzer:
    """Manages cybersecurity intelligence extraction and structured analysis."""

    def __init__(
        self,
        db: Optional[IntelligenceDB] = None,
        llm: Optional[BaseLLMProvider] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        self.config = config or load_cyber_config()
        self.db = db or IntelligenceDB(self.config["db_path"])
        self.llm = llm or get_llm_provider(self.config)
        self.version = str(self.config.get("analysis_version", "v1"))
        self.max_retries = int(self.config.get("max_retries", 3))
        self.retry_delay = float(self.config.get("retry_delay_seconds", 2.0))
        self.max_chars = int(self.config.get("max_content_chars", 12000))
        self.temperature = float(self.config.get("temperature", 0.1))

    # ── Single Article Analysis ───────────────────────────────────────────────

    def analyze_article(
        self,
        article_id: str,
        force_reprocess: bool = False,
        version: Optional[str] = None,
    ) -> ArticleAnalysis:
        """
        Analyze a single stored article by ID.
        Checks existing analysis first to prevent duplicate LLM calls unless force_reprocess is True.
        """
        ver = version or self.version
        article = self.db.get_article_by_id(article_id)
        if not article:
            raise ValueError(f"Article not found in database: {article_id}")

        # Duplicate analysis prevention
        if not force_reprocess:
            existing = self.db.get_analysis(article_id, version=ver)
            if existing and existing.analysis_status == "completed":
                logger.info("Article %s already analyzed (%s). Skipping LLM call.", article_id, ver)
                return existing

        analysis_id = f"analysis_{article_id}_{ver}"
        started_at = utc_now_iso()

        # Record processing status in database
        initial_record = ArticleAnalysis(
            analysis_id=analysis_id,
            article_id=article_id,
            analysis_version=ver,
            analysis_status="processing",
            analysis_model=self.llm.get_model_name(),
            analysis_started_at=started_at,
            title=article.title,
            source=article.source,
            url=article.url,
            published_at=article.published_at,
            category=article.category,
        )
        self.db.save_analysis(initial_record)

        # 1. Preprocess and sanitize untrusted text
        preprocessed = preprocess_article(
            article_id=article.article_id,
            title=article.title,
            content=article.content,
            summary=article.summary,
            max_chars=self.max_chars,
        )

        prompt = CYBER_EXTRACTION_PROMPT_TEMPLATE.format(
            title=article.title,
            source=article.source,
            url=article.url,
            published_at=article.published_at,
            cve_candidates=preprocessed.cve_candidates or "None detected",
            mitre_candidates=preprocessed.mitre_candidates or "None detected",
            ioc_candidates=[i["value"] for i in preprocessed.ioc_candidates] or "None detected",
            clean_content=preprocessed.clean_content,
        )

        # 2. Call LLM with controlled retries
        raw_output = ""
        last_error = ""
        repaired_data: dict[str, Any] = {}

        for attempt in range(1, self.max_retries + 1):
            try:
                raw_output = self.llm.generate(
                    prompt=prompt,
                    system=CYBER_ANALYST_SYSTEM_PROMPT,
                    temperature=self.temperature,
                )
                repaired_data, warnings = validate_and_repair_analysis(
                    raw_response=raw_output,
                    preprocessed=preprocessed,
                )
                if warnings:
                    logger.debug("Validation warnings for %s: %s", article_id, warnings)
                last_error = ""
                break  # Success
            except (ValidationError, Exception) as err:
                last_error = str(err)
                logger.warning("Attempt %d/%d for article %s failed: %s", attempt, self.max_retries, article_id, err)
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * attempt)

        # 3. Handle failure case
        if last_error:
            failed_record = ArticleAnalysis(
                analysis_id=analysis_id,
                article_id=article_id,
                analysis_version=ver,
                analysis_status="failed",
                analysis_model=self.llm.get_model_name(),
                analysis_started_at=started_at,
                analysis_completed_at=utc_now_iso(),
                analysis_error=last_error,
                title=article.title,
                source=article.source,
                url=article.url,
                published_at=article.published_at,
                raw_llm_response=raw_output,
            )
            self.db.save_analysis(failed_record)
            raise RuntimeError(f"Analysis extraction failed for {article_id} after {self.max_retries} attempts: {last_error}")

        # 4. Success: construct completed ArticleAnalysis
        completed_record = ArticleAnalysis(
            analysis_id=analysis_id,
            article_id=article_id,
            analysis_version=ver,
            analysis_status="completed",
            analysis_model=self.llm.get_model_name(),
            analysis_started_at=started_at,
            analysis_completed_at=utc_now_iso(),
            analysis_error=None,
            title=article.title,
            source=article.source,
            url=article.url,
            published_at=article.published_at,
            category=article.category,
            summary=repaired_data.get("summary", ""),
            threat_types=repaired_data.get("threat_types", []),
            attack_types=repaired_data.get("attack_types", []),
            attack_vectors=repaired_data.get("attack_vectors", []),
            threat_actors=repaired_data.get("threat_actors", []),
            threat_groups=repaired_data.get("threat_groups", []),
            malware=repaired_data.get("malware", []),
            ransomware=repaired_data.get("ransomware", []),
            vulnerabilities=repaired_data.get("vulnerabilities", []),
            cves=repaired_data.get("cves", []),
            cvss=repaired_data.get("cvss", {}),
            affected_products=repaired_data.get("affected_products", []),
            affected_vendors=repaired_data.get("affected_vendors", []),
            affected_versions=repaired_data.get("affected_versions", []),
            target_sectors=repaired_data.get("target_sectors", []),
            target_countries=repaired_data.get("target_countries", []),
            target_organizations=repaired_data.get("target_organizations", []),
            technical_explanation=repaired_data.get("technical_explanation", {}),
            mitre_attack=repaired_data.get("mitre_attack", []),
            iocs=repaired_data.get("iocs", []),
            tools=repaired_data.get("tools", []),
            technologies=repaired_data.get("technologies", []),
            impact=repaired_data.get("impact", {}),
            detection_methods=repaired_data.get("detection_methods", []),
            mitigation=repaired_data.get("mitigation", []),
            remediation=repaired_data.get("remediation", []),
            security_recommendations=repaired_data.get("security_recommendations", []),
            severity=repaired_data.get("severity", "MEDIUM"),
            severity_reason=repaired_data.get("severity_reason", ""),
            confidence=repaired_data.get("confidence", "HIGH"),
            facts=repaired_data.get("facts", []),
            inferences=repaired_data.get("inferences", []),
            raw_llm_response=raw_output,
        )

        self.db.save_analysis(completed_record)
        return completed_record

    # ── Batch & Resumable Analysis ────────────────────────────────────────────

    def analyze_pending_articles(
        self,
        limit: int = 10,
        version: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Batch analysis mechanism for unprocessed articles.
        Resumable: only fetches articles that are pending/unprocessed.
        Does not load thousands of articles into memory at once.
        """
        ver = version or self.version
        pending = self.db.get_pending_analysis_articles(limit=limit, version=ver)

        results: dict[str, Any] = {
            "requested_limit": limit,
            "found_pending": len(pending),
            "processed": 0,
            "succeeded": 0,
            "failed": 0,
            "analyses": [],
            "errors": {},
        }

        for article in pending:
            results["processed"] += 1
            try:
                analysis = self.analyze_article(article.article_id, version=ver)
                results["succeeded"] += 1
                results["analyses"].append({
                    "article_id": analysis.article_id,
                    "title": analysis.title,
                    "severity": analysis.severity,
                    "cves": analysis.cves,
                    "threat_actors": analysis.threat_actors,
                })
            except Exception as e:
                results["failed"] += 1
                results["errors"][article.article_id] = str(e)
                logger.error("Failed batch analysis for %s: %s", article.article_id, e)

        return results

    # ── Query & Reporting Interfaces ──────────────────────────────────────────

    def get_article_analysis(
        self,
        article_id: str,
        version: Optional[str] = None,
    ) -> Optional[ArticleAnalysis]:
        """Fetch analysis for an article by ID."""
        ver = version or self.version
        return self.db.get_analysis(article_id, version=ver)

    def get_analysis_status(
        self,
        article_id: str,
        version: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return status information for an article's analysis."""
        ver = version or self.version
        analysis = self.db.get_analysis(article_id, version=ver)
        if analysis:
            return {
                "article_id": article_id,
                "version": ver,
                "status": analysis.analysis_status,
                "model": analysis.analysis_model,
                "completed_at": analysis.analysis_completed_at,
                "error": analysis.analysis_error,
                "severity": analysis.severity,
            }

        # Check if article itself exists
        article = self.db.get_article_by_id(article_id)
        if not article:
            return {"article_id": article_id, "status": "not_found"}

        return {"article_id": article_id, "version": ver, "status": "unprocessed"}

    def reprocess_article(self, article_id: str, version: str = "v2") -> ArticleAnalysis:
        """Reprocess an article with a new or incremented schema version."""
        return self.analyze_article(article_id, force_reprocess=True, version=version)

    def get_intelligence_metrics(self) -> dict[str, Any]:
        """Aggregate cross-article intelligence metrics."""
        return self.db.get_intelligence_metrics()


def get_analyzer(config: Optional[dict[str, Any]] = None) -> CybersecurityAnalyzer:
    """Convenience factory function for obtaining CybersecurityAnalyzer."""
    return CybersecurityAnalyzer(config=config)
