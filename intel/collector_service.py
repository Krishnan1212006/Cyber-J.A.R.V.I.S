"""
Collector Orchestrator Service for JARVIS Cybersecurity News Intelligence Engine.
Coordinates multi-source data connectors, multi-tier deduplication, persistent storage,
run logging, per-source health monitoring, and resumable checkpoints.

Supports:
1. Hacklido (https://hacklido.com/)
2. BleepingComputer (https://www.bleepingcomputer.com/)
3. The Hacker News (https://thehackernews.com/)
4. Cybersecurity News (https://cybersecuritynews.com/)
"""

from __future__ import annotations
import logging
from typing import Any, Optional

from .config import load_cyber_config
from .connectors import (
    BaseCyberNewsConnector,
    HacklidoConnector,
    BleepingComputerConnector,
    TheHackerNewsConnector,
    CybersecurityNewsConnector,
)
from .db import IntelligenceDB
from .models import (
    Article,
    CollectionRun,
    CollectionCheckpoint,
    ConnectorHealth,
    SOURCE_THEHACKERNEWS,
    SOURCE_HACKLIDO,
    SOURCE_BLEEPINGCOMPUTER,
    SOURCE_CYBERSECURITYNEWS,
    ALL_CYBER_SOURCES,
    utc_now_iso,
)
from .security import compute_content_hash
from .thn_provider import BaseDataProvider, THNDataProvider

logger = logging.getLogger("intel.collector_service")


class CyberNewsCollector:
    """
    Multi-source orchestrator for cybersecurity news collection.
    Coordinates Hacklido, BleepingComputer, The Hacker News, and Cybersecurity News.
    Ensures safe handling of untrusted content, robust deduplication,
    detailed per-source run logging, source health telemetry, and resumable historical ingestion.
    """

    def __init__(
        self,
        db: Optional[IntelligenceDB] = None,
        connectors: Optional[dict[str, BaseDataProvider]] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        self.config = config or load_cyber_config()
        self.db = db or IntelligenceDB(self.config["db_path"])
        if connectors:
            self.connectors = connectors
        else:
            self.connectors = {
                SOURCE_THEHACKERNEWS: TheHackerNewsConnector(self.config),
                SOURCE_HACKLIDO: HacklidoConnector(self.config),
                SOURCE_BLEEPINGCOMPUTER: BleepingComputerConnector(self.config),
                SOURCE_CYBERSECURITYNEWS: CybersecurityNewsConnector(self.config),
            }

    # ── Source Health Telemetry ────────────────────────────────────────────────

    def update_source_health(
        self,
        source: str,
        status: str,
        records_processed: int = 0,
        last_error: Optional[str] = None,
        data_freshness: Optional[str] = None,
    ) -> None:
        """Record health and status metrics for a specific source connector."""
        connector_id = f"{source}_connector"
        name_map = {
            SOURCE_THEHACKERNEWS: "The Hacker News Connector",
            SOURCE_HACKLIDO: "Hacklido Connector",
            SOURCE_BLEEPINGCOMPUTER: "BleepingComputer Connector",
            SOURCE_CYBERSECURITYNEWS: "Cybersecurity News Connector",
        }
        connector_name = name_map.get(source, f"{source.title()} Connector")
        now = utc_now_iso()

        existing = self.db.get_connector_status(connector_id)
        last_success = now if status == "CONNECTED" else (existing.last_successful_run_at if existing else None)
        total_processed = (existing.records_processed if existing else 0) + records_processed

        health = ConnectorHealth(
            connector_id=connector_id,
            connector_name=connector_name,
            status=status,
            last_run_at=now,
            last_successful_run_at=last_success,
            records_processed=total_processed,
            last_error=last_error,
            data_freshness=data_freshness or now,
            config_summary={"source": source, "active": True},
            updated_at=now,
        )
        self.db.record_connector_status(health)

    def get_source_health(self, source: Optional[str] = None) -> list[ConnectorHealth]:
        """Fetch health telemetry for one or all registered source connectors."""
        if source:
            connector_id = f"{source}_connector"
            status = self.db.get_connector_status(connector_id)
            return [status] if status else []
        return self.db.get_all_connector_statuses()

    # ── Duplicate Checking ────────────────────────────────────────────────────

    def check_duplicate(
        self,
        url: str,
        content_hash: Optional[str] = None,
        article_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Multi-tier deduplication check against persistent database."""
        return self.db.check_duplicate(
            url=url,
            content_hash=content_hash,
            article_id=article_id,
        )

    # ── Single-Source Collection ───────────────────────────────────────────────

    def collect_source_latest(
        self,
        source: str,
        limit: int = 20,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """
        Ingest the latest articles from a single designated source.
        Returns execution statistics:
            {
                "source": str,
                "discovered": int,
                "new_articles": int,
                "duplicates": int,
                "failed": int,
                "run_id": str,
                "status": str,
            }
        """
        if source not in self.connectors:
            raise ValueError(f"Unknown source connector '{source}'. Available: {list(self.connectors.keys())}")

        provider = self.connectors[source]
        run_id = self.db.record_run_start(mode="latest", source=source)
        discovered_count = 0
        new_count = 0
        duplicate_count = 0
        failed_count = 0
        error_messages: list[str] = []

        try:
            raw_entries = provider.collect_latest(limit=limit)
            discovered_count = len(raw_entries)

            for raw_entry in raw_entries:
                try:
                    article = provider.normalize_article(raw_entry)
                    if not article:
                        failed_count += 1
                        error_messages.append("Article normalization returned None (missing title/URL/date)")
                        continue

                    # Multi-tier deduplication check
                    is_dup, reason = self.db.check_duplicate(
                        url=article.url,
                        content_hash=article.content_hash,
                        article_id=article.article_id,
                    )
                    if is_dup:
                        duplicate_count += 1
                        logger.debug(f"[{source}] Skipping duplicate ({reason}): {article.url}")
                        continue

                    # If new and full body requested, try fetching full article if not yet present
                    if fetch_full_body and len(article.content) < 300 and hasattr(provider, "fetch_article"):
                        try:
                            full_info = provider.fetch_article(article.url)
                            if isinstance(full_info, dict):
                                if isinstance(full_info.get("content"), str) and full_info["content"].strip():
                                    article.content = full_info["content"]
                                    article.content_hash = compute_content_hash(article.content)
                                if isinstance(full_info.get("accessible"), str):
                                    article.content_accessible = full_info["accessible"]
                                if isinstance(full_info.get("tags"), list):
                                    combined = set(article.tags + [str(t) for t in full_info["tags"]])
                                    article.tags = sorted(list(combined))
                        except Exception as fetch_err:
                            logger.warning(
                                f"[{source}] Failed to fetch full HTML body for {article.url}: {fetch_err}. Using available content."
                            )

                    # Persist article in database
                    inserted = self.db.insert_article(article)
                    if inserted:
                        new_count += 1
                        logger.info(f"[{source}] Ingested new article: [{article.article_id}] {article.title}")
                    else:
                        duplicate_count += 1

                except Exception as entry_err:
                    failed_count += 1
                    error_messages.append(f"Entry error: {entry_err}")
                    logger.error(f"[{source}] Error processing article entry: {entry_err}", exc_info=True)

            status = "completed" if discovered_count > 0 or not error_messages else "failed"
            health_status = "CONNECTED" if status == "completed" else "DEGRADED"
        except Exception as run_err:
            status = "failed"
            health_status = "ERROR"
            error_messages.append(f"Fatal run error: {run_err}")
            logger.error(f"[{source}] Latest collection run failed: {run_err}", exc_info=True)

        summary_text = "; ".join(error_messages[:5]) if error_messages else None
        run_record = CollectionRun(
            run_id=run_id,
            completed_at=utc_now_iso(),
            source=source,
            mode="latest",
            discovered_count=discovered_count,
            new_count=new_count,
            duplicate_count=duplicate_count,
            failed_count=failed_count,
            status=status,
            error_summary=summary_text,
            metadata={"requested_limit": limit},
        )
        self.db.complete_run(run_record)

        # Update per-source health telemetry
        self.update_source_health(
            source=source,
            status=health_status,
            records_processed=new_count,
            last_error=summary_text,
        )

        return {
            "source": source,
            "discovered": discovered_count,
            "new_articles": new_count,
            "duplicates": duplicate_count,
            "failed": failed_count,
            "run_id": run_id,
            "status": status,
        }

    # ── Multi-Source Collect Latest ───────────────────────────────────────────

    def collect_latest(
        self,
        source: Optional[str] = None,
        limit: int = 20,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """
        Ingest the latest articles from all sources or a specific source.
        Returns execution statistics with per-source breakdowns:
            {
                "sources": {
                    "thehackernews": {...},
                    "hacklido": {...},
                    "bleepingcomputer": {...},
                    "cybersecuritynews": {...},
                },
                "total_discovered": int,
                "total_new": int,
                "total_duplicates": int,
                "total_failed": int,
            }
        """
        targets = [source] if source and source != "all" else ALL_CYBER_SOURCES
        source_results: dict[str, Any] = {}
        total_discovered = 0
        total_new = 0
        total_duplicates = 0
        total_failed = 0

        for s in targets:
            if s in self.connectors:
                try:
                    res = self.collect_source_latest(source=s, limit=limit, fetch_full_body=fetch_full_body)
                    source_results[s] = res
                    total_discovered += res.get("discovered", 0)
                    total_new += res.get("new_articles", 0)
                    total_duplicates += res.get("duplicates", 0)
                    total_failed += res.get("failed", 0)
                except Exception as e:
                    logger.error(f"Error in multi-source collection for {s}: {e}")
                    source_results[s] = {
                        "source": s,
                        "discovered": 0,
                        "new_articles": 0,
                        "duplicates": 0,
                        "failed": 1,
                        "status": "failed",
                        "error": str(e),
                    }
                    total_failed += 1

        return {
            "sources": source_results,
            "total_discovered": total_discovered,
            "total_new": total_new,
            "total_duplicates": total_duplicates,
            "total_failed": total_failed,
            # Backward-compatibility keys for callers expecting flat single-source dict
            "discovered": total_discovered,
            "new_articles": total_new,
            "duplicates": total_duplicates,
            "failed": total_failed,
        }

    # ── Historical Collection with Resumable Checkpoints ──────────────────────

    def collect_source_historical(
        self,
        source: str,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        resume: bool = True,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """Controlled, resumable historical ingestion for a single designated source."""
        if source not in self.connectors:
            raise ValueError(f"Unknown source connector '{source}'")

        provider = self.connectors[source]
        job_name = f"{source}_historical_{start_date}_{end_date}"
        run_id = self.db.record_run_start(mode="historical", source=source)

        discovered_count = 0
        new_count = 0
        duplicate_count = 0
        failed_count = 0
        error_messages: list[str] = []

        start_offset = 1 if source == SOURCE_THEHACKERNEWS else 0
        if resume:
            checkpoint = self.db.get_checkpoint(job_name)
            if checkpoint and checkpoint.cursor_offset > 0:
                start_offset = checkpoint.cursor_offset
                logger.info(f"[{source}] Resuming historical collection from checkpoint offset {start_offset}")

        try:
            batch_generator = provider.collect_historical(
                start_date=start_date,
                end_date=end_date,
                max_articles=max_articles,
                start_offset=start_offset,
            )

            current_offset = start_offset
            last_article_id = None
            last_pub_date = None

            for batch in batch_generator:
                discovered_count += len(batch)

                for raw_entry in batch:
                    try:
                        article = provider.normalize_article(raw_entry)
                        if not article:
                            failed_count += 1
                            continue

                        last_article_id = article.article_id
                        last_pub_date = article.published_at

                        is_dup, _ = self.db.check_duplicate(
                            url=article.url,
                            content_hash=article.content_hash,
                            article_id=article.article_id,
                        )
                        if is_dup:
                            duplicate_count += 1
                            continue

                        if fetch_full_body and len(article.content) < 300 and hasattr(provider, "fetch_article"):
                            try:
                                full_info = provider.fetch_article(article.url)
                                if isinstance(full_info, dict):
                                    if isinstance(full_info.get("content"), str) and full_info["content"].strip():
                                        article.content = full_info["content"]
                                        article.content_hash = compute_content_hash(article.content)
                                    if isinstance(full_info.get("accessible"), str):
                                        article.content_accessible = full_info["accessible"]
                                    if isinstance(full_info.get("tags"), list):
                                        combined = set(article.tags + [str(t) for t in full_info["tags"]])
                                        article.tags = sorted(list(combined))
                            except Exception as fetch_err:
                                logger.warning(f"[{source}] Could not fetch full body for {article.url}: {fetch_err}")

                        inserted = self.db.insert_article(article)
                        if inserted:
                            new_count += 1
                        else:
                            duplicate_count += 1

                    except Exception as entry_err:
                        failed_count += 1
                        error_messages.append(f"Entry error: {entry_err}")

                # Update checkpoint after each batch
                current_offset += len(batch)
                self.db.save_checkpoint(
                    CollectionCheckpoint(
                        job_name=job_name,
                        last_run_at=utc_now_iso(),
                        last_article_id=last_article_id,
                        last_published_at=last_pub_date,
                        cursor_offset=current_offset,
                        articles_collected=new_count,
                        status="running",
                    )
                )

            status = "completed"
            self.db.save_checkpoint(
                CollectionCheckpoint(
                    job_name=job_name,
                    last_run_at=utc_now_iso(),
                    last_article_id=last_article_id,
                    last_published_at=last_pub_date,
                    cursor_offset=current_offset,
                    articles_collected=new_count,
                    status="idle",
                )
            )
            health_status = "CONNECTED"
        except Exception as run_err:
            status = "failed"
            health_status = "ERROR"
            error_messages.append(f"Historical run error: {run_err}")
            logger.error(f"[{source}] Historical collection run failed: {run_err}", exc_info=True)

        summary_text = "; ".join(error_messages[:5]) if error_messages else None
        run_record = CollectionRun(
            run_id=run_id,
            completed_at=utc_now_iso(),
            source=source,
            mode="historical",
            discovered_count=discovered_count,
            new_count=new_count,
            duplicate_count=duplicate_count,
            failed_count=failed_count,
            status=status,
            error_summary=summary_text,
            metadata={
                "start_date": start_date,
                "end_date": end_date,
                "max_articles": max_articles,
            },
        )
        self.db.complete_run(run_record)

        self.update_source_health(
            source=source,
            status=health_status,
            records_processed=new_count,
            last_error=summary_text,
        )

        return {
            "source": source,
            "discovered": discovered_count,
            "new_articles": new_count,
            "duplicates": duplicate_count,
            "failed": failed_count,
            "run_id": run_id,
            "status": status,
        }

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        source: Optional[str] = None,
        max_articles: Optional[int] = None,
        resume: bool = True,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """
        Controlled, resumable historical ingestion across all or a specific source.
        """
        targets = [source] if source and source != "all" else ALL_CYBER_SOURCES
        source_results: dict[str, Any] = {}
        total_discovered = 0
        total_new = 0
        total_duplicates = 0
        total_failed = 0

        for s in targets:
            if s in self.connectors:
                try:
                    res = self.collect_source_historical(
                        source=s,
                        start_date=start_date,
                        end_date=end_date,
                        max_articles=max_articles,
                        resume=resume,
                        fetch_full_body=fetch_full_body,
                    )
                    source_results[s] = res
                    total_discovered += res.get("discovered", 0)
                    total_new += res.get("new_articles", 0)
                    total_duplicates += res.get("duplicates", 0)
                    total_failed += res.get("failed", 0)
                except Exception as e:
                    logger.error(f"Error in historical collection for {s}: {e}")
                    source_results[s] = {
                        "source": s,
                        "discovered": 0,
                        "new_articles": 0,
                        "duplicates": 0,
                        "failed": 1,
                        "status": "failed",
                        "error": str(e),
                    }
                    total_failed += 1

        return {
            "sources": source_results,
            "total_discovered": total_discovered,
            "total_new": total_new,
            "total_duplicates": total_duplicates,
            "total_failed": total_failed,
            "discovered": total_discovered,
            "new_articles": total_new,
            "duplicates": total_duplicates,
            "failed": total_failed,
        }

    # ── Retry Failed Collection Jobs ──────────────────────────────────────────

    def retry_failed_jobs(self) -> dict[str, Any]:
        """Detect connectors reporting ERROR/DEGRADED status and retry collection."""
        retried: dict[str, Any] = {}
        statuses = self.db.get_all_connector_statuses()
        error_sources = [
            h.connector_id.replace("_connector", "")
            for h in statuses
            if h.status in ("ERROR", "DEGRADED")
        ]

        if not error_sources:
            return {"retried": 0, "results": {}, "message": "All connectors are healthy."}

        for source in error_sources:
            if source in self.connectors:
                try:
                    res = self.collect_source_latest(source=source, limit=10)
                    retried[source] = res
                except Exception as e:
                    retried[source] = {"status": "retry_failed", "error": str(e)}

        return {"retried": len(retried), "results": retried}


# ── Backward Compatibility THNCollectorService ────────────────────────────────

class THNCollectorService:
    """
    Backward-compatible orchestrator for The Hacker News ingestion.
    Preserves existing API signatures for callers and tests while delegating
    to the underlying provider.
    """

    def __init__(
        self,
        db: Optional[IntelligenceDB] = None,
        provider: Optional[BaseDataProvider] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        self.config = config or load_cyber_config()
        self.db = db or IntelligenceDB(self.config["db_path"])
        self.provider = provider or TheHackerNewsConnector(self.config)
        self._collector = CyberNewsCollector(
            db=self.db,
            connectors={SOURCE_THEHACKERNEWS: self.provider},
            config=self.config,
        )

    def collect_latest(
        self,
        limit: int = 20,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """Ingest the latest articles from The Hacker News."""
        res = self._collector.collect_source_latest(
            source=SOURCE_THEHACKERNEWS,
            limit=limit,
            fetch_full_body=fetch_full_body,
        )
        return {
            "discovered": res.get("discovered", 0),
            "new_articles": res.get("new_articles", 0),
            "duplicates": res.get("duplicates", 0),
            "failed": res.get("failed", 0),
            "run_id": res.get("run_id", ""),
        }

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        resume: bool = True,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """Controlled, resumable historical ingestion across a specified date range."""
        res = self._collector.collect_source_historical(
            source=SOURCE_THEHACKERNEWS,
            start_date=start_date,
            end_date=end_date,
            max_articles=max_articles,
            resume=resume,
            fetch_full_body=fetch_full_body,
        )
        return {
            "discovered": res.get("discovered", 0),
            "new_articles": res.get("new_articles", 0),
            "duplicates": res.get("duplicates", 0),
            "failed": res.get("failed", 0),
            "run_id": res.get("run_id", ""),
        }
