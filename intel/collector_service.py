"""
Collector Orchestrator Service.
Coordinates data providers, multi-tier deduplication, persistent storage,
run logging, and resumable checkpoints.
"""

from __future__ import annotations
import logging
from typing import Any, Optional

from .config import load_cyber_config
from .db import IntelligenceDB
from .models import Article, CollectionRun, CollectionCheckpoint, utc_now_iso
from .security import compute_content_hash
from .thn_provider import BaseDataProvider, THNDataProvider

logger = logging.getLogger("intel.collector_service")


class THNCollectorService:
    """
    High-level orchestrator for The Hacker News ingestion.
    Ensures safe handling of untrusted content, robust deduplication,
    detailed run logging, and resumable historical backfills.
    """

    def __init__(
        self,
        db: Optional[IntelligenceDB] = None,
        provider: Optional[BaseDataProvider] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        self.config = config or load_cyber_config()
        self.db = db or IntelligenceDB(self.config["db_path"])
        self.provider = provider or THNDataProvider(self.config)

    # ── Collect Latest ─────────────────────────────────────────────────────────

    def collect_latest(
        self,
        limit: int = 20,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """
        Ingest the latest articles from The Hacker News.
        Returns execution statistics:
            {
                "discovered": int,
                "new_articles": int,
                "duplicates": int,
                "failed": int,
                "run_id": str,
            }
        """
        run_id = self.db.record_run_start(mode="latest", source="thehackernews")
        discovered_count = 0
        new_count = 0
        duplicate_count = 0
        failed_count = 0
        error_messages: list[str] = []

        try:
            raw_entries = self.provider.collect_latest(limit=limit)
            discovered_count = len(raw_entries)

            for raw_entry in raw_entries:
                try:
                    article = self.provider.normalize_article(raw_entry)
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
                        logger.debug(f"Skipping duplicate ({reason}): {article.url}")
                        continue

                    # If new and full body requested, fetch full article HTML
                    if fetch_full_body:
                        try:
                            full_info = self.provider.fetch_article(article.url)
                            if full_info.get("content"):
                                article.content = full_info["content"]
                                article.content_hash = compute_content_hash(article.content)
                            if full_info.get("tags"):
                                # Merge tags
                                combined = set(article.tags + full_info["tags"])
                                article.tags = sorted(list(combined))
                        except Exception as fetch_err:
                            logger.warning(
                                f"Failed to fetch full HTML body for {article.url}: {fetch_err}. Using feed summary."
                            )

                    # Persist article in database
                    inserted = self.db.insert_article(article)
                    if inserted:
                        new_count += 1
                        logger.info(f"Ingested new article: [{article.article_id}] {article.title}")
                    else:
                        duplicate_count += 1

                except Exception as entry_err:
                    failed_count += 1
                    error_messages.append(f"Entry error: {entry_err}")
                    logger.error(f"Error processing article entry: {entry_err}", exc_info=True)

            status = "completed"
        except Exception as run_err:
            status = "failed"
            error_messages.append(f"Fatal run error: {run_err}")
            logger.error(f"Latest collection run failed: {run_err}", exc_info=True)

        summary_text = "; ".join(error_messages[:5]) if error_messages else None
        run_record = CollectionRun(
            run_id=run_id,
            completed_at=utc_now_iso(),
            source="thehackernews",
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

        return {
            "discovered": discovered_count,
            "new_articles": new_count,
            "duplicates": duplicate_count,
            "failed": failed_count,
            "run_id": run_id,
        }

    # ── Collect Historical ─────────────────────────────────────────────────────

    def collect_historical(
        self,
        start_date: str,
        end_date: str,
        max_articles: Optional[int] = None,
        resume: bool = True,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """
        Controlled, resumable historical ingestion across a specified date range.
        Returns execution statistics.
        """
        job_name = f"thn_historical_{start_date}_{end_date}"
        run_id = self.db.record_run_start(mode="historical", source="thehackernews")

        discovered_count = 0
        new_count = 0
        duplicate_count = 0
        failed_count = 0
        error_messages: list[str] = []

        start_offset = 1
        if resume:
            checkpoint = self.db.get_checkpoint(job_name)
            if checkpoint and checkpoint.cursor_offset > 0:
                start_offset = checkpoint.cursor_offset
                logger.info(f"Resuming historical collection from checkpoint offset {start_offset}")

        try:
            batch_generator = self.provider.collect_historical(
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
                        article = self.provider.normalize_article(raw_entry)
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

                        if fetch_full_body:
                            try:
                                full_info = self.provider.fetch_article(article.url)
                                if full_info.get("content"):
                                    article.content = full_info["content"]
                                    article.content_hash = compute_content_hash(article.content)
                                if full_info.get("tags"):
                                    combined = set(article.tags + full_info["tags"])
                                    article.tags = sorted(list(combined))
                            except Exception as fetch_err:
                                logger.warning(f"Could not fetch full body for {article.url}: {fetch_err}")

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
            # Mark checkpoint as completed
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
        except Exception as run_err:
            status = "failed"
            error_messages.append(f"Historical run error: {run_err}")
            logger.error(f"Historical collection run failed: {run_err}", exc_info=True)

        summary_text = "; ".join(error_messages[:5]) if error_messages else None
        run_record = CollectionRun(
            run_id=run_id,
            completed_at=utc_now_iso(),
            source="thehackernews",
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

        return {
            "discovered": discovered_count,
            "new_articles": new_count,
            "duplicates": duplicate_count,
            "failed": failed_count,
            "run_id": run_id,
        }
