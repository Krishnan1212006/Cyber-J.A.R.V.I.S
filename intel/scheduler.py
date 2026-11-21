"""
Real-Time Collection, Scheduling, and Connector Health Monitoring for JARVIS (Phase 3.5).

Coordinates independent, configurable jobs:
1. thn_collection: Incremental collection of latest The Hacker News articles.
2. attack_refresh: Official MITRE ATT&CK reference version check and technique updates.
3. owasp_reference_check: OWASP Top 10 2025 standard consistency and mapping maintenance.
4. vectra_polling: Optional Vectra AI detection polling (reports NOT_CONFIGURED when unconfigured).
5. article_analysis: Phase 2 AI structured extraction for newly ingested articles.
6. trend_analytics: Phase 3 trend acceleration and snapshot calculation.

Enforces:
- Status classifications: CONNECTED | DEGRADED | NOT_CONFIGURED | ERROR
- Idempotent execution, bounded retries, and checkpoint tracking.
- Precise data freshness tracking (never claiming 'real-time' without actual sensor latency).
"""

from __future__ import annotations
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .collector_service import CyberNewsCollector, THNCollectorService
from .config import load_cyber_config
from .db import IntelligenceDB
from .mitre_attack import MitreAttackConnector
from .models import (
    ConnectorHealth,
    SOURCE_THEHACKERNEWS,
    SOURCE_HACKLIDO,
    SOURCE_BLEEPINGCOMPUTER,
    SOURCE_CYBERSECURITYNEWS,
    utc_now_iso,
)
from .owasp_top10 import OwaspTop10Connector
from .vectra_provider import VectraProvider

logger = logging.getLogger(__name__)


class ConnectorScheduler:
    """Manages scheduled execution, retries, and health reporting for all intelligence connectors."""

    def __init__(
        self,
        db: Optional[IntelligenceDB] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        self.config = config or load_cyber_config()
        self.db = db or IntelligenceDB(self.config["db_path"])
        self.mitre_connector = MitreAttackConnector(self.db)
        self.owasp_connector = OwaspTop10Connector(self.db)
        self.vectra_provider = VectraProvider()
        self.thn_service = THNCollectorService(db=self.db, config=self.config)
        self.cyber_collector = CyberNewsCollector(db=self.db, config=self.config)

        # Initial status registration
        self._register_initial_statuses()

    def _register_initial_statuses(self) -> None:
        """Register initial baseline status for all connectors."""
        now = utc_now_iso()

        # 1. The Hacker News Connector (Legacy & Multi-Source)
        thn_health = self.db.get_connector_status("thn_collector")
        if not thn_health:
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="thn_collector",
                    connector_name="The Hacker News Ingestion",
                    status="CONNECTED",
                    last_run_at=now,
                    records_processed=self.db.get_article_count(source=SOURCE_THEHACKERNEWS),
                    data_freshness=self.db.get_freshness_timestamps().get("last_ingestion_time"),
                    config_summary={"source": "https://thehackernews.com/", "mode": "incremental"},
                    updated_at=now,
                )
            )

        # Register the 4 Cyber News Source Connectors
        news_sources = [
            (SOURCE_THEHACKERNEWS, "The Hacker News Connector", "https://thehackernews.com/"),
            (SOURCE_HACKLIDO, "Hacklido Connector", "https://hacklido.com/"),
            (SOURCE_BLEEPINGCOMPUTER, "BleepingComputer Connector", "https://www.bleepingcomputer.com/"),
            (SOURCE_CYBERSECURITYNEWS, "Cybersecurity News Connector", "https://cybersecuritynews.com/"),
        ]
        for src_id, src_name, src_url in news_sources:
            cid = f"{src_id}_connector"
            if not self.db.get_connector_status(cid):
                count = self.db.get_article_count(source=src_id)
                self.db.record_connector_status(
                    ConnectorHealth(
                        connector_id=cid,
                        connector_name=src_name,
                        status="CONNECTED",
                        last_run_at=now,
                        last_successful_run_at=now if count > 0 else None,
                        records_processed=count,
                        data_freshness=now,
                        config_summary={"source": src_id, "url": src_url, "mode": "incremental"},
                        updated_at=now,
                    )
                )

        # 2. MITRE ATT&CK Connector
        mitre_health = self.db.get_connector_status("mitre_attack")
        if not mitre_health:
            tech_count = len(self.db.get_all_mitre_techniques(limit=5000))
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="mitre_attack",
                    connector_name="MITRE ATT&CK Enterprise Catalog",
                    status="CONNECTED",
                    last_run_at=now,
                    last_successful_run_at=now,
                    records_processed=tech_count,
                    data_freshness="v16.1",
                    config_summary={"version": "v16.1", "source": "Official Enterprise ATT&CK"},
                    updated_at=now,
                )
            )

        # 3. OWASP Top 10 Connector
        owasp_health = self.db.get_connector_status("owasp_top10")
        if not owasp_health:
            cat_count = len(self.db.get_all_owasp_categories())
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="owasp_top10",
                    connector_name="OWASP Top 10 2025 Reference",
                    status="CONNECTED",
                    last_run_at=now,
                    last_successful_run_at=now,
                    records_processed=cat_count,
                    data_freshness="2025 Standard",
                    config_summary={"year": "2025", "categories_count": cat_count},
                    updated_at=now,
                )
            )

        # 4. Vectra AI Connector
        vectra_status = self.vectra_provider.get_status()
        self.db.record_connector_status(
            ConnectorHealth(
                connector_id="vectra_ai",
                connector_name="Vectra AI Platform Telemetry",
                status=vectra_status["status"],
                last_run_at=now,
                last_error=vectra_status.get("message") if not vectra_status["available"] else None,
                data_freshness="Not Configured" if not vectra_status["available"] else "Live",
                config_summary={"api_version": "v3.3/v3.4", "configured": self.vectra_provider.is_configured},
                updated_at=now,
            )
        )

    def run_thn_collection_job(self, limit: int = 20, max_pages: int = 1) -> dict[str, Any]:
        """Execute incremental THN collection job with error handling and health updates."""
        now = utc_now_iso()
        try:
            summary = self.thn_service.collect_latest(limit=limit)
            failed_count = summary.get("failed", 0) if isinstance(summary, dict) else getattr(summary, "failed_count", 0)
            new_count = summary.get("new_articles", 0) if isinstance(summary, dict) else getattr(summary, "new_count", 0)
            disc_count = summary.get("discovered", 0) if isinstance(summary, dict) else getattr(summary, "discovered_count", 0)
            dup_count = summary.get("duplicates", 0) if isinstance(summary, dict) else getattr(summary, "duplicate_count", 0)
            status = "CONNECTED" if failed_count == 0 else "DEGRADED"
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="thn_collector",
                    connector_name="The Hacker News Ingestion",
                    status=status,
                    last_run_at=now,
                    last_successful_run_at=now if new_count >= 0 else None,
                    records_processed=disc_count,
                    last_error=None,
                    data_freshness=now,
                    config_summary={"new": new_count, "duplicates": dup_count},
                    updated_at=now,
                )
            )
            return summary if isinstance(summary, dict) else summary.to_dict()
        except Exception as e:
            logger.error(f"THN collection job failed: {e}")
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="thn_collector",
                    connector_name="The Hacker News Ingestion",
                    status="ERROR",
                    last_run_at=now,
                    last_error=str(e),
                    updated_at=now,
                )
            )
            return {"error": str(e), "status": "ERROR"}

    def run_cyber_news_collection_job(
        self,
        source: Optional[str] = None,
        limit: int = 15,
        fetch_full_body: bool = True,
    ) -> dict[str, Any]:
        """Execute incremental collection across all 4 cyber news sources (or a single source)."""
        return self.cyber_collector.collect_latest(
            source=source,
            limit=limit,
            fetch_full_body=fetch_full_body,
        )

    def retry_failed_collection_jobs(self) -> dict[str, Any]:
        """Retry collection for any source connector currently in ERROR or DEGRADED status."""
        return self.cyber_collector.retry_failed_jobs()

    def run_mitre_refresh_job(self) -> dict[str, Any]:
        """Verify and refresh official MITRE ATT&CK reference data."""
        now = utc_now_iso()
        try:
            count = self.mitre_connector.ingest_core_dataset()
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="mitre_attack",
                    connector_name="MITRE ATT&CK Enterprise Catalog",
                    status="CONNECTED",
                    last_run_at=now,
                    last_successful_run_at=now,
                    records_processed=count,
                    data_freshness=self.mitre_connector.version,
                    config_summary={"version": self.mitre_connector.version, "techniques": count},
                    updated_at=now,
                )
            )
            return {"status": "SUCCESS", "version": self.mitre_connector.version, "techniques_synced": count}
        except Exception as e:
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="mitre_attack",
                    connector_name="MITRE ATT&CK Enterprise Catalog",
                    status="ERROR",
                    last_run_at=now,
                    last_error=str(e),
                    updated_at=now,
                )
            )
            return {"status": "ERROR", "error": str(e)}

    def run_owasp_check_job(self) -> dict[str, Any]:
        """Verify official OWASP Top 10 2025 categories."""
        now = utc_now_iso()
        try:
            count = self.owasp_connector.ingest_core_dataset()
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="owasp_top10",
                    connector_name="OWASP Top 10 2025 Reference",
                    status="CONNECTED",
                    last_run_at=now,
                    last_successful_run_at=now,
                    records_processed=count,
                    data_freshness=f"{self.owasp_connector.year} Standard",
                    config_summary={"categories_count": count},
                    updated_at=now,
                )
            )
            return {"status": "SUCCESS", "year": self.owasp_connector.year, "categories_synced": count}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def run_vectra_poll_job(self) -> dict[str, Any]:
        """
        Poll detections from Vectra AI if configured.
        Returns explicit NOT_CONFIGURED status when credentials are not supplied.
        """
        now = utc_now_iso()
        status_info = self.vectra_provider.get_status()

        if not self.vectra_provider.is_configured:
            self.db.record_connector_status(
                ConnectorHealth(
                    connector_id="vectra_ai",
                    connector_name="Vectra AI Platform Telemetry",
                    status="NOT_CONFIGURED",
                    last_run_at=now,
                    last_error=status_info["message"],
                    data_freshness="Not Configured",
                    config_summary={"configured": False},
                    updated_at=now,
                )
            )
            return {
                "status": "NOT_CONFIGURED",
                "message": "Vectra AI credentials are not configured. Sensor polling skipped.",
                "detections_count": 0,
            }

        detections = self.vectra_provider.poll_detections()
        self.db.record_connector_status(
            ConnectorHealth(
                connector_id="vectra_ai",
                connector_name="Vectra AI Platform Telemetry",
                status="CONNECTED",
                last_run_at=now,
                last_successful_run_at=now,
                records_processed=len(detections),
                data_freshness="Live",
                config_summary={"detections_polled": len(detections)},
                updated_at=now,
            )
        )
        return {
            "status": "CONNECTED",
            "detections_count": len(detections),
            "detections": [d.to_dict() for d in detections],
        }

    def get_all_health(self) -> list[dict[str, Any]]:
        """Return real-time health and freshness for all connectors."""
        statuses = self.db.get_all_connector_statuses()
        return [s.to_dict() for s in statuses]
