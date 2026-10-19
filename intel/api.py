"""
FastAPI Analytics Router and Service Endpoints for JARVIS Cybersecurity Subsystem.

Exposes REST endpoints:
- GET /api/intelligence/overview
- GET /api/intelligence/trends
- GET /api/intelligence/threats
- GET /api/intelligence/cves
- GET /api/intelligence/malware
- GET /api/intelligence/actors
- GET /api/intelligence/mitre
- GET /api/intelligence/sectors
- GET /api/intelligence/risk
- GET /api/intelligence/emerging
- GET /api/intelligence/timeline
- GET /api/intelligence/freshness
- GET /api/intelligence/report
"""

from __future__ import annotations
from typing import Any, Optional

try:
    from fastapi import APIRouter, Query
    from fastapi.responses import JSONResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from .intelligence_engine import CybersecurityIntelligenceEngine, get_intelligence_engine

_engine_instance: Optional[CybersecurityIntelligenceEngine] = None


def get_engine() -> CybersecurityIntelligenceEngine:
    """Return active engine instance, creating one if not yet initialized."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = get_intelligence_engine()
    return _engine_instance


def set_engine(engine: Optional[CybersecurityIntelligenceEngine]) -> None:
    """Explicitly set or reset the active engine instance (useful for testing)."""
    global _engine_instance
    _engine_instance = engine


if _FASTAPI_AVAILABLE:
    router = APIRouter(prefix="/api/intelligence", tags=["Cybersecurity Intelligence"])

    @router.get("/overview")
    async def get_overview_ep(
        window: str = Query("7d", description="Time window ('24h', '7d', '30d', '90d', 'all')"),
        start: Optional[str] = Query(None, description="Custom start ISO date"),
        end: Optional[str] = Query(None, description="Custom end ISO date"),
    ) -> Any:
        engine = get_engine()
        return engine.get_threat_overview(time_window=window, start_date=start, end_date=end)

    @router.get("/trends")
    async def get_trends_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_trending_threats(time_window=window, limit=limit)

    @router.get("/threats")
    async def get_threats_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_trending_threats(time_window=window, limit=limit)

    @router.get("/cves")
    async def get_cves_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_top_cves(time_window=window, limit=limit)

    @router.get("/malware")
    async def get_malware_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_top_malware(time_window=window, limit=limit)

    @router.get("/actors")
    async def get_actors_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_top_threat_actors(time_window=window, limit=limit)

    @router.get("/mitre")
    async def get_mitre_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_mitre_trends(time_window=window, limit=limit)

    @router.get("/sectors")
    async def get_sectors_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_sector_trends(time_window=window, limit=limit)

    @router.get("/risk")
    async def get_risk_ep(
        window: str = Query("7d", description="Time window ('24h', '7d', '30d')"),
    ) -> Any:
        engine = get_engine()
        overview = engine.get_threat_overview(time_window=window)
        return overview["risk_overview"]

    @router.get("/emerging")
    async def get_emerging_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
        limit: int = Query(10, ge=1, le=100),
    ) -> Any:
        engine = get_engine()
        return engine.get_emerging_threats(time_window=window, limit=limit)

    @router.get("/timeline")
    async def get_timeline_ep(
        window: str = Query("30d", description="Time window ('7d', '30d', '90d')"),
    ) -> Any:
        engine = get_engine()
        return engine.get_timeline(time_window=window)

    @router.get("/freshness")
    async def get_freshness_ep() -> Any:
        engine = get_engine()
        return engine.get_data_freshness()

    @router.get("/report")
    async def get_report_ep(
        window: str = Query("7d", description="Time window ('24h', '7d', '30d', 'all')"),
    ) -> Any:
        engine = get_engine()
        return engine.generate_intelligence_report(time_window=window)

    # ── Phase 3.5 Intelligence & Learning Endpoints ───────────────────────────

    @router.get("/connectors")
    async def get_connectors_health_ep() -> Any:
        """Return health, latency, and synchronization status for all intelligence connectors."""
        from .scheduler import ConnectorScheduler
        engine = get_engine()
        scheduler = ConnectorScheduler(db=engine.db)
        return scheduler.get_all_health()

    @router.get("/learning/explain/{article_id}")
    async def explain_article_ep(
        article_id: str,
        level: str = Query("intermediate", description="Learning level: 'beginner', 'intermediate', or 'advanced'"),
    ) -> Any:
        """Retrieve multi-tier defensive cybersecurity explanation for an article."""
        from .learning_service import CybersecurityLearningService
        engine = get_engine()
        svc = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        return svc.explain_thn_article(article_id=article_id, learning_level=level)

    @router.get("/learning/attack/{article_id}")
    async def map_attack_ep(article_id: str) -> Any:
        """Map article to official MITRE ATT&CK techniques with evidence."""
        from .learning_service import CybersecurityLearningService
        engine = get_engine()
        svc = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        return svc.map_article_to_attack_framework(article_id=article_id)

    @router.get("/learning/owasp/{article_id}")
    async def map_owasp_ep(article_id: str) -> Any:
        """Map article to official OWASP Top 10 2025 categories with evidence."""
        from .learning_service import CybersecurityLearningService
        engine = get_engine()
        svc = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        return svc.explain_owasp_relevance(article_id=article_id)

    @router.get("/learning/recommend/{article_id}")
    async def recommend_learning_ep(
        article_id: str,
        level: Optional[str] = Query(None, description="Preferred skill level"),
    ) -> Any:
        """Recommend tailored learning paths and safe lab simulations."""
        from .learning_service import CybersecurityLearningService
        from .models import UserLearningProfile
        engine = get_engine()
        svc = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        profile = UserLearningProfile(preferred_level=level or "intermediate") if level else None
        return svc.recommend_defensive_learning(article_id=article_id, learning_profile=profile)

    @router.get("/unified/graph")
    async def get_unified_graph_ep(
        entity_id: Optional[str] = Query(None, description="Filter by entity ID"),
        entity_type: Optional[str] = Query(None, description="Filter by entity type"),
        limit: int = Query(100, ge=1, le=500),
    ) -> Any:
        """Retrieve unified multi-source intelligence graph nodes and edges with provenance."""
        from .unified_schema import UnifiedIntelligenceEngine
        engine = get_engine()
        graph_engine = UnifiedIntelligenceEngine(db=engine.db)
        return graph_engine.get_unified_graph(entity_id=entity_id, entity_type=entity_type, limit=limit)

    @router.get("/vectra/status")
    async def get_vectra_status_ep() -> Any:
        """Return Vectra AI platform deployment status (returns NOT_CONFIGURED when unconfigured)."""
        from .vectra_provider import VectraProvider
        provider = VectraProvider()
        return provider.get_status()

else:
    router = None  # type: ignore
