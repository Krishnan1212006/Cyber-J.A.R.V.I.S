"""
JARVIS Cybersecurity Intelligence Subsystem.
Phase 1: The Hacker News Data Ingestion & Persistent Storage.
Phase 2: Cybersecurity Threat Intelligence Extraction & Structured Article Analysis.
Phase 3: Threat Trend Detection, Risk Scoring & Cross-Article Intelligence Analysis.
"""

from .models import (
    Article,
    CollectionRun,
    CollectionCheckpoint,
    ArticleAnalysis,
    TrendSnapshot,
    MitreTechnique,
    OwaspCategory,
    ArticleFrameworkMapping,
    UnifiedLink,
    ConnectorHealth,
    UserLearningProfile,
    SOURCE_THEHACKERNEWS,
    SOURCE_HACKLIDO,
    SOURCE_BLEEPINGCOMPUTER,
    SOURCE_CYBERSECURITYNEWS,
    ALL_CYBER_SOURCES,
)
from .db import IntelligenceDB
from .thn_provider import BaseDataProvider, THNDataProvider
from .connectors import (
    BaseCyberNewsConnector,
    HacklidoConnector,
    BleepingComputerConnector,
    TheHackerNewsConnector,
    CybersecurityNewsConnector,
)
from .collector_service import THNCollectorService, CyberNewsCollector
from .security import sanitize_text, normalize_url, compute_content_hash, wrap_untrusted
from .llm_provider import (
    BaseLLMProvider,
    GeminiLLMProvider,
    OllamaLLMProvider,
    OpenAILLMProvider,
    MockLLMProvider,
    get_llm_provider,
)
from .preprocessor import preprocess_article, extract_cves, extract_candidate_iocs
from .validator import validate_and_repair_analysis, ValidationError
from .analyzer_service import CybersecurityAnalyzer, get_analyzer
from .time_windows import resolve_time_window, get_previous_period, parse_iso, format_iso
from .trends import TrendResult, calculate_trend
from .risk_scoring import RiskScoreResult, calculate_risk_score, classify_risk_category
from .correlation import ThreatRelationship, ThreatCorrelationEngine
from .intelligence_engine import CybersecurityIntelligenceEngine, get_intelligence_engine
from .mitre_attack import MitreAttackConnector, validate_technique_id
from .owasp_top10 import OwaspTop10Connector
from .vectra_provider import VectraProvider, VectraDetection
from .unified_schema import UnifiedIntelligenceEngine, ProvenanceType
from .scheduler import ConnectorScheduler
from .learning_service import CybersecurityLearningService

__all__ = [
    # Phase 1
    "Article",
    "CollectionRun",
    "CollectionCheckpoint",
    "IntelligenceDB",
    "BaseDataProvider",
    "THNDataProvider",
    "THNCollectorService",
    "CyberNewsCollector",
    "BaseCyberNewsConnector",
    "HacklidoConnector",
    "BleepingComputerConnector",
    "TheHackerNewsConnector",
    "CybersecurityNewsConnector",
    "SOURCE_THEHACKERNEWS",
    "SOURCE_HACKLIDO",
    "SOURCE_BLEEPINGCOMPUTER",
    "SOURCE_CYBERSECURITYNEWS",
    "ALL_CYBER_SOURCES",
    "sanitize_text",
    "normalize_url",
    "compute_content_hash",
    "wrap_untrusted",
    # Phase 2
    "ArticleAnalysis",
    "CybersecurityAnalyzer",
    "get_analyzer",
    "BaseLLMProvider",
    "GeminiLLMProvider",
    "OllamaLLMProvider",
    "OpenAILLMProvider",
    "MockLLMProvider",
    "get_llm_provider",
    "preprocess_article",
    "extract_cves",
    "extract_candidate_iocs",
    "validate_and_repair_analysis",
    "ValidationError",
    # Phase 3
    "TrendSnapshot",
    "CybersecurityIntelligenceEngine",
    "get_intelligence_engine",
    "ThreatCorrelationEngine",
    "ThreatRelationship",
    "RiskScoreResult",
    "calculate_risk_score",
    "classify_risk_category",
    "TrendResult",
    "calculate_trend",
    "resolve_time_window",
    "get_previous_period",
    "parse_iso",
    "format_iso",
    # Phase 3.5
    "MitreTechnique",
    "OwaspCategory",
    "ArticleFrameworkMapping",
    "UnifiedLink",
    "ConnectorHealth",
    "UserLearningProfile",
    "MitreAttackConnector",
    "validate_technique_id",
    "OwaspTop10Connector",
    "VectraProvider",
    "VectraDetection",
    "UnifiedIntelligenceEngine",
    "ProvenanceType",
    "ConnectorScheduler",
    "CybersecurityLearningService",
]


