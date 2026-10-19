"""
Data models for JARVIS Cybersecurity Intelligence Subsystem.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Article:
    """Represents an ingested cybersecurity article."""

    article_id: str
    source: str = "thehackernews"
    title: str = ""
    url: str = ""
    author: str = "The Hacker News"
    published_at: str = ""  # ISO 8601 UTC
    collected_at: str = field(default_factory=utc_now_iso)
    category: str = "Cybersecurity"
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    content: str = ""
    content_hash: str = ""

    # Additional metadata
    updated_at: str = ""
    raw_html_path: Optional[str] = None

    # Extensible fields for Phase 2 (Threat Analysis & Entities)
    cve_ids: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    target_sectors: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    analysis_status: str = "pending"  # 'pending', 'analyzed', 'failed'

    def to_dict(self) -> dict[str, Any]:
        """Convert Article to a dictionary suitable for serialization/storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Article:
        """Construct an Article instance from dictionary data."""
        # Parse JSON strings for list fields if read from database
        parsed = dict(data)
        list_fields = [
            "tags",
            "cve_ids",
            "threat_actors",
            "malware_families",
            "target_sectors",
            "attack_techniques",
        ]
        for f in list_fields:
            val = parsed.get(f)
            if isinstance(val, str):
                try:
                    parsed[f] = json.loads(val)
                except Exception:
                    parsed[f] = [val] if val.strip() else []
            elif val is None:
                parsed[f] = []

        # Filter only known fields to handle forward compatibility
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in parsed.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class CollectionRun:
    """Logs each collection execution run."""

    run_id: str
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: Optional[str] = None
    source: str = "thehackernews"
    mode: str = "latest"  # 'latest' | 'historical'
    discovered_count: int = 0
    new_count: int = 0
    duplicate_count: int = 0
    failed_count: int = 0
    status: str = "running"  # 'running' | 'completed' | 'failed' | 'interrupted'
    error_summary: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionRun:
        parsed = dict(data)
        meta = parsed.get("metadata")
        if isinstance(meta, str):
            try:
                parsed["metadata"] = json.loads(meta)
            except Exception:
                parsed["metadata"] = {}
        elif meta is None:
            parsed["metadata"] = {}

        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in parsed.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class CollectionCheckpoint:
    """Tracks state and offsets for resumable historical ingestion."""

    job_name: str  # 'thn_historical' | 'thn_continuous'
    last_run_at: str = field(default_factory=utc_now_iso)
    last_article_id: Optional[str] = None
    last_published_at: Optional[str] = None
    cursor_offset: int = 0
    articles_collected: int = 0
    status: str = "idle"  # 'idle' | 'running' | 'paused' | 'error'

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionCheckpoint:
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in parsed.items() if k in valid_keys} if (parsed := dict(data)) else {}
        return cls(**filtered)


@dataclass
class ArticleAnalysis:
    """Represents structured cybersecurity intelligence extracted from an article."""

    analysis_id: str
    article_id: str
    analysis_version: str = "v1"
    analysis_status: str = "pending"  # 'pending', 'processing', 'completed', 'failed'
    analysis_model: str = "gemini-3.8-flash"
    analysis_started_at: Optional[str] = None
    analysis_completed_at: Optional[str] = None
    analysis_error: Optional[str] = None

    # Source correlation
    title: str = ""
    source: str = "thehackernews"
    url: str = ""
    published_at: str = ""
    category: str = "Cybersecurity"

    # Executive cybersecurity summary (answers what, who, how, why, what defenders should do)
    summary: str = ""

    # Threat Information
    threat_types: list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    threat_groups: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    ransomware: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    cves_exploited: list[str] = field(default_factory=list)
    cvss: dict[str, Any] = field(default_factory=dict)
    affected_products: list[str] = field(default_factory=list)
    affected_vendors: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    target_sectors: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    target_organizations: list[str] = field(default_factory=list)

    # Technical Details
    technical_explanation: dict[str, Any] = field(default_factory=dict)
    mitre_attack: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    # Impact
    impact: dict[str, str] = field(default_factory=dict)

    # Defensive Information
    detection_methods: list[str] = field(default_factory=list)
    mitigation: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    security_recommendations: list[str] = field(default_factory=list)

    # Classification & Evidence Separation
    severity: str = "MEDIUM"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    severity_reason: str = ""
    confidence: str = "HIGH"  # 'HIGH', 'MEDIUM', 'LOW'
    facts: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)

    # Audit & Tracking
    raw_llm_response: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert ArticleAnalysis to dictionary suitable for JSON/SQLite storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArticleAnalysis:
        """Construct an ArticleAnalysis instance safely parsing JSON strings for complex fields."""
        parsed = dict(data)

        # Fields stored as JSON strings in SQLite
        json_fields = [
            "threat_types",
            "attack_types",
            "attack_vectors",
            "threat_actors",
            "threat_groups",
            "malware",
            "ransomware",
            "vulnerabilities",
            "cves",
            "cves_exploited",
            "cvss",
            "affected_products",
            "affected_vendors",
            "affected_versions",
            "target_sectors",
            "target_countries",
            "target_organizations",
            "technical_explanation",
            "mitre_attack",
            "iocs",
            "tools",
            "technologies",
            "impact",
            "detection_methods",
            "mitigation",
            "remediation",
            "security_recommendations",
            "facts",
            "inferences",
        ]

        for field_name in json_fields:
            val = parsed.get(field_name)
            if isinstance(val, str):
                try:
                    parsed[field_name] = json.loads(val)
                except Exception:
                    # Fallback for plain strings
                    default_empty = {} if field_name in ("cvss", "impact", "technical_explanation") else []
                    parsed[field_name] = default_empty
            elif val is None:
                parsed[field_name] = {} if field_name in ("cvss", "impact", "technical_explanation") else []

        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in parsed.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class TrendSnapshot:
    """Represents a persistent analytical intelligence snapshot across a defined time window."""

    snapshot_id: str
    created_at: str = field(default_factory=utc_now_iso)
    start_date: str = ""
    end_date: str = ""
    metric_type: str = ""  # 'overall_risk', 'threat_type', 'threat_actor', 'malware', 'cve', 'mitre_technique', 'sector'
    metric_name: str = ""
    value: float = 0.0
    previous_value: Optional[float] = None
    change: Optional[float] = None
    trend_status: str = "INSUFFICIENT_DATA"  # 'INCREASING', 'DECREASING', 'STABLE', 'EMERGING', 'DECLINING', 'INSUFFICIENT_DATA'
    risk_score: float = 0.0
    confidence: str = "HIGH"  # 'HIGH', 'MEDIUM', 'LOW'
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrendSnapshot:
        parsed = dict(data)
        meta = parsed.get("metadata")
        if isinstance(meta, str):
            try:
                parsed["metadata"] = json.loads(meta)
            except Exception:
                parsed["metadata"] = {}
        elif meta is None:
            parsed["metadata"] = {}

        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in parsed.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class MitreTechnique:
    """Official MITRE ATT&CK technique reference record."""

    technique_id: str  # e.g. 'T1059.001'
    technique_name: str
    tactic_id: Optional[str] = None  # e.g. 'TA0002'
    tactic_name: Optional[str] = None  # e.g. 'Execution'
    description: str = ""
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    detection_guidance: str = ""
    version: str = "v16.1"
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    url: str = ""
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MitreTechnique:
        parsed = dict(data)
        for json_k in ("platforms", "data_sources"):
            val = parsed.get(json_k)
            if isinstance(val, str):
                try:
                    parsed[json_k] = json.loads(val)
                except Exception:
                    parsed[json_k] = []
        valid_keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in parsed.items() if k in valid_keys})


@dataclass
class OwaspCategory:
    """Official OWASP Top 10 2025 standard category."""

    category_id: str  # e.g. 'A01:2025'
    category_name: str  # e.g. 'Broken Access Control'
    year: str = "2025"
    description: str = ""
    common_cwes: list[str] = field(default_factory=list)
    prevention_guidance: str = ""
    safe_lab_exercise: str = ""
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OwaspCategory:
        parsed = dict(data)
        val = parsed.get("common_cwes")
        if isinstance(val, str):
            try:
                parsed["common_cwes"] = json.loads(val)
            except Exception:
                parsed["common_cwes"] = []
        valid_keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in parsed.items() if k in valid_keys})


@dataclass
class ArticleFrameworkMapping:
    """Evidence-backed mapping connecting an article disclosure to MITRE ATT&CK or OWASP Top 10."""

    mapping_id: str
    article_id: str
    framework: str  # 'MITRE_ATTACK' | 'OWASP_TOP10'
    framework_item_id: str  # e.g. 'T1059.001' or 'A01:2025'
    framework_item_name: str
    evidence_text: str
    mapping_method: str  # 'explicit' | 'inferred' | 'confirmed' | 'ai_suggested'
    confidence: str = "HIGH"  # 'HIGH' | 'MEDIUM' | 'LOW'
    dataset_version: str = "v1"
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArticleFrameworkMapping:
        parsed = dict(data)
        meta = parsed.get("metadata")
        if isinstance(meta, str):
            try:
                parsed["metadata"] = json.loads(meta)
            except Exception:
                parsed["metadata"] = {}
        valid_keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in parsed.items() if k in valid_keys})


@dataclass
class UnifiedLink:
    """Normalized cross-entity relationship with strict provenance tracking."""

    link_id: str
    source_type: str  # 'article', 'cve', 'malware', 'threat_actor', 'mitre_technique', 'owasp_category', 'vectra_detection'
    source_id: str
    relationship: str  # 'exploits', 'employs', 'mapped_to', 'targets_sector', 'detected_in', 'associated_with'
    target_type: str
    target_id: str
    provenance: str  # 'ARTICLE_REPORTED_FACT', 'OFFICIAL_FRAMEWORK_METADATA', 'ACTUAL_OBSERVED_DETECTION', 'AI_INFERENCE', 'UNVERIFIED_HYPOTHESIS'
    evidence_text: Optional[str] = None
    supporting_article_id: Optional[str] = None
    confidence: str = "HIGH"  # 'HIGH', 'MEDIUM', 'LOW'
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedLink:
        parsed = dict(data)
        valid_keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in parsed.items() if k in valid_keys})


@dataclass
class ConnectorHealth:
    """Health, latency, and status monitoring record for intelligence connectors."""

    connector_id: str  # 'thn_collector', 'mitre_attack', 'owasp_top10', 'vectra_ai', 'article_analyzer', 'trend_analytics'
    connector_name: str
    status: str = "NOT_CONFIGURED"  # 'CONNECTED', 'DEGRADED', 'NOT_CONFIGURED', 'ERROR'
    last_run_at: Optional[str] = None
    last_successful_run_at: Optional[str] = None
    records_processed: int = 0
    last_error: Optional[str] = None
    data_freshness: Optional[str] = None
    config_summary: dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectorHealth:
        parsed = dict(data)
        cfg = parsed.get("config_summary")
        if isinstance(cfg, str):
            try:
                parsed["config_summary"] = json.loads(cfg)
            except Exception:
                parsed["config_summary"] = {}
        valid_keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in parsed.items() if k in valid_keys})


@dataclass
class UserLearningProfile:
    """User preferences, learning level, and educational progress tracker."""

    user_id: str = "default"
    preferred_level: str = "intermediate"  # 'beginner', 'intermediate', 'advanced'
    topics_covered: list[str] = field(default_factory=list)
    completed_challenges: list[str] = field(default_factory=list)
    quiz_scores: dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserLearningProfile:
        parsed = dict(data)
        for json_k in ("topics_covered", "completed_challenges"):
            val = parsed.get(json_k)
            if isinstance(val, str):
                try:
                    parsed[json_k] = json.loads(val)
                except Exception:
                    parsed[json_k] = []
        q_scores = parsed.get("quiz_scores")
        if isinstance(q_scores, str):
            try:
                parsed["quiz_scores"] = json.loads(q_scores)
            except Exception:
                parsed["quiz_scores"] = {}
        valid_keys = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in parsed.items() if k in valid_keys})


@dataclass
class InformationPage:
    """Represents a dedicated persistent information page or comprehensive research record."""

    id: str
    title: str
    summary: str = ""
    content: str = ""
    content_format: str = "markdown"  # 'markdown' | 'html'
    category: str = "General"
    tags: list[str] = field(default_factory=list)
    presentation_type: str = "INFORMATION_PAGE"  # 'CHAT' | 'INFORMATION_PAGE' | 'CYBERSECURITY_REPORT' | 'LEARNING_PAGE' | 'PROJECT_DOCUMENT' | 'GENERATED_ARTIFACT'
    source_references: list[dict[str, Any]] = field(default_factory=list)
    table_of_contents: list[dict[str, Any]] = field(default_factory=list)
    related_topics: list[str] = field(default_factory=list)
    follow_up_questions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    model_provider: str = "gemini"
    generation_status: str = "completed"  # 'completed' | 'generating' | 'failed'
    related_project_id: Optional[str] = None
    user_bookmarked: bool = False
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Convert InformationPage to dictionary suitable for JSON serialization and DB storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InformationPage:
        """Construct an InformationPage instance from dictionary data with JSON deserialization."""
        parsed = dict(data)
        # Parse JSON fields if read from database
        list_fields = ["tags", "source_references", "table_of_contents", "related_topics", "follow_up_questions"]
        for f in list_fields:
            val = parsed.get(f)
            if isinstance(val, str):
                try:
                    parsed[f] = json.loads(val)
                except Exception:
                    parsed[f] = []
            elif val is None:
                parsed[f] = []

        dict_fields = ["metadata"]
        for f in dict_fields:
            val = parsed.get(f)
            if isinstance(val, str):
                try:
                    parsed[f] = json.loads(val)
                except Exception:
                    parsed[f] = {}
            elif val is None:
                parsed[f] = {}

        if "user_bookmarked" in parsed:
            parsed["user_bookmarked"] = bool(parsed["user_bookmarked"])

        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in parsed.items() if k in valid_keys}
        return cls(**filtered)



