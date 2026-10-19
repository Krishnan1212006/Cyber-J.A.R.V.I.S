"""
SQLite database storage layer with WAL mode and Full-Text Search (FTS5).
Provides thread-safe persistence, multi-tier deduplication, and collection logging.
"""

from __future__ import annotations
import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

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
    InformationPage,
    utc_now_iso,
)


class IntelligenceDB:
    """Manages SQLite storage for cybersecurity intelligence articles and runs."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a thread-local SQLite connection with proper pragma settings."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            # Enable WAL mode and performance pragmas
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            self._local.conn = conn

        try:
            yield conn
        except Exception:
            conn.rollback()
            raise

    def _init_db(self) -> None:
        """Create database tables, triggers, and indices if they do not exist."""
        with self._lock, self.connection() as conn:
            cursor = conn.cursor()
            cursor.executescript(
                """
                -- Main Article Table
                CREATE TABLE IF NOT EXISTS thn_articles (
                    article_id          TEXT PRIMARY KEY,
                    source              TEXT NOT NULL DEFAULT 'thehackernews',
                    title               TEXT NOT NULL,
                    url                 TEXT NOT NULL UNIQUE,
                    author              TEXT DEFAULT 'The Hacker News',
                    published_at        TEXT NOT NULL,
                    collected_at        TEXT NOT NULL,
                    category            TEXT DEFAULT 'Cybersecurity',
                    tags                TEXT DEFAULT '[]',
                    summary             TEXT DEFAULT '',
                    content             TEXT NOT NULL,
                    content_hash        TEXT NOT NULL,
                    updated_at          TEXT DEFAULT '',
                    raw_html_path       TEXT,
                    cve_ids             TEXT DEFAULT '[]',
                    threat_actors       TEXT DEFAULT '[]',
                    malware_families    TEXT DEFAULT '[]',
                    target_sectors      TEXT DEFAULT '[]',
                    attack_techniques   TEXT DEFAULT '[]',
                    analysis_status     TEXT DEFAULT 'pending'
                );

                CREATE INDEX IF NOT EXISTS idx_thn_url ON thn_articles(url);
                CREATE INDEX IF NOT EXISTS idx_thn_content_hash ON thn_articles(content_hash);
                CREATE INDEX IF NOT EXISTS idx_thn_published_at ON thn_articles(published_at DESC);
                CREATE INDEX IF NOT EXISTS idx_thn_analysis_status ON thn_articles(analysis_status);

                -- Collection Run Logging
                CREATE TABLE IF NOT EXISTS collection_runs (
                    run_id              TEXT PRIMARY KEY,
                    started_at          TEXT NOT NULL,
                    completed_at        TEXT,
                    source              TEXT NOT NULL,
                    mode                TEXT NOT NULL,
                    discovered_count    INTEGER DEFAULT 0,
                    new_count           INTEGER DEFAULT 0,
                    duplicate_count     INTEGER DEFAULT 0,
                    failed_count        INTEGER DEFAULT 0,
                    status              TEXT NOT NULL,
                    error_summary       TEXT,
                    metadata            TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_run_started_at ON collection_runs(started_at DESC);

                -- Resumable Checkpoints Table
                CREATE TABLE IF NOT EXISTS collection_checkpoints (
                    job_name            TEXT PRIMARY KEY,
                    last_run_at         TEXT NOT NULL,
                    last_article_id     TEXT,
                    last_published_at   TEXT,
                    cursor_offset       INTEGER DEFAULT 0,
                    articles_collected  INTEGER DEFAULT 0,
                    status              TEXT NOT NULL
                );

                -- Full-Text Search Virtual Table (FTS5)
                CREATE VIRTUAL TABLE IF NOT EXISTS thn_articles_fts USING fts5(
                    title,
                    summary,
                    content,
                    tags,
                    content='thn_articles',
                    content_rowid='rowid'
                );

                -- Triggers to keep FTS index synchronized
                CREATE TRIGGER IF NOT EXISTS thn_articles_ai AFTER INSERT ON thn_articles BEGIN
                    INSERT INTO thn_articles_fts(rowid, title, summary, content, tags)
                    VALUES (new.rowid, new.title, new.summary, new.content, new.tags);
                END;

                CREATE TRIGGER IF NOT EXISTS thn_articles_ad AFTER DELETE ON thn_articles BEGIN
                    INSERT INTO thn_articles_fts(thn_articles_fts, rowid, title, summary, content, tags)
                    VALUES ('delete', old.rowid, old.title, old.summary, old.content, old.tags);
                END;

                CREATE TRIGGER IF NOT EXISTS thn_articles_au AFTER UPDATE ON thn_articles BEGIN
                    INSERT INTO thn_articles_fts(thn_articles_fts, rowid, title, summary, content, tags)
                    VALUES ('delete', old.rowid, old.title, old.summary, old.content, old.tags);
                    INSERT INTO thn_articles_fts(rowid, title, summary, content, tags)
                    VALUES (new.rowid, new.title, new.summary, new.content, new.tags);
                END;

                -- Phase 2 Structured Cybersecurity Intelligence Analysis Table
                CREATE TABLE IF NOT EXISTS article_analysis (
                    analysis_id             TEXT PRIMARY KEY,
                    article_id              TEXT NOT NULL REFERENCES thn_articles(article_id) ON DELETE CASCADE,
                    analysis_version        TEXT NOT NULL DEFAULT 'v1',
                    analysis_status         TEXT NOT NULL DEFAULT 'pending',
                    analysis_model          TEXT NOT NULL,
                    analysis_started_at     TEXT,
                    analysis_completed_at   TEXT,
                    analysis_error          TEXT,
                    title                   TEXT DEFAULT '',
                    source                  TEXT DEFAULT 'thehackernews',
                    url                     TEXT DEFAULT '',
                    published_at            TEXT DEFAULT '',
                    category                TEXT DEFAULT 'Cybersecurity',
                    summary                 TEXT DEFAULT '',
                    threat_types            TEXT DEFAULT '[]',
                    attack_types            TEXT DEFAULT '[]',
                    attack_vectors          TEXT DEFAULT '[]',
                    threat_actors           TEXT DEFAULT '[]',
                    threat_groups           TEXT DEFAULT '[]',
                    malware                 TEXT DEFAULT '[]',
                    ransomware              TEXT DEFAULT '[]',
                    vulnerabilities         TEXT DEFAULT '[]',
                    cves                    TEXT DEFAULT '[]',
                    cvss                    TEXT DEFAULT '{}',
                    affected_products       TEXT DEFAULT '[]',
                    affected_vendors        TEXT DEFAULT '[]',
                    affected_versions       TEXT DEFAULT '[]',
                    target_sectors          TEXT DEFAULT '[]',
                    target_countries        TEXT DEFAULT '[]',
                    target_organizations    TEXT DEFAULT '[]',
                    technical_explanation   TEXT DEFAULT '{}',
                    mitre_attack            TEXT DEFAULT '[]',
                    iocs                    TEXT DEFAULT '[]',
                    tools                   TEXT DEFAULT '[]',
                    technologies            TEXT DEFAULT '[]',
                    impact                  TEXT DEFAULT '{}',
                    detection_methods       TEXT DEFAULT '[]',
                    mitigation              TEXT DEFAULT '[]',
                    remediation             TEXT DEFAULT '[]',
                    security_recommendations TEXT DEFAULT '[]',
                    severity                TEXT DEFAULT 'MEDIUM',
                    severity_reason         TEXT DEFAULT '',
                    confidence              TEXT DEFAULT 'HIGH',
                    facts                   TEXT DEFAULT '[]',
                    inferences              TEXT DEFAULT '[]',
                    raw_llm_response        TEXT,
                    created_at              TEXT NOT NULL,
                    updated_at              TEXT NOT NULL,
                    UNIQUE(article_id, analysis_version)
                );

                CREATE INDEX IF NOT EXISTS idx_analysis_article_id ON article_analysis(article_id);
                CREATE INDEX IF NOT EXISTS idx_analysis_status ON article_analysis(analysis_status);
                CREATE INDEX IF NOT EXISTS idx_analysis_severity ON article_analysis(severity);
                CREATE INDEX IF NOT EXISTS idx_analysis_version ON article_analysis(analysis_version);
                CREATE INDEX IF NOT EXISTS idx_analysis_completed_at ON article_analysis(analysis_completed_at DESC);

                -- Phase 3 Trend Intelligence Snapshots Table
                CREATE TABLE IF NOT EXISTS trend_snapshots (
                    snapshot_id         TEXT PRIMARY KEY,
                    created_at          TEXT NOT NULL,
                    start_date          TEXT NOT NULL,
                    end_date            TEXT NOT NULL,
                    metric_type         TEXT NOT NULL,
                    metric_name         TEXT NOT NULL,
                    value               REAL NOT NULL,
                    previous_value      REAL,
                    change              REAL,
                    trend_status        TEXT NOT NULL,
                    risk_score          REAL DEFAULT 0.0,
                    confidence          TEXT NOT NULL DEFAULT 'HIGH',
                    metadata            TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_snapshot_dates ON trend_snapshots(start_date, end_date);
                CREATE INDEX IF NOT EXISTS idx_snapshot_type_name ON trend_snapshots(metric_type, metric_name);
                CREATE INDEX IF NOT EXISTS idx_snapshot_created_at ON trend_snapshots(created_at DESC);

                -- Phase 3.5 MITRE ATT&CK Official Reference Dataset
                CREATE TABLE IF NOT EXISTS mitre_attack_dataset (
                    technique_id        TEXT PRIMARY KEY,
                    technique_name      TEXT NOT NULL,
                    tactic_id           TEXT,
                    tactic_name         TEXT,
                    description         TEXT DEFAULT '',
                    platforms           TEXT DEFAULT '[]',
                    data_sources        TEXT DEFAULT '[]',
                    detection_guidance  TEXT DEFAULT '',
                    version             TEXT NOT NULL DEFAULT 'v16.1',
                    is_subtechnique     INTEGER DEFAULT 0,
                    parent_technique_id TEXT,
                    url                 TEXT DEFAULT '',
                    updated_at          TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_mitre_tactic ON mitre_attack_dataset(tactic_name);
                CREATE INDEX IF NOT EXISTS idx_mitre_parent ON mitre_attack_dataset(parent_technique_id);

                -- Phase 3.5 OWASP Top 10 2025 Reference Dataset
                CREATE TABLE IF NOT EXISTS owasp_top10_dataset (
                    category_id         TEXT PRIMARY KEY,
                    category_name       TEXT NOT NULL,
                    year                TEXT NOT NULL DEFAULT '2025',
                    description         TEXT NOT NULL,
                    common_cwes         TEXT DEFAULT '[]',
                    prevention_guidance TEXT DEFAULT '',
                    safe_lab_exercise   TEXT DEFAULT '',
                    updated_at          TEXT NOT NULL
                );

                -- Phase 3.5 Article Framework Mappings (ATT&CK & OWASP with evidence)
                CREATE TABLE IF NOT EXISTS article_framework_mappings (
                    mapping_id          TEXT PRIMARY KEY,
                    article_id          TEXT NOT NULL,
                    framework           TEXT NOT NULL,
                    framework_item_id   TEXT NOT NULL,
                    framework_item_name TEXT NOT NULL,
                    evidence_text       TEXT NOT NULL,
                    mapping_method      TEXT NOT NULL,
                    confidence          TEXT NOT NULL DEFAULT 'HIGH',
                    dataset_version     TEXT DEFAULT 'v1',
                    metadata            TEXT DEFAULT '{}',
                    created_at          TEXT NOT NULL,
                    UNIQUE(article_id, framework, framework_item_id)
                );
                CREATE INDEX IF NOT EXISTS idx_afm_article ON article_framework_mappings(article_id);
                CREATE INDEX IF NOT EXISTS idx_afm_framework_item ON article_framework_mappings(framework, framework_item_id);

                -- Phase 3.5 Unified Intelligence Links & Provenance
                CREATE TABLE IF NOT EXISTS unified_intelligence_links (
                    link_id               TEXT PRIMARY KEY,
                    source_type           TEXT NOT NULL,
                    source_id             TEXT NOT NULL,
                    relationship          TEXT NOT NULL,
                    target_type           TEXT NOT NULL,
                    target_id             TEXT NOT NULL,
                    provenance            TEXT NOT NULL,
                    evidence_text         TEXT,
                    supporting_article_id TEXT,
                    confidence            TEXT NOT NULL DEFAULT 'HIGH',
                    created_at            TEXT NOT NULL,
                    UNIQUE(source_type, source_id, relationship, target_type, target_id)
                );
                CREATE INDEX IF NOT EXISTS idx_uil_source ON unified_intelligence_links(source_type, source_id);
                CREATE INDEX IF NOT EXISTS idx_uil_target ON unified_intelligence_links(target_type, target_id);
                CREATE INDEX IF NOT EXISTS idx_uil_article ON unified_intelligence_links(supporting_article_id);

                -- Phase 3.5 Connector Health & Telemetry Status
                CREATE TABLE IF NOT EXISTS connector_health (
                    connector_id           TEXT PRIMARY KEY,
                    connector_name         TEXT NOT NULL,
                    status                 TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
                    last_run_at            TEXT,
                    last_successful_run_at TEXT,
                    records_processed      INTEGER DEFAULT 0,
                    last_error             TEXT,
                    data_freshness         TEXT,
                    config_summary         TEXT DEFAULT '{}',
                    updated_at             TEXT NOT NULL
                );

                -- Phase 3.5 User Learning Profiles
                CREATE TABLE IF NOT EXISTS user_learning_profiles (
                    user_id               TEXT PRIMARY KEY DEFAULT 'default',
                    preferred_level       TEXT NOT NULL DEFAULT 'intermediate',
                    topics_covered        TEXT DEFAULT '[]',
                    completed_challenges  TEXT DEFAULT '[]',
                    quiz_scores           TEXT DEFAULT '{}',
                    updated_at            TEXT NOT NULL
                );

                -- Dedicated Information Pages Table
                CREATE TABLE IF NOT EXISTS information_pages (
                    id                  TEXT PRIMARY KEY,
                    title               TEXT NOT NULL,
                    summary             TEXT DEFAULT '',
                    content             TEXT NOT NULL,
                    content_format      TEXT DEFAULT 'markdown',
                    category            TEXT DEFAULT 'General',
                    tags                TEXT DEFAULT '[]',
                    presentation_type   TEXT DEFAULT 'INFORMATION_PAGE',
                    source_references   TEXT DEFAULT '[]',
                    table_of_contents   TEXT DEFAULT '[]',
                    related_topics      TEXT DEFAULT '[]',
                    follow_up_questions TEXT DEFAULT '[]',
                    metadata            TEXT DEFAULT '{}',
                    model_provider      TEXT DEFAULT 'gemini',
                    generation_status   TEXT DEFAULT 'completed',
                    related_project_id  TEXT,
                    user_bookmarked     INTEGER DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_info_category ON information_pages(category);
                CREATE INDEX IF NOT EXISTS idx_info_type ON information_pages(presentation_type);
                CREATE INDEX IF NOT EXISTS idx_info_bookmarked ON information_pages(user_bookmarked);
                CREATE INDEX IF NOT EXISTS idx_info_created_at ON information_pages(created_at DESC);

                -- Dedicated Information Pages Full-Text Search (FTS5)
                CREATE VIRTUAL TABLE IF NOT EXISTS information_pages_fts USING fts5(
                    title,
                    summary,
                    content,
                    tags,
                    content='information_pages',
                    content_rowid='rowid'
                );

                -- Synchronisation triggers for information_pages_fts
                CREATE TRIGGER IF NOT EXISTS info_pages_ai AFTER INSERT ON information_pages BEGIN
                    INSERT INTO information_pages_fts(rowid, title, summary, content, tags)
                    VALUES (new.rowid, new.title, new.summary, new.content, new.tags);
                END;

                CREATE TRIGGER IF NOT EXISTS info_pages_ad AFTER DELETE ON information_pages BEGIN
                    INSERT INTO information_pages_fts(information_pages_fts, rowid, title, summary, content, tags)
                    VALUES ('delete', old.rowid, old.title, old.summary, old.content, old.tags);
                END;

                CREATE TRIGGER IF NOT EXISTS info_pages_au AFTER UPDATE ON information_pages BEGIN
                    INSERT INTO information_pages_fts(information_pages_fts, rowid, title, summary, content, tags)
                    VALUES ('delete', old.rowid, old.title, old.summary, old.content, old.tags);
                    INSERT INTO information_pages_fts(rowid, title, summary, content, tags)
                    VALUES (new.rowid, new.title, new.summary, new.content, new.tags);
                END;
                """
            )
            conn.commit()

    # ── Deduplication Checks ───────────────────────────────────────────────────

    def check_duplicate(
        self,
        url: str,
        content_hash: Optional[str] = None,
        article_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Check if an article already exists using the 3-tier strategy:
        1. Canonical URL
        2. Article ID (e.g. Blogger post ID)
        3. Normalized content hash (SHA-256)
        Returns (is_duplicate, reason).
        """
        with self.connection() as conn:
            # Tier 1: Canonical URL
            if url:
                row = conn.execute(
                    "SELECT article_id FROM thn_articles WHERE url = ? LIMIT 1",
                    (url,),
                ).fetchone()
                if row:
                    return True, "url"

            # Tier 2: Article ID
            if article_id:
                row = conn.execute(
                    "SELECT article_id FROM thn_articles WHERE article_id = ? LIMIT 1",
                    (article_id,),
                ).fetchone()
                if row:
                    return True, "article_id"

            # Tier 3: Content Hash
            if content_hash:
                row = conn.execute(
                    "SELECT article_id FROM thn_articles WHERE content_hash = ? LIMIT 1",
                    (content_hash,),
                ).fetchone()
                if row:
                    return True, "content_hash"

        return False, ""

    # ── Article Operations ────────────────────────────────────────────────────

    def insert_article(self, article: Article) -> bool:
        """
        Insert an article record.
        Returns True if inserted, False if skipped due to duplicate constraint.
        """
        # Final safety check against duplicates
        is_dup, _ = self.check_duplicate(
            url=article.url,
            content_hash=article.content_hash,
            article_id=article.article_id,
        )
        if is_dup:
            return False

        with self.connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO thn_articles (
                        article_id, source, title, url, author, published_at,
                        collected_at, category, tags, summary, content, content_hash,
                        updated_at, raw_html_path, cve_ids, threat_actors,
                        malware_families, target_sectors, attack_techniques, analysis_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        article.article_id,
                        article.source,
                        article.title,
                        article.url,
                        article.author,
                        article.published_at,
                        article.collected_at,
                        article.category,
                        json.dumps(article.tags or []),
                        article.summary,
                        article.content,
                        article.content_hash,
                        article.updated_at,
                        article.raw_html_path,
                        json.dumps(article.cve_ids or []),
                        json.dumps(article.threat_actors or []),
                        json.dumps(article.malware_families or []),
                        json.dumps(article.target_sectors or []),
                        json.dumps(article.attack_techniques or []),
                        article.analysis_status,
                    ),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_article_by_id(self, article_id: str) -> Optional[Article]:
        """Fetch article by article_id."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM thn_articles WHERE article_id = ? LIMIT 1",
                (article_id,),
            ).fetchone()
            if row:
                return Article.from_dict(dict(row))
        return None

    def get_article_by_url(self, url: str) -> Optional[Article]:
        """Fetch article by URL."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM thn_articles WHERE url = ? LIMIT 1",
                (url,),
            ).fetchone()
            if row:
                return Article.from_dict(dict(row))
        return None

    def get_article_by_content_hash(self, content_hash: str) -> Optional[Article]:
        """Fetch article by content hash to detect duplicate/syndicated reports."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM thn_articles WHERE content_hash = ? LIMIT 1",
                (content_hash,),
            ).fetchone()
            if row:
                return Article.from_dict(dict(row))
        return None

    def is_content_hash_duplicate(self, content_hash: str) -> bool:
        """Check if an article with the given content hash already exists."""
        return self.get_article_by_content_hash(content_hash) is not None


    def get_articles(self, limit: int = 50, offset: int = 0) -> list[Article]:
        """Fetch recent articles ordered by published_at DESC."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM thn_articles ORDER BY published_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [Article.from_dict(dict(r)) for r in rows]

    def get_article_count(self) -> int:
        """Return total count of stored articles."""
        with self.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM thn_articles").fetchone()
            return int(row["cnt"]) if row else 0

    def search_articles_fts(self, query: str, limit: int = 20) -> list[Article]:
        """Execute full-text search against FTS5 table."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT a.* FROM thn_articles a
                JOIN thn_articles_fts f ON a.rowid = f.rowid
                WHERE thn_articles_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()
            return [Article.from_dict(dict(r)) for r in rows]

    # ── Collection Runs ────────────────────────────────────────────────────────

    def record_run_start(self, mode: str, source: str = "thehackernews") -> str:
        """Create an initial running entry for a collection job."""
        import uuid
        run_id = f"run_{uuid.uuid4().hex[:12]}"
        now = utc_now_iso()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO collection_runs (
                    run_id, started_at, source, mode, status
                ) VALUES (?, ?, ?, ?, 'running')
                """,
                (run_id, now, source, mode),
            )
            conn.commit()
        return run_id

    def complete_run(self, run: CollectionRun) -> None:
        """Update a collection run with final metrics and status."""
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE collection_runs SET
                    completed_at = ?,
                    discovered_count = ?,
                    new_count = ?,
                    duplicate_count = ?,
                    failed_count = ?,
                    status = ?,
                    error_summary = ?,
                    metadata = ?
                WHERE run_id = ?
                """,
                (
                    run.completed_at or utc_now_iso(),
                    run.discovered_count,
                    run.new_count,
                    run.duplicate_count,
                    run.failed_count,
                    run.status,
                    run.error_summary,
                    json.dumps(run.metadata or {}),
                    run.run_id,
                ),
            )
            conn.commit()

    def get_latest_runs(self, limit: int = 10) -> list[CollectionRun]:
        """Retrieve recent collection runs."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM collection_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [CollectionRun.from_dict(dict(r)) for r in rows]

    # ── Checkpoints ───────────────────────────────────────────────────────────

    def get_checkpoint(self, job_name: str) -> Optional[CollectionCheckpoint]:
        """Fetch saved checkpoint for a given job."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM collection_checkpoints WHERE job_name = ? LIMIT 1",
                (job_name,),
            ).fetchone()
            if row:
                return CollectionCheckpoint.from_dict(dict(row))
        return None

    def save_checkpoint(self, checkpoint: CollectionCheckpoint) -> None:
        """Upsert a collection checkpoint."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO collection_checkpoints (
                    job_name, last_run_at, last_article_id, last_published_at,
                    cursor_offset, articles_collected, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_name) DO UPDATE SET
                    last_run_at = excluded.last_run_at,
                    last_article_id = excluded.last_article_id,
                    last_published_at = excluded.last_published_at,
                    cursor_offset = excluded.cursor_offset,
                    articles_collected = excluded.articles_collected,
                    status = excluded.status
                """,
                (
                    checkpoint.job_name,
                    checkpoint.last_run_at or utc_now_iso(),
                    checkpoint.last_article_id,
                    checkpoint.last_published_at,
                    checkpoint.cursor_offset,
                    checkpoint.articles_collected,
                    checkpoint.status,
                ),
            )
            conn.commit()

    # ── Phase 2 Article Analysis Operations ───────────────────────────────────

    def save_analysis(self, analysis: ArticleAnalysis) -> bool:
        """
        Save or update an article analysis record.
        Also updates the corresponding thn_articles summary fields and analysis_status.
        """
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO article_analysis (
                    analysis_id, article_id, analysis_version, analysis_status,
                    analysis_model, analysis_started_at, analysis_completed_at, analysis_error,
                    title, source, url, published_at, category, summary,
                    threat_types, attack_types, attack_vectors, threat_actors, threat_groups,
                    malware, ransomware, vulnerabilities, cves, cvss,
                    affected_products, affected_vendors, affected_versions,
                    target_sectors, target_countries, target_organizations,
                    technical_explanation, mitre_attack, iocs, tools, technologies,
                    impact, detection_methods, mitigation, remediation,
                    security_recommendations, severity, severity_reason,
                    confidence, facts, inferences, raw_llm_response,
                    created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(article_id, analysis_version) DO UPDATE SET
                    analysis_id = excluded.analysis_id,
                    analysis_status = excluded.analysis_status,
                    analysis_model = excluded.analysis_model,
                    analysis_started_at = excluded.analysis_started_at,
                    analysis_completed_at = excluded.analysis_completed_at,
                    analysis_error = excluded.analysis_error,
                    title = excluded.title,
                    source = excluded.source,
                    url = excluded.url,
                    published_at = excluded.published_at,
                    category = excluded.category,
                    summary = excluded.summary,
                    threat_types = excluded.threat_types,
                    attack_types = excluded.attack_types,
                    attack_vectors = excluded.attack_vectors,
                    threat_actors = excluded.threat_actors,
                    threat_groups = excluded.threat_groups,
                    malware = excluded.malware,
                    ransomware = excluded.ransomware,
                    vulnerabilities = excluded.vulnerabilities,
                    cves = excluded.cves,
                    cvss = excluded.cvss,
                    affected_products = excluded.affected_products,
                    affected_vendors = excluded.affected_vendors,
                    affected_versions = excluded.affected_versions,
                    target_sectors = excluded.target_sectors,
                    target_countries = excluded.target_countries,
                    target_organizations = excluded.target_organizations,
                    technical_explanation = excluded.technical_explanation,
                    mitre_attack = excluded.mitre_attack,
                    iocs = excluded.iocs,
                    tools = excluded.tools,
                    technologies = excluded.technologies,
                    impact = excluded.impact,
                    detection_methods = excluded.detection_methods,
                    mitigation = excluded.mitigation,
                    remediation = excluded.remediation,
                    security_recommendations = excluded.security_recommendations,
                    severity = excluded.severity,
                    severity_reason = excluded.severity_reason,
                    confidence = excluded.confidence,
                    facts = excluded.facts,
                    inferences = excluded.inferences,
                    raw_llm_response = excluded.raw_llm_response,
                    updated_at = excluded.updated_at
                """,
                (
                    analysis.analysis_id,
                    analysis.article_id,
                    analysis.analysis_version,
                    analysis.analysis_status,
                    analysis.analysis_model,
                    analysis.analysis_started_at,
                    analysis.analysis_completed_at,
                    analysis.analysis_error,
                    analysis.title,
                    analysis.source,
                    analysis.url,
                    analysis.published_at,
                    analysis.category,
                    analysis.summary,
                    json.dumps(analysis.threat_types or []),
                    json.dumps(analysis.attack_types or []),
                    json.dumps(analysis.attack_vectors or []),
                    json.dumps(analysis.threat_actors or []),
                    json.dumps(analysis.threat_groups or []),
                    json.dumps(analysis.malware or []),
                    json.dumps(analysis.ransomware or []),
                    json.dumps(analysis.vulnerabilities or []),
                    json.dumps(analysis.cves or []),
                    json.dumps(analysis.cvss or {}),
                    json.dumps(analysis.affected_products or []),
                    json.dumps(analysis.affected_vendors or []),
                    json.dumps(analysis.affected_versions or []),
                    json.dumps(analysis.target_sectors or []),
                    json.dumps(analysis.target_countries or []),
                    json.dumps(analysis.target_organizations or []),
                    json.dumps(analysis.technical_explanation or {}),
                    json.dumps(analysis.mitre_attack or []),
                    json.dumps(analysis.iocs or []),
                    json.dumps(analysis.tools or []),
                    json.dumps(analysis.technologies or []),
                    json.dumps(analysis.impact or {}),
                    json.dumps(analysis.detection_methods or []),
                    json.dumps(analysis.mitigation or []),
                    json.dumps(analysis.remediation or []),
                    json.dumps(analysis.security_recommendations or []),
                    analysis.severity,
                    analysis.severity_reason,
                    analysis.confidence,
                    json.dumps(analysis.facts or []),
                    json.dumps(analysis.inferences or []),
                    analysis.raw_llm_response,
                    analysis.created_at or utc_now_iso(),
                    analysis.updated_at or utc_now_iso(),
                ),
            )

            # Synchronize core entity tags back to thn_articles for high-speed indexing & backward compatibility
            if analysis.analysis_status == "completed":
                technique_names = [
                    m.get("technique_id") or m.get("technique_name", "")
                    for m in (analysis.mitre_attack or [])
                    if isinstance(m, dict)
                ]
                conn.execute(
                    """
                    UPDATE thn_articles SET
                        analysis_status = 'completed',
                        cve_ids = ?,
                        threat_actors = ?,
                        malware_families = ?,
                        target_sectors = ?,
                        attack_techniques = ?,
                        updated_at = ?
                    WHERE article_id = ?
                    """,
                    (
                        json.dumps(analysis.cves or []),
                        json.dumps(analysis.threat_actors or []),
                        json.dumps((analysis.malware or []) + (analysis.ransomware or [])),
                        json.dumps(analysis.target_sectors or []),
                        json.dumps([t for t in technique_names if t]),
                        utc_now_iso(),
                        analysis.article_id,
                    ),
                )
            elif analysis.analysis_status == "failed":
                conn.execute(
                    "UPDATE thn_articles SET analysis_status = 'failed', updated_at = ? WHERE article_id = ?",
                    (utc_now_iso(), analysis.article_id),
                )
            elif analysis.analysis_status == "processing":
                conn.execute(
                    "UPDATE thn_articles SET analysis_status = 'processing', updated_at = ? WHERE article_id = ?",
                    (utc_now_iso(), analysis.article_id),
                )

            conn.commit()
            return True

    def get_analysis(self, article_id: str, version: str = "v1") -> Optional[ArticleAnalysis]:
        """Fetch analysis by article_id and version."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM article_analysis WHERE article_id = ? AND analysis_version = ? LIMIT 1",
                (article_id, version),
            ).fetchone()
            if row:
                return ArticleAnalysis.from_dict(dict(row))
        return None

    def get_latest_analysis(self, article_id: str) -> Optional[ArticleAnalysis]:
        """Fetch the most recent analysis record for an article regardless of version."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM article_analysis
                WHERE article_id = ?
                ORDER BY analysis_completed_at DESC, updated_at DESC
                LIMIT 1
                """,
                (article_id,),
            ).fetchone()
            if row:
                return ArticleAnalysis.from_dict(dict(row))
        return None

    def get_analysis_by_article_id(self, article_id: str) -> Optional[ArticleAnalysis]:
        """Fetch analysis by article ID (returns the latest analysis)."""
        return self.get_latest_analysis(article_id)

    def list_analyses(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
        version: Optional[str] = None,
    ) -> list[ArticleAnalysis]:
        """Fetch list of analysis records with optional status and version filtering."""
        query = "SELECT * FROM article_analysis"
        params: list[Any] = []
        conditions: list[str] = []

        if status:
            conditions.append("analysis_status = ?")
            params.append(status)
        if version:
            conditions.append("analysis_version = ?")
            params.append(version)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [ArticleAnalysis.from_dict(dict(r)) for r in rows]

    def get_pending_analysis_articles(self, limit: int = 10, version: str = "v1") -> list[Article]:
        """
        Fetch articles that have not yet been successfully analyzed for the given version.
        Resumable: only fetches pending or unanalyzed articles, never completed ones.
        """
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT a.* FROM thn_articles a
                LEFT JOIN article_analysis an
                    ON a.article_id = an.article_id AND an.analysis_version = ?
                WHERE an.analysis_status IS NULL
                   OR an.analysis_status IN ('pending', 'failed')
                ORDER BY a.published_at DESC
                LIMIT ?
                """,
                (version, limit),
            ).fetchall()
            return [Article.from_dict(dict(r)) for r in rows]

    def update_analysis_status(
        self,
        analysis_id: str,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        """Update status and error of an existing analysis record."""
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE article_analysis
                SET analysis_status = ?, analysis_error = ?, updated_at = ?
                WHERE analysis_id = ?
                """,
                (status, error, utc_now_iso(), analysis_id),
            )
            conn.commit()

    def get_intelligence_metrics(self) -> dict[str, Any]:
        """
        Aggregate intelligence metrics for Phase 3 readiness:
        - Total analyzed articles
        - Severity distribution
        - Distinct CVE count
        - Top threat actors
        - Top malware families
        - Top target sectors
        """
        with self.connection() as conn:
            total_analyzed = conn.execute(
                "SELECT COUNT(*) FROM article_analysis WHERE analysis_status = 'completed'"
            ).fetchone()[0]

            severity_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM article_analysis
                WHERE analysis_status = 'completed'
                GROUP BY severity
                """
            ).fetchall()
            severity_counts = {r["severity"]: r["count"] for r in severity_rows}

            # Retrieve completed analyses to parse aggregate lists
            analyses_rows = conn.execute(
                """
                SELECT cves, threat_actors, malware, ransomware, target_sectors
                FROM article_analysis
                WHERE analysis_status = 'completed'
                """
            ).fetchall()

            all_cves: set[str] = set()
            actor_freq: dict[str, int] = {}
            malware_freq: dict[str, int] = {}
            sector_freq: dict[str, int] = {}

            for row in analyses_rows:
                # CVEs
                try:
                    cve_list = json.loads(row["cves"]) if row["cves"] else []
                    for c in cve_list:
                        if isinstance(c, str) and c.strip():
                            all_cves.add(c.strip().upper())
                except Exception:
                    pass

                # Threat actors
                try:
                    actors = json.loads(row["threat_actors"]) if row["threat_actors"] else []
                    for a in actors:
                        if isinstance(a, str) and a.strip():
                            actor_freq[a.strip()] = actor_freq.get(a.strip(), 0) + 1
                except Exception:
                    pass

                # Malware + Ransomware
                try:
                    mal = (json.loads(row["malware"]) if row["malware"] else []) + (
                        json.loads(row["ransomware"]) if row["ransomware"] else []
                    )
                    for m in mal:
                        if isinstance(m, str) and m.strip():
                            malware_freq[m.strip()] = malware_freq.get(m.strip(), 0) + 1
                except Exception:
                    pass

                # Sectors
                try:
                    sectors = json.loads(row["target_sectors"]) if row["target_sectors"] else []
                    for s in sectors:
                        if isinstance(s, str) and s.strip():
                            sector_freq[s.strip()] = sector_freq.get(s.strip(), 0) + 1
                except Exception:
                    pass

            top_actors = sorted(actor_freq.items(), key=lambda x: x[1], reverse=True)[:5]
            top_malware = sorted(malware_freq.items(), key=lambda x: x[1], reverse=True)[:5]
            top_sectors = sorted(sector_freq.items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "total_analyzed": total_analyzed,
                "severity_distribution": severity_counts,
                "distinct_cve_count": len(all_cves),
                "top_cves": sorted(list(all_cves))[:10],
                "top_threat_actors": dict(top_actors),
                "top_malware_families": dict(top_malware),
                "top_target_sectors": dict(top_sectors),
            }

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return system statistics summary."""
        with self.connection() as conn:
            total_articles = conn.execute("SELECT COUNT(*) FROM thn_articles").fetchone()[0]
            earliest = conn.execute("SELECT MIN(published_at) FROM thn_articles").fetchone()[0]
            latest = conn.execute("SELECT MAX(published_at) FROM thn_articles").fetchone()[0]
            total_runs = conn.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0]
            unique_authors = conn.execute("SELECT COUNT(DISTINCT author) FROM thn_articles").fetchone()[0]
            pending_analysis = conn.execute(
                "SELECT COUNT(*) FROM thn_articles WHERE analysis_status = 'pending'"
            ).fetchone()[0]

            return {
                "total_articles": total_articles,
                "earliest_article": earliest,
                "latest_article": latest,
                "total_runs": total_runs,
                "unique_authors": unique_authors,
                "pending_analysis": pending_analysis,
                "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            }

    # ── Phase 3 Temporal Analysis & Snapshot Operations ────────────────────────

    def get_analyses_in_range(
        self,
        start_iso: str,
        end_iso: str,
        version: str = "v1",
    ) -> list[ArticleAnalysis]:
        """
        Fetch completed ArticleAnalysis records published within the specified ISO UTC range.
        Optimized query using published_at index.
        """
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM article_analysis
                WHERE analysis_status = 'completed'
                  AND analysis_version = ?
                  AND published_at >= ?
                  AND published_at <= ?
                ORDER BY published_at DESC
                """,
                (version, start_iso, end_iso),
            ).fetchall()
            return [ArticleAnalysis.from_dict(dict(r)) for r in rows]

    def save_trend_snapshot(self, snapshot: TrendSnapshot) -> bool:
        """Persist or update an analytical trend snapshot."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO trend_snapshots (
                    snapshot_id, created_at, start_date, end_date,
                    metric_type, metric_name, value, previous_value,
                    change, trend_status, risk_score, confidence, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    value = excluded.value,
                    previous_value = excluded.previous_value,
                    change = excluded.change,
                    trend_status = excluded.trend_status,
                    risk_score = excluded.risk_score,
                    confidence = excluded.confidence,
                    metadata = excluded.metadata
                """,
                (
                    snapshot.snapshot_id,
                    snapshot.created_at or utc_now_iso(),
                    snapshot.start_date,
                    snapshot.end_date,
                    snapshot.metric_type,
                    snapshot.metric_name,
                    float(snapshot.value),
                    float(snapshot.previous_value) if snapshot.previous_value is not None else None,
                    float(snapshot.change) if snapshot.change is not None else None,
                    snapshot.trend_status,
                    float(snapshot.risk_score),
                    snapshot.confidence,
                    json.dumps(snapshot.metadata or {}),
                ),
            )
            conn.commit()
            return True

    def get_trend_snapshots(
        self,
        metric_type: Optional[str] = None,
        limit: int = 50,
    ) -> list[TrendSnapshot]:
        """Fetch historical snapshots with optional metric_type filter."""
        with self.connection() as conn:
            if metric_type:
                rows = conn.execute(
                    """
                    SELECT * FROM trend_snapshots
                    WHERE metric_type = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (metric_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM trend_snapshots ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [TrendSnapshot.from_dict(dict(r)) for r in rows]

    def get_freshness_timestamps(self) -> dict[str, Optional[str]]:
        """
        Track and expose data freshness:
        - last_ingestion_time (most recent article collected_at)
        - last_analysis_time (most recent analysis completed_at)
        - last_trend_calculation_time (most recent snapshot created_at)
        """
        with self.connection() as conn:
            row_ingest = conn.execute(
                "SELECT MAX(collected_at) FROM thn_articles"
            ).fetchone()
            last_ingest = row_ingest[0] if row_ingest and row_ingest[0] else None

            row_analysis = conn.execute(
                "SELECT MAX(analysis_completed_at) FROM article_analysis WHERE analysis_status = 'completed'"
            ).fetchone()
            last_analysis = row_analysis[0] if row_analysis and row_analysis[0] else None

            row_snapshot = conn.execute(
                "SELECT MAX(created_at) FROM trend_snapshots"
            ).fetchone()
            last_snapshot = row_snapshot[0] if row_snapshot and row_snapshot[0] else None

            return {
                "last_ingestion_time": last_ingest,
                "last_analysis_time": last_analysis,
                "last_trend_calculation_time": last_snapshot,
            }

    # ── Phase 3.5 MITRE ATT&CK Dataset Operations ─────────────────────────────

    def upsert_mitre_technique(self, tech: MitreTechnique) -> None:
        """Insert or update an official MITRE ATT&CK technique reference record."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO mitre_attack_dataset (
                    technique_id, technique_name, tactic_id, tactic_name,
                    description, platforms, data_sources, detection_guidance,
                    version, is_subtechnique, parent_technique_id, url, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(technique_id) DO UPDATE SET
                    technique_name=excluded.technique_name,
                    tactic_id=excluded.tactic_id,
                    tactic_name=excluded.tactic_name,
                    description=excluded.description,
                    platforms=excluded.platforms,
                    data_sources=excluded.data_sources,
                    detection_guidance=excluded.detection_guidance,
                    version=excluded.version,
                    is_subtechnique=excluded.is_subtechnique,
                    parent_technique_id=excluded.parent_technique_id,
                    url=excluded.url,
                    updated_at=excluded.updated_at
                """,
                (
                    tech.technique_id,
                    tech.technique_name,
                    tech.tactic_id,
                    tech.tactic_name,
                    tech.description,
                    json.dumps(tech.platforms),
                    json.dumps(tech.data_sources),
                    tech.detection_guidance,
                    tech.version,
                    1 if tech.is_subtechnique else 0,
                    tech.parent_technique_id,
                    tech.url,
                    tech.updated_at or utc_now_iso(),
                ),
            )
            conn.commit()

    def get_mitre_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Fetch official technique reference by technique ID (e.g. 'T1059.001')."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM mitre_attack_dataset WHERE technique_id = ? LIMIT 1",
                (technique_id.strip().upper(),),
            ).fetchone()
            if row:
                return MitreTechnique.from_dict(dict(row))
        return None

    def get_all_mitre_techniques(self, limit: int = 1000) -> list[MitreTechnique]:
        """Fetch all official MITRE ATT&CK techniques stored in reference dataset."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM mitre_attack_dataset ORDER BY technique_id ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [MitreTechnique.from_dict(dict(r)) for r in rows]

    def search_mitre_techniques(self, query: str, limit: int = 20) -> list[MitreTechnique]:
        """Search techniques by ID, name, or description."""
        q = f"%{query.strip()}%"
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM mitre_attack_dataset
                WHERE technique_id LIKE ? OR technique_name LIKE ? OR description LIKE ?
                ORDER BY technique_id ASC LIMIT ?
                """,
                (q, q, q, limit),
            ).fetchall()
            return [MitreTechnique.from_dict(dict(r)) for r in rows]

    # ── Phase 3.5 OWASP Top 10 Reference Operations ───────────────────────────

    def upsert_owasp_category(self, cat: OwaspCategory) -> None:
        """Insert or update an official OWASP Top 10 category record."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO owasp_top10_dataset (
                    category_id, category_name, year, description,
                    common_cwes, prevention_guidance, safe_lab_exercise, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(category_id) DO UPDATE SET
                    category_name=excluded.category_name,
                    year=excluded.year,
                    description=excluded.description,
                    common_cwes=excluded.common_cwes,
                    prevention_guidance=excluded.prevention_guidance,
                    safe_lab_exercise=excluded.safe_lab_exercise,
                    updated_at=excluded.updated_at
                """,
                (
                    cat.category_id,
                    cat.category_name,
                    cat.year,
                    cat.description,
                    json.dumps(cat.common_cwes),
                    cat.prevention_guidance,
                    cat.safe_lab_exercise,
                    cat.updated_at or utc_now_iso(),
                ),
            )
            conn.commit()

    def get_owasp_category(self, category_id: str) -> Optional[OwaspCategory]:
        """Fetch OWASP category by ID (e.g. 'A01:2025')."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM owasp_top10_dataset WHERE category_id = ? LIMIT 1",
                (category_id.strip(),),
            ).fetchone()
            if row:
                return OwaspCategory.from_dict(dict(row))
        return None

    def get_all_owasp_categories(self) -> list[OwaspCategory]:
        """Fetch all OWASP Top 10 2025 categories."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM owasp_top10_dataset ORDER BY category_id ASC"
            ).fetchall()
            return [OwaspCategory.from_dict(dict(r)) for r in rows]

    # ── Phase 3.5 Article Framework Mappings ──────────────────────────────────

    def save_framework_mapping(self, mapping: ArticleFrameworkMapping) -> None:
        """Persist an evidence-backed framework mapping (ATT&CK or OWASP)."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO article_framework_mappings (
                    mapping_id, article_id, framework, framework_item_id,
                    framework_item_name, evidence_text, mapping_method,
                    confidence, dataset_version, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(article_id, framework, framework_item_id) DO UPDATE SET
                    framework_item_name=excluded.framework_item_name,
                    evidence_text=excluded.evidence_text,
                    mapping_method=excluded.mapping_method,
                    confidence=excluded.confidence,
                    dataset_version=excluded.dataset_version,
                    metadata=excluded.metadata,
                    created_at=excluded.created_at
                """,
                (
                    mapping.mapping_id,
                    mapping.article_id,
                    mapping.framework,
                    mapping.framework_item_id,
                    mapping.framework_item_name,
                    mapping.evidence_text,
                    mapping.mapping_method,
                    mapping.confidence,
                    mapping.dataset_version,
                    json.dumps(mapping.metadata),
                    mapping.created_at or utc_now_iso(),
                ),
            )
            conn.commit()

    def get_framework_mappings_for_article(
        self,
        article_id: str,
        framework: Optional[str] = None,
    ) -> list[ArticleFrameworkMapping]:
        """Retrieve all framework mappings (ATT&CK or OWASP) for an article."""
        with self.connection() as conn:
            if framework:
                rows = conn.execute(
                    """
                    SELECT * FROM article_framework_mappings
                    WHERE article_id = ? AND framework = ?
                    ORDER BY confidence DESC, framework_item_id ASC
                    """,
                    (article_id, framework),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM article_framework_mappings
                    WHERE article_id = ?
                    ORDER BY framework ASC, confidence DESC
                    """,
                    (article_id,),
                ).fetchall()
            return [ArticleFrameworkMapping.from_dict(dict(r)) for r in rows]

    def get_articles_for_framework_item(
        self,
        framework: str,
        item_id: str,
        limit: int = 50,
    ) -> list[ArticleFrameworkMapping]:
        """Fetch all article mappings referencing a specific framework item ID."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM article_framework_mappings
                WHERE framework = ? AND framework_item_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (framework, item_id, limit),
            ).fetchall()
            return [ArticleFrameworkMapping.from_dict(dict(r)) for r in rows]

    # ── Phase 3.5 Unified Intelligence Links ──────────────────────────────────

    def save_unified_link(self, link: UnifiedLink) -> None:
        """Persist a normalized cross-entity link with strict provenance."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO unified_intelligence_links (
                    link_id, source_type, source_id, relationship,
                    target_type, target_id, provenance, evidence_text,
                    supporting_article_id, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_type, source_id, relationship, target_type, target_id) DO UPDATE SET
                    provenance=excluded.provenance,
                    evidence_text=excluded.evidence_text,
                    supporting_article_id=excluded.supporting_article_id,
                    confidence=excluded.confidence,
                    created_at=excluded.created_at
                """,
                (
                    link.link_id,
                    link.source_type,
                    link.source_id,
                    link.relationship,
                    link.target_type,
                    link.target_id,
                    link.provenance,
                    link.evidence_text,
                    link.supporting_article_id,
                    link.confidence,
                    link.created_at or utc_now_iso(),
                ),
            )
            conn.commit()

    def get_unified_links(
        self,
        source_type: Optional[str] = None,
        source_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[UnifiedLink]:
        """Retrieve unified relationships, optionally filtered by source entity."""
        with self.connection() as conn:
            if source_type and source_id:
                rows = conn.execute(
                    """
                    SELECT * FROM unified_intelligence_links
                    WHERE source_type = ? AND source_id = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (source_type, source_id, limit),
                ).fetchall()
            elif source_type:
                rows = conn.execute(
                    """
                    SELECT * FROM unified_intelligence_links
                    WHERE source_type = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (source_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM unified_intelligence_links ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [UnifiedLink.from_dict(dict(r)) for r in rows]

    # ── Phase 3.5 Connector Health Monitoring ─────────────────────────────────

    def record_connector_status(self, health: ConnectorHealth) -> None:
        """Record health, status, latency, and telemetry for an intelligence connector."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO connector_health (
                    connector_id, connector_name, status, last_run_at,
                    last_successful_run_at, records_processed, last_error,
                    data_freshness, config_summary, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(connector_id) DO UPDATE SET
                    connector_name=excluded.connector_name,
                    status=excluded.status,
                    last_run_at=excluded.last_run_at,
                    last_successful_run_at=excluded.last_successful_run_at,
                    records_processed=excluded.records_processed,
                    last_error=excluded.last_error,
                    data_freshness=excluded.data_freshness,
                    config_summary=excluded.config_summary,
                    updated_at=excluded.updated_at
                """,
                (
                    health.connector_id,
                    health.connector_name,
                    health.status,
                    health.last_run_at,
                    health.last_successful_run_at,
                    health.records_processed,
                    health.last_error,
                    health.data_freshness,
                    json.dumps(health.config_summary),
                    health.updated_at or utc_now_iso(),
                ),
            )
            conn.commit()

    def get_all_connector_statuses(self) -> list[ConnectorHealth]:
        """Fetch latest health status for all registered connectors."""
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM connector_health ORDER BY connector_name ASC"
            ).fetchall()
            return [ConnectorHealth.from_dict(dict(r)) for r in rows]

    def get_connector_status(self, connector_id: str) -> Optional[ConnectorHealth]:
        """Fetch health status for a specific connector."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM connector_health WHERE connector_id = ? LIMIT 1",
                (connector_id,),
            ).fetchone()
            if row:
                return ConnectorHealth.from_dict(dict(row))
        return None

    # ── Phase 3.5 User Learning Profiles ──────────────────────────────────────

    def get_or_create_learning_profile(self, user_id: str = "default") -> UserLearningProfile:
        """Fetch user learning profile or create a default intermediate profile."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM user_learning_profiles WHERE user_id = ? LIMIT 1",
                (user_id,),
            ).fetchone()
            if row:
                return UserLearningProfile.from_dict(dict(row))

        # Create default profile
        profile = UserLearningProfile(user_id=user_id, preferred_level="intermediate")
        self.update_learning_profile(profile)
        return profile

    def update_learning_profile(self, profile: UserLearningProfile) -> None:
        """Update or insert user learning preferences and challenge progress."""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO user_learning_profiles (
                    user_id, preferred_level, topics_covered,
                    completed_challenges, quiz_scores, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    preferred_level=excluded.preferred_level,
                    topics_covered=excluded.topics_covered,
                    completed_challenges=excluded.completed_challenges,
                    quiz_scores=excluded.quiz_scores,
                    updated_at=excluded.updated_at
                """,
                (
                    profile.user_id,
                    profile.preferred_level,
                    json.dumps(profile.topics_covered),
                    json.dumps(profile.completed_challenges),
                    json.dumps(profile.quiz_scores),
                    utc_now_iso(),
                ),
            )
            conn.commit()

    # ── Dedicated Information Pages ──────────────────────────────────────────

    def save_information_page(self, page: InformationPage) -> None:
        """Persist or update an information page record."""
        now = utc_now_iso()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO information_pages (
                    id, title, summary, content, content_format,
                    category, tags, presentation_type, source_references,
                    table_of_contents, related_topics, follow_up_questions,
                    metadata, model_provider, generation_status,
                    related_project_id, user_bookmarked, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    summary=excluded.summary,
                    content=excluded.content,
                    content_format=excluded.content_format,
                    category=excluded.category,
                    tags=excluded.tags,
                    presentation_type=excluded.presentation_type,
                    source_references=excluded.source_references,
                    table_of_contents=excluded.table_of_contents,
                    related_topics=excluded.related_topics,
                    follow_up_questions=excluded.follow_up_questions,
                    metadata=excluded.metadata,
                    model_provider=excluded.model_provider,
                    generation_status=excluded.generation_status,
                    related_project_id=excluded.related_project_id,
                    user_bookmarked=excluded.user_bookmarked,
                    updated_at=excluded.updated_at
                """,
                (
                    page.id,
                    page.title,
                    page.summary,
                    page.content,
                    page.content_format,
                    page.category,
                    json.dumps(page.tags),
                    page.presentation_type,
                    json.dumps(page.source_references),
                    json.dumps(page.table_of_contents),
                    json.dumps(page.related_topics),
                    json.dumps(page.follow_up_questions),
                    json.dumps(page.metadata),
                    page.model_provider,
                    page.generation_status,
                    page.related_project_id,
                    1 if page.user_bookmarked else 0,
                    page.created_at or now,
                    now,
                ),
            )
            conn.commit()

    def get_information_page(self, page_id: str) -> Optional[InformationPage]:
        """Fetch a single information page by its unique identifier."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM information_pages WHERE id = ? LIMIT 1",
                (page_id,),
            ).fetchone()
            if row:
                return InformationPage.from_dict(dict(row))
        return None

    def list_information_pages(
        self,
        category: Optional[str] = None,
        presentation_type: Optional[str] = None,
        bookmarked_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[InformationPage]:
        """Retrieve paginated list of information pages with optional filtering."""
        query = "SELECT * FROM information_pages WHERE 1=1"
        params: list[Any] = []

        if category:
            query += " AND category = ?"
            params.append(category)

        if presentation_type:
            query += " AND presentation_type = ?"
            params.append(presentation_type)

        if bookmarked_only:
            query += " AND user_bookmarked = 1"

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [InformationPage.from_dict(dict(r)) for r in rows]

    def search_information_pages(self, query: str, limit: int = 20) -> list[InformationPage]:
        """Perform full-text search across title, summary, content, and tags."""
        clean_q = query.strip()
        if not clean_q:
            return self.list_information_pages(limit=limit)

        with self.connection() as conn:
            # First try FTS5 match
            try:
                # Sanitize query for FTS5 (remove special characters that break syntax)
                safe_fts = "".join(c for c in clean_q if c.isalnum() or c.isspace()).strip()
                if safe_fts:
                    fts_term = " OR ".join(f'"{word}"*' for word in safe_fts.split() if word)
                    rows = conn.execute(
                        """
                        SELECT ip.* FROM information_pages ip
                        JOIN information_pages_fts fts ON ip.rowid = fts.rowid
                        WHERE information_pages_fts MATCH ?
                        ORDER BY bm25(information_pages_fts)
                        LIMIT ?
                        """,
                        (fts_term, limit),
                    ).fetchall()
                    if rows:
                        return [InformationPage.from_dict(dict(r)) for r in rows]
            except Exception:
                pass

            # Fallback to LIKE query across title, summary, content
            like_term = f"%{clean_q}%"
            rows = conn.execute(
                """
                SELECT * FROM information_pages
                WHERE title LIKE ? OR summary LIKE ? OR content LIKE ? OR tags LIKE ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (like_term, like_term, like_term, like_term, limit),
            ).fetchall()
            return [InformationPage.from_dict(dict(r)) for r in rows]

    def toggle_page_bookmark(self, page_id: str, bookmarked: Optional[bool] = None) -> bool:
        """Toggle or explicitly set bookmark status for a page. Returns new status."""
        with self.connection() as conn:
            if bookmarked is None:
                row = conn.execute(
                    "SELECT user_bookmarked FROM information_pages WHERE id = ? LIMIT 1",
                    (page_id,),
                ).fetchone()
                if not row:
                    return False
                new_state = 0 if row["user_bookmarked"] else 1
            else:
                new_state = 1 if bookmarked else 0

            conn.execute(
                "UPDATE information_pages SET user_bookmarked = ?, updated_at = ? WHERE id = ?",
                (new_state, utc_now_iso(), page_id),
            )
            conn.commit()
            return bool(new_state)

    def delete_information_page(self, page_id: str) -> bool:
        """Delete an information page by its ID. Returns True if deleted."""
        with self.connection() as conn:
            cursor = conn.execute("DELETE FROM information_pages WHERE id = ?", (page_id,))
            conn.commit()
            return cursor.rowcount > 0

    def find_existing_page_by_title_or_query(self, query: str) -> Optional[InformationPage]:
        """Find an existing page that closely matches the query within recent records to avoid duplicates."""
        norm_q = query.strip().lower()
        if not norm_q:
            return None

        words = [w for w in re.findall(r"[a-zA-Z0-9&+-]{3,}", norm_q) if w not in ("jarvis", "explain", "detail", "tell", "show", "give", "please")]

        with self.connection() as conn:
            # 1. Exact or substring match in title or metadata (stores original_query)
            row = conn.execute(
                """
                SELECT * FROM information_pages
                WHERE LOWER(title) = ?
                   OR LOWER(title) LIKE ?
                   OR LOWER(metadata) LIKE ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (norm_q, f"%{norm_q[:40]}%", f"%{norm_q[:40]}%"),
            ).fetchone()
            if row:
                return InformationPage.from_dict(dict(row))

            # 2. Check if key significant words all match title or summary
            if len(words) >= 2:
                conditions = " AND ".join(["(LOWER(title) LIKE ? OR LOWER(summary) LIKE ?)" for _ in words])
                params = []
                for w in words:
                    params.extend([f"%{w}%", f"%{w}%"])
                row = conn.execute(
                    f"SELECT * FROM information_pages WHERE {conditions} ORDER BY created_at DESC LIMIT 1",
                    tuple(params),
                ).fetchone()
                if row:
                    return InformationPage.from_dict(dict(row))

        return None
