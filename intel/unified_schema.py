"""
Unified Cybersecurity Intelligence Schema and Graph Engine for JARVIS (Phase 3.5).

Links and normalizes:
- THN Articles
- CVEs & Software Flaws
- Malware & Ransomware Families
- Threat Actors & State Groups
- MITRE ATT&CK Tactics & Techniques
- OWASP Top 10 2025 Categories
- Vectra AI Observed Detections (when available)
- Risk & Trend Indicators

Enforces strict provenance classification:
1. ARTICLE_REPORTED_FACT: Explicit factual claim directly asserted by the source article.
2. OFFICIAL_FRAMEWORK_METADATA: Standard structural relationship defined by MITRE or OWASP.
3. ACTUAL_OBSERVED_DETECTION: Verified network/host telemetry observed by authorized sensors (e.g. Vectra).
4. AI_INFERENCE: Plausible technical conclusion derived from LLM analysis.
5. UNVERIFIED_HYPOTHESIS: Uncorroborated theory or potential correlation pending verification.
"""

from __future__ import annotations
import logging
from typing import Any, Optional

from .db import IntelligenceDB
from .models import (
    Article,
    ArticleAnalysis,
    ArticleFrameworkMapping,
    MitreTechnique,
    OwaspCategory,
    UnifiedLink,
    utc_now_iso,
)

logger = logging.getLogger(__name__)


class ProvenanceType:
    ARTICLE_REPORTED_FACT = "ARTICLE_REPORTED_FACT"
    OFFICIAL_FRAMEWORK_METADATA = "OFFICIAL_FRAMEWORK_METADATA"
    ACTUAL_OBSERVED_DETECTION = "ACTUAL_OBSERVED_DETECTION"
    AI_INFERENCE = "AI_INFERENCE"
    UNVERIFIED_HYPOTHESIS = "UNVERIFIED_HYPOTHESIS"


class UnifiedIntelligenceEngine:
    """Constructs and queries the unified multi-source intelligence graph."""

    def __init__(self, db: IntelligenceDB):
        self.db = db

    def synthesize_article_intelligence(
        self,
        article: Article,
        analysis: ArticleAnalysis,
        framework_mappings: Optional[list[ArticleFrameworkMapping]] = None,
    ) -> list[UnifiedLink]:
        """
        Synthesize normalized unified links for an analyzed article, recording
        concrete provenance and supporting article evidence.
        """
        if framework_mappings is None:
            framework_mappings = self.db.get_framework_mappings_for_article(article.article_id)

        links: list[UnifiedLink] = []
        aid = article.article_id
        now = utc_now_iso()

        # 1. Article -> CVEs (ARTICLE_REPORTED_FACT)
        for cve in analysis.cves:
            clean_cve = cve.strip().upper()
            if clean_cve:
                link = UnifiedLink(
                    link_id=f"link_{aid}_cve_{clean_cve.replace('-', '_')}",
                    source_type="article",
                    source_id=aid,
                    relationship="reports_vulnerability",
                    target_type="cve",
                    target_id=clean_cve,
                    provenance=ProvenanceType.ARTICLE_REPORTED_FACT,
                    evidence_text=f"Article discloses vulnerability {clean_cve}.",
                    supporting_article_id=aid,
                    confidence="HIGH",
                    created_at=now,
                )
                self.db.save_unified_link(link)
                links.append(link)

        # 2. Article -> Malware (ARTICLE_REPORTED_FACT)
        for mal in (analysis.malware + analysis.ransomware):
            clean_mal = mal.strip()
            if clean_mal:
                link = UnifiedLink(
                    link_id=f"link_{aid}_mal_{''.join(c if c.isalnum() else '_' for c in clean_mal)}",
                    source_type="article",
                    source_id=aid,
                    relationship="reports_malware",
                    target_type="malware",
                    target_id=clean_mal,
                    provenance=ProvenanceType.ARTICLE_REPORTED_FACT,
                    evidence_text=f"Article mentions malware/ransomware {clean_mal}.",
                    supporting_article_id=aid,
                    confidence="HIGH",
                    created_at=now,
                )
                self.db.save_unified_link(link)
                links.append(link)

        # 3. Article -> Threat Actors (ARTICLE_REPORTED_FACT)
        for act in analysis.threat_actors:
            clean_act = act.strip()
            if clean_act:
                link = UnifiedLink(
                    link_id=f"link_{aid}_act_{''.join(c if c.isalnum() else '_' for c in clean_act)}",
                    source_type="article",
                    source_id=aid,
                    relationship="attributes_threat_actor",
                    target_type="threat_actor",
                    target_id=clean_act,
                    provenance=ProvenanceType.ARTICLE_REPORTED_FACT,
                    evidence_text=f"Article identifies threat actor {clean_act}.",
                    supporting_article_id=aid,
                    confidence="HIGH",
                    created_at=now,
                )
                self.db.save_unified_link(link)
                links.append(link)

        # 4. Article -> Framework Mappings (MITRE ATT&CK & OWASP)
        for m in framework_mappings:
            is_explicit = (m.mapping_method in ("explicit", "confirmed"))
            prov = ProvenanceType.ARTICLE_REPORTED_FACT if is_explicit else ProvenanceType.AI_INFERENCE
            link = UnifiedLink(
                link_id=f"link_{aid}_{m.framework.lower()}_{m.framework_item_id.replace(':', '_').replace('.', '_')}",
                source_type="article",
                source_id=aid,
                relationship="mapped_to_framework",
                target_type="mitre_technique" if m.framework == "MITRE_ATTACK" else "owasp_category",
                target_id=m.framework_item_id,
                provenance=prov,
                evidence_text=m.evidence_text,
                supporting_article_id=aid,
                confidence=m.confidence,
                created_at=now,
            )
            self.db.save_unified_link(link)
            links.append(link)

        # 5. Threat Actor -> Malware (ARTICLE_REPORTED_FACT when co-reported)
        for act in analysis.threat_actors:
            for mal in (analysis.malware + analysis.ransomware):
                if act.strip() and mal.strip():
                    link = UnifiedLink(
                        link_id=f"link_act_{act.strip()}_uses_{mal.strip()}",
                        source_type="threat_actor",
                        source_id=act.strip(),
                        relationship="uses_malware",
                        target_type="malware",
                        target_id=mal.strip(),
                        provenance=ProvenanceType.ARTICLE_REPORTED_FACT,
                        evidence_text=f"Observed in article '{article.title}'",
                        supporting_article_id=aid,
                        confidence="HIGH",
                        created_at=now,
                    )
                    self.db.save_unified_link(link)
                    links.append(link)

        # 6. Malware -> MITRE Technique
        for mal in (analysis.malware + analysis.ransomware):
            for m in [fm for fm in framework_mappings if fm.framework == "MITRE_ATTACK"]:
                if mal.strip():
                    link = UnifiedLink(
                        link_id=f"link_mal_{mal.strip()}_tech_{m.framework_item_id}",
                        source_type="malware",
                        source_id=mal.strip(),
                        relationship="employs_technique",
                        target_type="mitre_technique",
                        target_id=m.framework_item_id,
                        provenance=ProvenanceType.AI_INFERENCE,
                        evidence_text=f"Malware {mal} associated with {m.framework_item_id} in {article.title}",
                        supporting_article_id=aid,
                        confidence=m.confidence,
                        created_at=now,
                    )
                    self.db.save_unified_link(link)
                    links.append(link)

        return links

    def get_unified_graph(
        self,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """
        Retrieve structured nodes and edges for intelligence graph visualization
        and multi-hop reasoning.
        """
        links = self.db.get_unified_links(source_type=entity_type, source_id=entity_id, limit=limit)
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []

        for link in links:
            # Source node
            src_key = f"{link.source_type}:{link.source_id}"
            if src_key not in nodes:
                nodes[src_key] = {"id": src_key, "name": link.source_id, "type": link.source_type}

            # Target node
            tgt_key = f"{link.target_type}:{link.target_id}"
            if tgt_key not in nodes:
                nodes[tgt_key] = {"id": tgt_key, "name": link.target_id, "type": link.target_type}

            # Edge
            edges.append({
                "source": src_key,
                "target": tgt_key,
                "relationship": link.relationship,
                "provenance": link.provenance,
                "confidence": link.confidence,
                "evidence": link.evidence_text,
                "supporting_article_id": link.supporting_article_id,
            })

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": list(nodes.values()),
            "edges": edges,
        }
