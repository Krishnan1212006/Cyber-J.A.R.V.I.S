"""
Threat Correlation and Multi-hop Entity Relationship Engine.

Extracts direct factual relationships and cross-article correlations:
- Threat Actor -> Malware
- Threat Actor -> CVE
- Threat Actor -> MITRE Technique
- Threat Actor -> Target Sector
- Malware -> MITRE Technique
- Malware -> Target Sector
- CVE -> Affected Product / Vendor
- Cross-Article Correlation Chains
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import ArticleAnalysis


@dataclass
class ThreatRelationship:
    """Represents a validated relationship between two threat entities."""

    source_type: str
    source_name: str
    relationship: str
    target_type: str
    target_name: str
    nature: str  # 'DIRECT_FACT' | 'CROSS_ARTICLE_CORRELATION'
    evidence_article_ids: list[str] = field(default_factory=list)
    frequency: int = 1
    confidence: str = "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_name": self.source_name,
            "relationship": self.relationship,
            "target_type": self.target_type,
            "target_name": self.target_name,
            "nature": self.nature,
            "evidence_article_ids": self.evidence_article_ids,
            "frequency": self.frequency,
            "confidence": self.confidence,
        }


class ThreatCorrelationEngine:
    """Builds and analyzes relationship graphs from structured article analyses."""

    def __init__(self, min_correlation_evidence: int = 1):
        self.min_evidence = min_correlation_evidence

    def extract_relationships(
        self,
        analyses: list[ArticleAnalysis],
    ) -> list[ThreatRelationship]:
        """
        Extract direct intra-article relationships backed by explicit source statements.
        """
        # Map: (source_type, source_name, relationship, target_type, target_name) -> set(article_ids)
        rel_map: dict[tuple[str, str, str, str, str], set[str]] = {}

        for a in analyses:
            aid = a.article_id
            actors = [act.strip() for act in a.threat_actors if act.strip()]
            malware_list = [m.strip() for m in (a.malware + a.ransomware) if m.strip()]
            cves = [c.strip().upper() for c in a.cves if c.strip()]
            sectors = [s.strip() for s in a.target_sectors if s.strip()]
            products = [p.strip() for p in a.affected_products if p.strip()]
            vendors = [v.strip() for v in a.affected_vendors if v.strip()]

            techniques = []
            for item in a.mitre_attack:
                if isinstance(item, dict):
                    t_id = item.get("technique_id") or item.get("technique_name")
                    if t_id:
                        techniques.append(str(t_id).strip())

            # 1. Threat Actor -> Malware
            for actor in actors:
                for mal in malware_list:
                    key = ("threat_actor", actor, "uses_malware", "malware", mal)
                    rel_map.setdefault(key, set()).add(aid)

            # 2. Threat Actor -> CVE
            for actor in actors:
                for cve in cves:
                    key = ("threat_actor", actor, "exploits_cve", "cve", cve)
                    rel_map.setdefault(key, set()).add(aid)

            # 3. Threat Actor -> MITRE Technique
            for actor in actors:
                for tech in techniques:
                    key = ("threat_actor", actor, "employs_technique", "mitre_technique", tech)
                    rel_map.setdefault(key, set()).add(aid)

            # 4. Threat Actor -> Target Sector
            for actor in actors:
                for sec in sectors:
                    key = ("threat_actor", actor, "targets_sector", "sector", sec)
                    rel_map.setdefault(key, set()).add(aid)

            # 5. Malware -> MITRE Technique
            for mal in malware_list:
                for tech in techniques:
                    key = ("malware", mal, "employs_technique", "mitre_technique", tech)
                    rel_map.setdefault(key, set()).add(aid)

            # 6. Malware -> Target Sector
            for mal in malware_list:
                for sec in sectors:
                    key = ("malware", mal, "targets_sector", "sector", sec)
                    rel_map.setdefault(key, set()).add(aid)

            # 7. CVE -> Affected Product
            for cve in cves:
                for prod in products:
                    key = ("cve", cve, "affects_product", "product", prod)
                    rel_map.setdefault(key, set()).add(aid)

            # 8. CVE -> Affected Vendor
            for cve in cves:
                for vend in vendors:
                    key = ("cve", cve, "affects_vendor", "vendor", vend)
                    rel_map.setdefault(key, set()).add(aid)

        results: list[ThreatRelationship] = []
        for (src_type, src_name, rel, tgt_type, tgt_name), aids in rel_map.items():
            freq = len(aids)
            if freq >= self.min_evidence:
                conf = "HIGH" if freq >= 2 else "MEDIUM"
                results.append(
                    ThreatRelationship(
                        source_type=src_type,
                        source_name=src_name,
                        relationship=rel,
                        target_type=tgt_type,
                        target_name=tgt_name,
                        nature="DIRECT_FACT",
                        evidence_article_ids=sorted(list(aids)),
                        frequency=freq,
                        confidence=conf,
                    )
                )

        # Sort by frequency descending
        results.sort(key=lambda r: r.frequency, reverse=True)
        return results

    def find_cross_article_correlations(
        self,
        direct_relationships: list[ThreatRelationship],
    ) -> list[dict[str, Any]]:
        """
        Find multi-hop cross-article correlation paths:
        e.g., Actor A --(uses)--> Malware M --(employs)--> Technique T --(targets)--> Sector S.
        Clearly marked as CROSS_ARTICLE_CORRELATION rather than direct facts.
        """
        chains: list[dict[str, Any]] = []

        # Index direct relationships by source and target
        actor_to_malware = [r for r in direct_relationships if r.relationship == "uses_malware"]
        malware_to_tech = [r for r in direct_relationships if r.relationship == "employs_technique" and r.source_type == "malware"]
        malware_to_sector = [r for r in direct_relationships if r.relationship == "targets_sector" and r.source_type == "malware"]

        for a_m in actor_to_malware:
            # Check if this malware connects to techniques
            m_name = a_m.target_name
            techs = [m_t.target_name for m_t in malware_to_tech if m_t.source_name == m_name]
            secs = [m_s.target_name for m_s in malware_to_sector if m_s.source_name == m_name]

            if techs or secs:
                all_aids = set(a_m.evidence_article_ids)
                for m_t in malware_to_tech:
                    if m_t.source_name == m_name:
                        all_aids.update(m_t.evidence_article_ids)
                for m_s in malware_to_sector:
                    if m_s.source_name == m_name:
                        all_aids.update(m_s.evidence_article_ids)

                chains.append({
                    "threat_actor": a_m.source_name,
                    "malware": m_name,
                    "correlated_techniques": sorted(list(set(techs))),
                    "correlated_sectors": sorted(list(set(secs))),
                    "correlation_type": "CROSS_ARTICLE_CORRELATION",
                    "supporting_article_ids": sorted(list(all_aids)),
                    "confidence": "HIGH" if len(all_aids) >= 2 else "MEDIUM",
                })

        return chains
