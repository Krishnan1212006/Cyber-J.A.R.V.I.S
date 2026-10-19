"""
Comprehensive MITRE ATT&CK STIX 2.1 Engine for JARVIS.
Integrates the official attack-stix-data repository datasets and mitreattack-python SDK.
Provides high-performance, offline querying of:
- Techniques & Sub-techniques (attack-pattern)
- Tactics (x-mitre-tactic)
- Mitigations (course-of-action)
- Threat Groups / APTs (intrusion-set)
- Software & Malware & Tools (malware, tool)
- Campaigns (campaign)
- Data Sources & Data Components (x-mitre-data-source, x-mitre-data-component)
- Full SRO Relationships (uses, mitigates, subtechnique-of, detects)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("jarvis.intel.mitre_stix")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
STIX_DIR = DATA_DIR / "attack_stix"
ENTERPRISE_STIX_FILE = STIX_DIR / "enterprise-attack.json"


class MitreStixEngine:
    """In-memory indexed STIX 2.1 engine for Enterprise MITRE ATT&CK."""

    _instance: Optional["MitreStixEngine"] = None

    @classmethod
    def get_instance(cls) -> "MitreStixEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self, stix_path: Optional[Path] = None):
        self.stix_path = stix_path or ENTERPRISE_STIX_FILE
        self.is_loaded = False
        self.version = "v16.1"

        # SDO index stores
        self.techniques: dict[str, dict[str, Any]] = {}       # T1059 -> SDO
        self.techniques_by_stix_id: dict[str, dict[str, Any]] = {}
        self.tactics: dict[str, dict[str, Any]] = {}          # TA0001 or initial-access -> SDO
        self.tactics_by_stix_id: dict[str, dict[str, Any]] = {}
        self.mitigations: dict[str, dict[str, Any]] = {}      # M1011 or stix_id -> SDO
        self.groups: dict[str, dict[str, Any]] = {}           # G0016 or name/alias -> SDO
        self.groups_by_stix_id: dict[str, dict[str, Any]] = {}
        self.software: dict[str, dict[str, Any]] = {}         # S0001 or name -> SDO
        self.software_by_stix_id: dict[str, dict[str, Any]] = {}
        self.campaigns: dict[str, dict[str, Any]] = {}        # C0015 or name -> SDO
        self.data_sources: dict[str, dict[str, Any]] = {}     # DS0001 or name -> SDO
        self.data_components: dict[str, dict[str, Any]] = {}  # stix_id -> SDO

        # Relationship graph indices: source_ref -> list[rel] and target_ref -> list[rel]
        self.rel_by_source: dict[str, list[dict[str, Any]]] = {}
        self.rel_by_target: dict[str, list[dict[str, Any]]] = {}

        self.load_dataset()

    def load_dataset(self) -> bool:
        if not self.stix_path.is_file():
            logger.warning(f"Enterprise ATT&CK STIX bundle not found at {self.stix_path}")
            return False

        try:
            raw = self.stix_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            objects = data.get("objects", [])

            for obj in objects:
                obj_type = obj.get("type")
                stix_id = obj.get("id", "")
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue

                # 1. Techniques (attack-pattern)
                if obj_type == "attack-pattern":
                    tech_id = self._extract_external_id(obj)
                    if tech_id:
                        self.techniques[tech_id.upper()] = obj
                    self.techniques_by_stix_id[stix_id] = obj

                # 2. Tactics (x-mitre-tactic)
                elif obj_type == "x-mitre-tactic":
                    tactic_id = self._extract_external_id(obj)
                    short_name = obj.get("x_mitre_shortname", "").lower()
                    name = obj.get("name", "").lower()
                    if tactic_id:
                        self.tactics[tactic_id.upper()] = obj
                    if short_name:
                        self.tactics[short_name] = obj
                    if name:
                        self.tactics[name] = obj
                    self.tactics_by_stix_id[stix_id] = obj

                # 3. Mitigations (course-of-action)
                elif obj_type == "course-of-action":
                    mit_id = self._extract_external_id(obj)
                    if mit_id:
                        self.mitigations[mit_id.upper()] = obj
                    self.mitigations[stix_id] = obj

                # 4. Threat Groups (intrusion-set)
                elif obj_type == "intrusion-set":
                    group_id = self._extract_external_id(obj)
                    name = obj.get("name", "").lower()
                    if group_id:
                        self.groups[group_id.upper()] = obj
                    if name:
                        self.groups[name] = obj
                    for alias in obj.get("aliases", []):
                        self.groups[alias.lower()] = obj
                    self.groups_by_stix_id[stix_id] = obj

                # 5. Software (malware / tool)
                elif obj_type in ("malware", "tool"):
                    soft_id = self._extract_external_id(obj)
                    name = obj.get("name", "").lower()
                    if soft_id:
                        self.software[soft_id.upper()] = obj
                    if name:
                        self.software[name] = obj
                    for alias in obj.get("x_mitre_aliases", []):
                        self.software[alias.lower()] = obj
                    self.software_by_stix_id[stix_id] = obj

                # 6. Campaigns (campaign)
                elif obj_type == "campaign":
                    camp_id = self._extract_external_id(obj)
                    name = obj.get("name", "").lower()
                    if camp_id:
                        self.campaigns[camp_id.upper()] = obj
                    if name:
                        self.campaigns[name] = obj

                # 7. Data Sources & Components
                elif obj_type == "x-mitre-data-source":
                    ds_id = self._extract_external_id(obj)
                    name = obj.get("name", "").lower()
                    if ds_id:
                        self.data_sources[ds_id.upper()] = obj
                    if name:
                        self.data_sources[name] = obj
                elif obj_type == "x-mitre-data-component":
                    self.data_components[stix_id] = obj

                # 8. Relationships
                elif obj_type == "relationship":
                    sref = obj.get("source_ref")
                    tref = obj.get("target_ref")
                    if sref:
                        self.rel_by_source.setdefault(sref, []).append(obj)
                    if tref:
                        self.rel_by_target.setdefault(tref, []).append(obj)

            self.is_loaded = True
            logger.info(
                f"Loaded MITRE ATT&CK STIX bundle: {len(self.techniques)} techniques, "
                f"{len(self.groups_by_stix_id)} groups, {len(self.software_by_stix_id)} software, "
                f"{len(self.mitigations)} mitigations."
            )
            return True
        except Exception as exc:
            logger.error(f"Failed to load ATT&CK STIX dataset: {exc}")
            return False

    @staticmethod
    def _extract_external_id(obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-enterprise-attack", "mitre-mobile-attack"):
                return ref.get("external_id", "")
        return ""

    @staticmethod
    def _extract_url(obj: dict[str, Any]) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-enterprise-attack"):
                return ref.get("url", "")
        return ""

    # -----------------------------------------------------------------------
    # Technique Queries
    # -----------------------------------------------------------------------
    def get_technique(self, query: str) -> Optional[dict[str, Any]]:
        """Lookup technique by ID (T1059, T1059.001) or exact name."""
        q = query.strip().upper()
        if q in self.techniques:
            return self._format_technique(self.techniques[q])
        # Search by name
        lower_q = query.strip().lower()
        for tech in self.techniques.values():
            if tech.get("name", "").lower() == lower_q:
                return self._format_technique(tech)
        return None

    def search_techniques(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Fuzzy search across techniques by ID, name, or description."""
        q_lower = query.strip().lower()
        results = []
        for tech in self.techniques.values():
            tech_id = self._extract_external_id(tech).upper()
            name = tech.get("name", "")
            desc = tech.get("description", "")
            if q_lower in tech_id.lower() or q_lower in name.lower() or q_lower in desc.lower():
                results.append(self._format_technique(tech))
                if len(results) >= limit:
                    break
        return results

    def _format_technique(self, obj: dict[str, Any]) -> dict[str, Any]:
        tech_id = self._extract_external_id(obj)
        stix_id = obj.get("id", "")
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", "").replace("-", " ").title())

        # Find mitigations that mitigate this technique
        mitigations = []
        for rel in self.rel_by_target.get(stix_id, []):
            if rel.get("relationship_type") == "mitigates":
                mit_sdo = self.mitigations.get(rel.get("source_ref"))
                if mit_sdo:
                    mit_id = self._extract_external_id(mit_sdo)
                    mitigations.append({
                        "id": mit_id,
                        "name": mit_sdo.get("name"),
                        "description": rel.get("description", mit_sdo.get("description", ""))[:200],
                    })

        # Find groups that use this technique
        groups = []
        for rel in self.rel_by_target.get(stix_id, []):
            if rel.get("relationship_type") == "uses":
                grp_sdo = self.groups_by_stix_id.get(rel.get("source_ref"))
                if grp_sdo:
                    grp_id = self._extract_external_id(grp_sdo)
                    groups.append({"id": grp_id, "name": grp_sdo.get("name")})

        # Find detection data sources
        data_sources = obj.get("x_mitre_data_sources", [])

        return {
            "id": tech_id,
            "stix_id": stix_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": data_sources,
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "detection_guidance": obj.get("x_mitre_detection", "Review security telemetry for anomalous behavior."),
            "url": self._extract_url(obj),
            "mitigations": mitigations,
            "adversaries_using": groups[:8],
        }

    # -----------------------------------------------------------------------
    # Threat Group (APT) Queries
    # -----------------------------------------------------------------------
    def get_group(self, query: str) -> Optional[dict[str, Any]]:
        """Lookup threat actor / APT by ID (G0016), common name, or alias (APT29, Cozy Bear)."""
        clean = query.strip().lower()
        obj = self.groups.get(clean) or self.groups.get(query.strip().upper())
        if not obj:
            return None

        stix_id = obj.get("id", "")
        group_id = self._extract_external_id(obj)

        # Find techniques used by this group
        used_techniques = []
        used_software = []
        for rel in self.rel_by_source.get(stix_id, []):
            if rel.get("relationship_type") == "uses":
                tref = rel.get("target_ref", "")
                tech_sdo = self.techniques_by_stix_id.get(tref)
                if tech_sdo:
                    used_techniques.append({
                        "id": self._extract_external_id(tech_sdo),
                        "name": tech_sdo.get("name"),
                    })
                soft_sdo = self.software_by_stix_id.get(tref)
                if soft_sdo:
                    used_software.append({
                        "id": self._extract_external_id(soft_sdo),
                        "name": soft_sdo.get("name"),
                    })

        return {
            "id": group_id,
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
            "url": self._extract_url(obj),
            "techniques_count": len(used_techniques),
            "techniques": used_techniques[:25],
            "software": used_software[:15],
        }

    # -----------------------------------------------------------------------
    # Software / Malware Queries
    # -----------------------------------------------------------------------
    def get_software(self, query: str) -> Optional[dict[str, Any]]:
        clean = query.strip().lower()
        obj = self.software.get(clean) or self.software.get(query.strip().upper())
        if not obj:
            return None

        soft_id = self._extract_external_id(obj)
        stix_id = obj.get("id", "")

        used_techniques = []
        for rel in self.rel_by_source.get(stix_id, []):
            if rel.get("relationship_type") == "uses":
                tech_sdo = self.techniques_by_stix_id.get(rel.get("target_ref"))
                if tech_sdo:
                    used_techniques.append({
                        "id": self._extract_external_id(tech_sdo),
                        "name": tech_sdo.get("name"),
                    })

        return {
            "id": soft_id,
            "name": obj.get("name", ""),
            "type": obj.get("type", "software"),
            "platforms": obj.get("x_mitre_platforms", []),
            "aliases": obj.get("x_mitre_aliases", []),
            "description": obj.get("description", ""),
            "techniques": used_techniques[:20],
        }

    # -----------------------------------------------------------------------
    # General Matrix Statistics
    # -----------------------------------------------------------------------
    def get_statistics(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "techniques_count": len(self.techniques),
            "groups_count": len(self.groups_by_stix_id),
            "software_count": len(self.software_by_stix_id),
            "mitigations_count": len(self.mitigations),
            "tactics_count": 14,
            "relationships_count": sum(len(r) for r in self.rel_by_source.values()),
        }
