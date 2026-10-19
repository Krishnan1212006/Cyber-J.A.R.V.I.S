"""
ATT&CK Navigator Layer Engine for JARVIS (attack-navigator).
Implements the official MITRE ATT&CK Navigator Layer Specification (v4.5).
Generates ready-to-load JSON layers for the ATT&CK Navigator web application.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from intel.mitre_attack_stix import MitreStixEngine

logger = logging.getLogger("jarvis.intel.navigator")

NAVIGATOR_VERSION = "4.5"
ATTACK_VERSION = "16"
DEFAULT_DOMAIN = "enterprise-attack"


class AttackNavigatorEngine:
    """Creates, scores, and exports MITRE ATT&CK Navigator layers."""

    @staticmethod
    def create_layer_dict(
        name: str,
        description: str,
        technique_scores: dict[str, float],
        technique_comments: Optional[dict[str, str]] = None,
        gradient_colors: Optional[list[str]] = None,
        domain: str = DEFAULT_DOMAIN,
    ) -> dict[str, Any]:
        """
        Creates a dictionary compliant with ATT&CK Navigator v4.5 schema.
        technique_scores: { "T1059.001": 85.0, "T1190": 100.0 }
        """
        technique_comments = technique_comments or {}
        gradient = gradient_colors or ["#ffffff", "#f59e0b", "#dc2626"]

        techniques_list = []
        for tech_id, score in technique_scores.items():
            entry: dict[str, Any] = {
                "techniqueID": tech_id,
                "score": round(score, 1),
                "enabled": True,
            }
            if tech_id in technique_comments:
                entry["comment"] = technique_comments[tech_id]
            techniques_list.append(entry)

        min_val = min(technique_scores.values()) if technique_scores else 0
        max_val = max(technique_scores.values()) if technique_scores else 100

        layer = {
            "name": name,
            "versions": {
                "attack": ATTACK_VERSION,
                "navigator": NAVIGATOR_VERSION,
                "layer": "4.5",
            },
            "domain": domain,
            "description": description,
            "filters": {
                "platforms": ["Linux", "Windows", "macOS", "Network", "PRE"],
            },
            "sorting": 3,  # sort by score descending
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
                "showSubtechniques": "expanded",
            },
            "hideDisabled": False,
            "techniques": techniques_list,
            "gradient": {
                "colors": gradient,
                "minValue": min_val,
                "maxValue": max_val if max_val > min_val else min_val + 10,
            },
            "legendItems": [
                {"label": "Low / Informational", "color": gradient[0]},
                {"label": "Medium Risk / Indirect Threat", "color": gradient[1]},
                {"label": "High / Critical Exploit Target", "color": gradient[2]},
            ],
            "metadata": [
                {"name": "generated_by", "value": "JARVIS Cyber Defense Intelligence"},
                {"name": "timestamp", "value": datetime.now(timezone.utc).isoformat()},
            ],
        }
        return layer

    @classmethod
    def generate_adversary_layer(cls, group_name_or_id: str, output_path: Optional[Path] = None) -> Tuple[dict[str, Any], Path]:
        """Generates an ATT&CK Navigator layer for a specific Threat Group (e.g., APT29, Lazarus)."""
        stix = MitreStixEngine.get_instance()
        group = stix.get_group(group_name_or_id)
        if not group:
            raise ValueError(f"Threat group '{group_name_or_id}' not found in ATT&CK STIX database.")

        scores = {}
        comments = {}
        for tech in group["techniques"]:
            tid = tech["id"]
            scores[tid] = 100.0
            comments[tid] = f"Observed in campaigns by {group['name']} ({', '.join(group['aliases'][:3])})"

        clean_name = group["name"].replace(" ", "_")
        layer_dict = cls.create_layer_dict(
            name=f"Threat Actor Profile: {group['name']}",
            description=f"ATT&CK matrix techniques actively utilized by {group['name']} ({group['id']}).",
            technique_scores=scores,
            technique_comments=comments,
            gradient_colors=["#ffffff", "#ef4444", "#991b1b"],
        )

        save_path = output_path or Path(__file__).resolve().parent.parent / "data" / "security_reports" / f"navigator_layer_{clean_name}.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(json.dumps(layer_dict, indent=2), encoding="utf-8")
        return layer_dict, save_path

    @classmethod
    def generate_findings_layer(cls, target_name: str, findings: list[dict[str, Any]], output_path: Optional[Path] = None) -> Tuple[dict[str, Any], Path]:
        """Maps vulnerability assessment findings to ATT&CK technique heatmaps."""
        scores: dict[str, float] = {}
        comments: dict[str, str] = {}

        severity_weights = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0, "info": 10.0}

        for f in findings:
            title = f.get("title", "")
            sev = f.get("severity", "medium").lower()
            weight = severity_weights.get(sev, 50.0)

            # Heuristic mapping from finding to techniques if not explicitly tagged
            techniques = f.get("mitre_techniques", [])
            if not techniques:
                lower_title = title.lower()
                if "sql" in lower_title:
                    techniques.append("T1190")
                elif "xss" in lower_title:
                    techniques.append("T1189")
                elif "directory" in lower_title or "admin" in lower_title:
                    techniques.append("T1083")
                elif "port" in lower_title or "ssh" in lower_title:
                    techniques.append("T1046")
                elif "header" in lower_title:
                    techniques.append("T1557")
                else:
                    techniques.append("T1190")

            for tid in techniques:
                scores[tid] = max(scores.get(tid, 0.0), weight)
                comments[tid] = f"{title} (Severity: {sev.upper()})"

        clean_target = target_name.replace("http://", "").replace("https://", "").replace("/", "_")
        layer_dict = cls.create_layer_dict(
            name=f"Vulnerability Assessment: {target_name}",
            description=f"Adversary techniques enabled by vulnerabilities discovered on {target_name}.",
            technique_scores=scores,
            technique_comments=comments,
            gradient_colors=["#ffffff", "#eab308", "#dc2626"],
        )

        save_path = output_path or Path(__file__).resolve().parent.parent / "data" / "security_reports" / f"navigator_layer_{clean_target}.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(json.dumps(layer_dict, indent=2), encoding="utf-8")
        return layer_dict, save_path
