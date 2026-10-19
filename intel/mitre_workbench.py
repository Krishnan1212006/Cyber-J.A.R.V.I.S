"""
ATT&CK Workbench & TAXII 2.1 Protocol Engine for JARVIS (attack-workbench-frontend & taxii-server).
Implements TAXII 2.1 server response formatting and client synchronization:
- Discovery Endpoint (/taxii2/)
- API Root Endpoint (/taxii2/enterprise/)
- Collections Registry (/taxii2/enterprise/collections/)
- Objects Querying & STIX 2.1 Envelopes (/taxii2/enterprise/collections/{id}/objects/)
- Workbench Collection & Workspace Management
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from intel.mitre_attack_stix import MitreStixEngine

logger = logging.getLogger("jarvis.intel.workbench")

TAXII_MEDIA_TYPE_21 = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE_21 = "application/stix+json;version=2.1"


class TaxiiServerEngine:
    """Emulates a compliant TAXII 2.1 server for querying ATT&CK STIX bundles."""

    def __init__(self, api_root: str = "enterprise"):
        self.api_root = api_root
        self.title = "JARVIS Autonomous Cyber Threat Intelligence TAXII Server"
        self.description = "TAXII 2.1 interface for MITRE ATT&CK Enterprise STIX 2.1 intelligence data."

    def get_server_discovery(self) -> dict[str, Any]:
        """TAXII 2.1 /taxii2/ discovery response."""
        return {
            "title": self.title,
            "description": self.description,
            "default": f"/taxii2/{self.api_root}/",
            "api_roots": [f"/taxii2/{self.api_root}/"],
        }

    def get_api_root_info(self) -> dict[str, Any]:
        """TAXII 2.1 /taxii2/{api_root}/ API Root details."""
        return {
            "title": f"MITRE ATT&CK {self.api_root.title()} Root",
            "description": "API Root serving MITRE ATT&CK STIX 2.1 datasets.",
            "versions": [TAXII_MEDIA_TYPE_21],
            "max_content_length": 104857600,  # 100 MB
        }

    def get_collections(self) -> dict[str, Any]:
        """TAXII 2.1 /taxii2/{api_root}/collections/ list."""
        stix = MitreStixEngine.get_instance()
        return {
            "collections": [
                {
                    "id": "enterprise-attack",
                    "title": "MITRE ATT&CK Enterprise",
                    "description": f"Official Enterprise ATT&CK matrix dataset ({stix.version}).",
                    "can_read": True,
                    "can_write": False,
                    "media_types": [STIX_MEDIA_TYPE_21],
                },
                {
                    "id": "workbench-custom",
                    "title": "JARVIS Custom Workbench Workspace",
                    "description": "Local workspace for organizational techniques, custom threat models, and overlays.",
                    "can_read": True,
                    "can_write": True,
                    "media_types": [STIX_MEDIA_TYPE_21],
                },
            ]
        }

    def query_objects(
        self,
        collection_id: str = "enterprise-attack",
        object_type: Optional[str] = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """TAXII 2.1 /taxii2/{api_root}/collections/{id}/objects/ endpoint."""
        stix = MitreStixEngine.get_instance()
        matched_objects: list[dict[str, Any]] = []

        if object_type == "attack-pattern" or not object_type:
            matched_objects.extend(list(stix.techniques.values())[:limit])
        if object_type == "intrusion-set" or not object_type:
            matched_objects.extend(list(stix.groups_by_stix_id.values())[:limit])
        if object_type == "malware" or object_type == "tool" or not object_type:
            matched_objects.extend(list(stix.software_by_stix_id.values())[:limit])
        if object_type == "course-of-action" or not object_type:
            matched_objects.extend(list(stix.mitigations.values())[:limit])

        trimmed = matched_objects[:limit]
        return {
            "more": len(matched_objects) > limit,
            "objects": trimmed,
            "count": len(trimmed),
        }


class AttackWorkbenchEngine:
    """Manages ATT&CK Workbench workspaces, collection export, and remote sync."""

    @classmethod
    def export_collection_bundle(cls, collection_name: str = "JARVIS-Defense-Collection") -> dict[str, Any]:
        stix = MitreStixEngine.get_instance()
        bundle_id = f"bundle--{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        # Combine sampled high-value enterprise techniques and local mitigations
        sample_objects = list(stix.techniques.values())[:50] + list(stix.mitigations.values())[:20]
        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": sample_objects,
            "x_mitre_collection": {
                "name": collection_name,
                "version": stix.version,
                "exported_at": datetime.now(timezone.utc).isoformat(),
            },
        }

    @classmethod
    def sync_remote_taxii(cls, taxii_url: str = "https://cti-taxii.mitre.org/taxii/") -> dict[str, Any]:
        """Polls remote TAXII 2.1 server for health and collection metadata."""
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                res = client.get(taxii_url, headers={"Accept": TAXII_MEDIA_TYPE_21})
                if res.status_code == 200:
                    return {
                        "status": "ONLINE",
                        "taxii_url": taxii_url,
                        "data": res.json() if res.headers.get("content-type", "").startswith("application/json") else res.text[:200],
                    }
                return {"status": "UNREACHABLE", "http_status": res.status_code}
        except Exception as exc:
            return {"status": "OFFLINE", "error": str(exc), "taxii_url": taxii_url}
