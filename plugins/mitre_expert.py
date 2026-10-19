"""
MITRE ATT&CK Expert & Cyber Threat Intelligence Plugin for JARVIS.
Integrates:
- attack-stix-data & mitreattack-python (offline STIX 2.1 query engine across 650+ techniques, 160+ groups, 700+ software)
- attack-navigator (ATT&CK Navigator v4.5 JSON layer generation with heatmaps & scoring)
- attack-data-model (telemetry mappings to Sysmon, Windows Event IDs 4688/4624/4697, Linux auditd)
- attack-workbench & attack-workbench-taxii-server (TAXII 2.1 collections, STIX envelopes & workspaces)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from intel.attack_data_model import AttackDataModelEngine
from intel.mitre_attack_stix import MitreStixEngine
from intel.mitre_navigator import AttackNavigatorEngine
from intel.mitre_workbench import AttackWorkbenchEngine, TaxiiServerEngine

logger = logging.getLogger("jarvis.mitre_expert")

PLUGIN = {
    "name": "mitre_expert",
    "description": (
        "Authoritative MITRE ATT&CK cybersecurity intelligence and threat analysis. "
        "Performs deep analysis on Techniques & Sub-techniques (T-codes), Threat Actors / APT Groups "
        "(APT29, Lazarus, FIN7), Mitigations (M-codes), Detection Telemetry (Sysmon & Windows Event IDs), "
        "and generates ATT&CK Navigator JSON layers. Use whenever the user asks about MITRE ATT&CK, "
        "adversary TTPs, threat groups, detection rules, or heatmaps."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {
                "type": "STRING",
                "description": (
                    "Intelligence action: 'technique' (analyze technique ID/name), 'threat_group' (profile an APT/adversary), "
                    "'mitigations' (lookup defensive countermeasures), 'detect' (ATT&CK Data Model telemetry and event IDs), "
                    "'generate_navigator_layer' (create an ATT&CK Navigator layer JSON file), "
                    "'workbench_taxii' (query TAXII 2.1 collections and STIX statistics), "
                    "or 'search' (search entire ATT&CK matrix). Defaults to 'technique'."
                ),
            },
            "query": {
                "type": "STRING",
                "description": "Technique ID (e.g. 'T1059.001'), group name ('APT29'), software ('Mimikatz'), or search term.",
            },
            "target": {
                "type": "STRING",
                "description": "Optional target name when generating assessment layers.",
            },
        },
        "required": ["action"],
    },
}


def run(parameters: dict, player=None, session_memory=None) -> str:
    action = str(parameters.get("action", "technique")).lower().strip()
    query = str(parameters.get("query", "")).strip()
    target = str(parameters.get("target", "")).strip()

    stix = MitreStixEngine.get_instance()

    # 1. Technique Analysis
    if action in ("technique", "lookup", "technique_lookup"):
        if not query:
            return "Sir, please specify a technique ID (e.g., T1059.001, T1190) or name."

        tech = stix.get_technique(query)
        if not tech:
            # Fallback search
            matches = stix.search_techniques(query, limit=3)
            if matches:
                names = ", ".join(f"{m['id']} ({m['name']})" for m in matches)
                return f"Sir, technique '{query}' was not an exact match. Did you mean: {names}?"
            return f"Sir, technique '{query}' was not found in the MITRE ATT&CK Enterprise dataset."

        # Format details
        tactics_str = ", ".join(tech.get("tactics", []))
        platforms_str = ", ".join(tech.get("platforms", []))
        mit_count = len(tech.get("mitigations", []))
        adv_count = len(tech.get("adversaries_using", []))

        if player:
            try:
                player.write_log(f"JARVIS [MITRE ATT&CK]: {tech['id']} - {tech['name']}")
                player.write_log(f"  Tactics: {tactics_str} | Platforms: {platforms_str}")
                player.write_log(f"  Description: {tech['description'][:250]}...")
                if tech.get("mitigations"):
                    player.write_log("  Recommended Mitigations:")
                    for m in tech["mitigations"][:4]:
                        player.write_log(f"    - {m['id']}: {m['name']}")
                if tech.get("adversaries_using"):
                    player.write_log(f"  Observed Threat Actors: {', '.join(a['name'] for a in tech['adversaries_using'][:6])}")
            except Exception:
                pass

        spoken = (
            f"Sir, MITRE ATT&CK {tech['id']} is '{tech['name']}', mapped under {tactics_str}. "
            f"It targets {platforms_str} platforms and is known to be leveraged by {adv_count} tracked adversary groups. "
            f"There are {mit_count} official mitigations documented."
        )
        return spoken

    # 2. Threat Group (APT) Profiling
    if action in ("threat_group", "adversary", "group", "apt"):
        if not query:
            return "Sir, please specify a threat group name or ID (e.g. APT29, Lazarus Group, FIN7)."

        group = stix.get_group(query)
        if not group:
            return f"Sir, threat group '{query}' was not identified in the ATT&CK dataset."

        aliases_str = ", ".join(group.get("aliases", [])[:4])
        tech_count = group.get("techniques_count", 0)
        soft_count = len(group.get("software", []))

        if player:
            try:
                player.write_log(f"JARVIS [THREAT DOSSIER]: {group['name']} ({group['id']})")
                player.write_log(f"  Known Aliases: {aliases_str}")
                player.write_log(f"  Tracked TTPs: {tech_count} techniques, {soft_count} tools/malware")
                player.write_log(f"  Profile Summary: {group['description'][:300]}...")
                if group.get("techniques"):
                    player.write_log("  Top Adversary Techniques:")
                    for t in group["techniques"][:6]:
                        player.write_log(f"    - {t['id']}: {t['name']}")
            except Exception:
                pass

        spoken = (
            f"Sir, {group['name']} (also known as {aliases_str}) is a tracked threat group associated with {tech_count} "
            f"official ATT&CK techniques and {soft_count} software tools. "
            f"Top techniques include {', '.join(t['name'] for t in group.get('techniques', [])[:3])}."
        )
        return spoken

    # 3. Mitigations & Defensive Blueprint
    if action in ("mitigations", "mitigate", "defense"):
        if not query:
            return "Sir, please provide the technique ID or attack to mitigate."

        tech = stix.get_technique(query)
        if not tech or not tech.get("mitigations"):
            return f"Sir, no specific mitigations found for '{query}' in ATT&CK."

        mitigations = tech["mitigations"]
        if player:
            try:
                player.write_log(f"JARVIS [DEFENSIVE MITIGATIONS] for {tech['id']} ({tech['name']}):")
                for m in mitigations:
                    player.write_log(f"  🛡️ {m['id']} ({m['name']}): {m['description'][:140]}")
            except Exception:
                pass

        top_mits = ", ".join(m["name"] for m in mitigations[:3])
        return (
            f"Sir, to defend against {tech['id']} ({tech['name']}), MITRE recommends {len(mitigations)} mitigations, "
            f"chiefly: {top_mits}."
        )

    # 4. ATT&CK Data Model (ADM) & Telemetry Detection
    if action in ("detect", "detection", "adm", "telemetry"):
        if not query:
            return "Sir, please specify a technique ID to generate detection telemetry for."

        blueprint = AttackDataModelEngine.get_detection_blueprint(query)
        if "error" in blueprint:
            return f"Sir, {blueprint['error']}"

        telemetry_items = blueprint.get("telemetry_prerequisites", [])

        if player:
            try:
                player.write_log(f"JARVIS [ATT&CK DATA MODEL DETECTION] for {blueprint['technique_id']} ({blueprint['technique_name']}):")
                for t in telemetry_items:
                    player.write_log(f"  📡 Data Source: {t['data_source']}")
                    for src in t.get("telemetry_sources", [])[:2]:
                        player.write_log(f"     -> {src}")
                    if t.get("sample_query"):
                        player.write_log(f"     -> Rule Logic: {t['sample_query']}")
            except Exception:
                pass

        primary_sources = ", ".join(t["data_source"] for t in telemetry_items[:2])
        return (
            f"Sir, detection telemetry for {blueprint['technique_id']} requires monitoring {primary_sources}. "
            f"Specific rule logic and event IDs (such as Sysmon and Windows 4688) have been logged to the terminal."
        )

    # 5. ATT&CK Navigator Layer Generation
    if action in ("generate_navigator_layer", "navigator", "layer"):
        if not query:
            return "Sir, specify a threat group (e.g. 'APT29') or set target for vulnerability findings layer."

        try:
            layer, path = AttackNavigatorEngine.generate_adversary_layer(query)
            if player:
                try:
                    player.write_log(f"JARVIS: Generated ATT&CK Navigator Layer for {query} at {path}")
                except Exception:
                    pass
            return (
                f"Sir, official ATT&CK Navigator v4.5 JSON layer for {query} has been generated with {len(layer['techniques'])} "
                f"techniques and saved to {path.name}. It can be opened directly in the ATT&CK Navigator web application."
            )
        except Exception as exc:
            return f"Sir, failed to generate Navigator layer: {exc}"

    # 6. ATT&CK Workbench & TAXII 2.1 Status
    if action in ("workbench_taxii", "taxii", "workbench", "matrix_stats"):
        taxii = TaxiiServerEngine()
        discovery = taxii.get_server_discovery()
        collections = taxii.get_collections().get("collections", [])
        stats = stix.get_statistics()

        if player:
            try:
                player.write_log("JARVIS [ATT&CK WORKBENCH & TAXII 2.1 STATUS]:")
                player.write_log(f"  Discovery API Root: {discovery['default']}")
                player.write_log(f"  Collections: {', '.join(c['id'] for c in collections)}")
                player.write_log(f"  STIX 2.1 Dataset: {stats['techniques_count']} techniques | {stats['groups_count']} groups | {stats['relationships_count']} relationships")
            except Exception:
                pass

        return (
            f"Sir, the ATT&CK Workbench & TAXII 2.1 engine is active. "
            f"Local STIX 2.1 dataset contains {stats['techniques_count']} techniques, {stats['groups_count']} threat groups, "
            f"and {stats['relationships_count']} relationships across all 14 enterprise tactics."
        )

    # 7. Fuzzy Search
    if action in ("search", "find"):
        if not query:
            return "Sir, please provide a search term."
        matches = stix.search_techniques(query, limit=5)
        if not matches:
            return f"Sir, no ATT&CK objects found matching '{query}'."

        if player:
            try:
                player.write_log(f"JARVIS: MITRE ATT&CK Search Results for '{query}':")
                for m in matches:
                    player.write_log(f"  - {m['id']}: {m['name']} ({', '.join(m.get('tactics', []))})")
            except Exception:
                pass

        summary = ", ".join(f"{m['id']} ({m['name']})" for m in matches[:3])
        return f"Sir, found {len(matches)} matching techniques in the ATT&CK matrix: {summary}."

    return (
        "Sir, please select an action: 'technique', 'threat_group', 'mitigations', 'detect', "
        "'generate_navigator_layer', 'workbench_taxii', or 'search'."
    )
