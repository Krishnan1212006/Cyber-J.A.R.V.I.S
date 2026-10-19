"""
MITRE ATT&CK Connector and Knowledge Integration for JARVIS (Phase 3.5).

Provides:
- Machine-readable official ATT&CK Enterprise dataset ingestion & version tracking (v16.1).
- Strict Technique ID validation (e.g., T1059.001) against official reference ontology.
- Tactic and technique lookup (names, descriptions, platforms, detection guidance).
- Separate storage of official framework definitions from article-derived intelligence.
- Evidence-backed mapping of THN article claims with explicit vs. inferred provenance.
"""

from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from .db import IntelligenceDB
from .models import Article, ArticleAnalysis, ArticleFrameworkMapping, MitreTechnique, utc_now_iso

logger = logging.getLogger(__name__)

ATTACK_VERSION = "v16.1"
TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

# Official Enterprise ATT&CK Tactics Reference
OFFICIAL_TACTICS = {
    "TA0043": {"name": "Reconnaissance", "description": "Gathering information to plan future adversary operations."},
    "TA0042": {"name": "Resource Development", "description": "Establishing resources to support operations."},
    "TA0001": {"name": "Initial Access", "description": "Techniques used to gain an initial foothold within a network."},
    "TA0002": {"name": "Execution", "description": "Techniques that result in adversary-controlled code running on a local or remote system."},
    "TA0003": {"name": "Persistence", "description": "Techniques used to keep access across restarts, changed credentials, and other interruptions."},
    "TA0004": {"name": "Privilege Escalation", "description": "Techniques used to gain higher-level permissions on a system or network."},
    "TA0005": {"name": "Defense Evasion", "description": "Techniques used to avoid detection throughout their compromise."},
    "TA0006": {"name": "Credential Access", "description": "Techniques for stealing credentials like account names and passwords."},
    "TA0007": {"name": "Discovery", "description": "Techniques used to gain knowledge about the system and internal network."},
    "TA0008": {"name": "Lateral Movement", "description": "Techniques used to enter and control remote systems on a network."},
    "TA0009": {"name": "Collection", "description": "Techniques used to gather information of interest to the adversary's goal."},
    "TA0011": {"name": "Command and Control", "description": "Techniques used to communicate with systems under adversary control."},
    "TA0010": {"name": "Exfiltration", "description": "Techniques used to steal data from the target network."},
    "TA0040": {"name": "Impact", "description": "Techniques used to disrupt availability or compromise integrity by manipulating processes."},
}

# Core Official MITRE ATT&CK Enterprise Techniques Catalog (bundled for reliable offline operation)
CORE_OFFICIAL_TECHNIQUES: list[dict[str, Any]] = [
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, packet, or interface vulnerabilities.",
        "platforms": ["Linux", "Windows", "macOS", "Network"],
        "data_sources": ["Application Log: Application Error", "Network Traffic: Network Traffic Flow"],
        "detection_guidance": "Monitor application logs for anomalous process spawns or crash reports following inbound external network connections.",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems via deceptive communications.",
        "platforms": ["Linux", "Windows", "macOS", "SaaS", "Office 365"],
        "data_sources": ["Email Gateway", "File: File Creation"],
        "detection_guidance": "Inspect inbound email headers, attachments, and embedded URLs with threat intelligence detonation sandboxes.",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    {
        "technique_id": "T1566.001",
        "technique_name": "Phishing: Spearphishing Attachment",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may send spearphishing emails with malicious attachments to gain initial access.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["File: File Creation", "Process: Process Creation"],
        "detection_guidance": "Monitor for unexpected child processes spawned by email clients or document readers (e.g. Word launching PowerShell).",
        "is_subtechnique": True,
        "parent_technique_id": "T1566",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may send spearphishing messages with malicious links to lure victims into credential harvesting or drive-by payload downloads.",
        "platforms": ["Linux", "Windows", "macOS", "SaaS"],
        "data_sources": ["Network Traffic: Web Traffic", "Email Gateway"],
        "detection_guidance": "Detect newly registered domain lookups and suspicious redirection chains clicked from email clients.",
        "is_subtechnique": True,
        "parent_technique_id": "T1566",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "platforms": ["Linux", "Windows", "macOS", "Network"],
        "data_sources": ["Command: Command Execution", "Process: Process Creation"],
        "detection_guidance": "Enable process command-line auditing (Sysmon Event ID 1 / Windows 4688) and auditd log collection.",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution and defense evasion.",
        "platforms": ["Windows"],
        "data_sources": ["Script: Script Execution", "Process: Process Creation"],
        "detection_guidance": "Enable PowerShell Script Block Logging (Event ID 4104) and monitor for encoded commands (-EncodedCommand).",
        "is_subtechnique": True,
        "parent_technique_id": "T1059",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    {
        "technique_id": "T1059.005",
        "technique_name": "Command and Scripting Interpreter: Visual Basic",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may abuse Visual Basic for Applications (VBA) or VBScript to execute malicious code.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Creation", "Script: Script Execution"],
        "detection_guidance": "Monitor wscript.exe and cscript.exe invocations originating from temporary or user-writable paths.",
        "is_subtechnique": True,
        "parent_technique_id": "T1059",
        "url": "https://attack.mitre.org/techniques/T1059/005/",
    },
    {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may execute malicious JavaScript/JScript payloads through Windows Script Host or Node.js.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process: Process Creation"],
        "detection_guidance": "Track unusual mshta.exe or wscript.exe execution with remote script parameters.",
        "is_subtechnique": True,
        "parent_technique_id": "T1059",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to escalate privileges on host systems.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["Process: Process Creation", "Kernel Module: Kernel Module Load"],
        "detection_guidance": "Monitor process integrity elevation and suspicious kernel privilege transitions.",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    {
        "technique_id": "T1574.002",
        "technique_name": "Hijack Execution Flow: DLL Side-Loading",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries may abuse DLL search order by placing a malicious DLL with the name of a legitimate dependency in the same directory as a trusted executable.",
        "platforms": ["Windows"],
        "data_sources": ["Module: Module Load", "File: File Creation"],
        "detection_guidance": "Detect unsigned or unexpectedly located DLLs loaded by legitimately signed system or vendor binaries.",
        "is_subtechnique": True,
        "parent_technique_id": "T1574",
        "url": "https://attack.mitre.org/techniques/T1574/002/",
    },
    {
        "technique_id": "T1027.003",
        "technique_name": "Obfuscated Files or Information: Steganography",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries may disguise data or malicious payload code within image, audio, or document files to evade detection.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["File: File Metadata", "Network Traffic: Content Inspection"],
        "detection_guidance": "Inspect trailing data appended to image headers and monitor memory allocations from image-loading libraries.",
        "is_subtechnique": True,
        "parent_technique_id": "T1027",
        "url": "https://attack.mitre.org/techniques/T1027/003/",
    },
    {
        "technique_id": "T1505.003",
        "technique_name": "Server Software Component: Web Shell",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "description": "Adversaries may place web shells (PHP, ASPX, JSP) within web server directories to maintain persistent backdoor access.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["File: File Creation", "Process: Process Creation"],
        "detection_guidance": "Monitor web server root directories for new script creation and detect web server worker processes (e.g. w3wp.exe, nginx) spawning command shells.",
        "is_subtechnique": True,
        "parent_technique_id": "T1505",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources, commonly used in ransomware campaigns.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["File: File Modification", "Process: Process Creation"],
        "detection_guidance": "Detect high-frequency file write/rename activity across user document directories and shadow copy deletion (vssadmin delete shadows).",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    {
        "technique_id": "T1072",
        "technique_name": "Software Deployment Tools",
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "description": "Adversaries may take advantage of third-party or enterprise software deployment tools to laterally move and execute commands.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process: Process Creation", "Network Traffic: Network Traffic Flow"],
        "detection_guidance": "Monitor administrative remote management packages invoking binaries outside scheduled maintenance windows.",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1072/",
    },
    {
        "technique_id": "T1102.002",
        "technique_name": "Web Service: Bidirectional Communication",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "description": "Adversaries may use legitimate external Web services (Telegram, Discord, GitHub, Google Drive) for C2 communication.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["Network Traffic: Web Traffic", "DNS: DNS Query"],
        "detection_guidance": "Correlate outbound TLS traffic to consumer cloud APIs with anomalous process execution context.",
        "is_subtechnique": True,
        "parent_technique_id": "T1102",
        "url": "https://attack.mitre.org/techniques/T1102/002/",
    },
    {
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries may disable or modify security tools, services, or kernel drivers to avoid detection.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["Service: Service Stop", "Process: Process Termination"],
        "detection_guidance": "Alert on unexpected termination or uninstallation of antivirus, EDR agents, or security event forwarders.",
        "is_subtechnique": True,
        "parent_technique_id": "T1562",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    {
        "technique_id": "T1572",
        "technique_name": "Protocol Tunneling",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "description": "Adversaries may tunnel network communications to disguise C2 traffic or evade network filtering.",
        "platforms": ["Linux", "Windows", "macOS"],
        "data_sources": ["Network Traffic: Protocol Inspection"],
        "detection_guidance": "Detect non-standard protocol handshakes over standard ports (e.g., SSH or custom protocols over port 443/80).",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "url": "https://attack.mitre.org/techniques/T1572/",
    },
]


def validate_technique_id(technique_id: str) -> bool:
    """
    Validate MITRE ATT&CK technique ID format (e.g. 'T1059' or 'T1059.001').
    Ensures technique identifiers are syntactically valid and never invented.
    """
    if not technique_id or not isinstance(technique_id, str):
        return False
    return bool(TECHNIQUE_ID_REGEX.match(technique_id.strip()))


class MitreAttackConnector:
    """Official MITRE ATT&CK Enterprise reference catalog and evidence-based mapper."""

    def __init__(self, db: IntelligenceDB):
        self.db = db
        self.version = ATTACK_VERSION
        # Ensure official reference catalog is initialized in database
        self._ensure_dataset_initialized()

    def _ensure_dataset_initialized(self) -> None:
        """Seed official reference techniques into SQLite database if missing."""
        try:
            stored = self.db.get_all_mitre_techniques(limit=1)
            if not stored:
                self.ingest_core_dataset()
        except Exception as e:
            logger.warning(f"Error checking MITRE ATT&CK dataset: {e}")

    def ingest_core_dataset(self) -> int:
        """Populate database with official machine-readable MITRE ATT&CK reference data."""
        count = 0
        now = utc_now_iso()
        for item in CORE_OFFICIAL_TECHNIQUES:
            tech = MitreTechnique(
                technique_id=item["technique_id"],
                technique_name=item["technique_name"],
                tactic_id=item.get("tactic_id"),
                tactic_name=item.get("tactic_name"),
                description=item.get("description", ""),
                platforms=item.get("platforms", []),
                data_sources=item.get("data_sources", []),
                detection_guidance=item.get("detection_guidance", ""),
                version=self.version,
                is_subtechnique=item.get("is_subtechnique", False),
                parent_technique_id=item.get("parent_technique_id"),
                url=item.get("url", ""),
                updated_at=now,
            )
            self.db.upsert_mitre_technique(tech)
            count += 1
        logger.info(f"Ingested {count} official MITRE ATT&CK techniques ({self.version}).")
        return count

    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Lookup official technique details by ID."""
        if not validate_technique_id(technique_id):
            return None
        return self.db.get_mitre_technique(technique_id.upper())

    def get_tactic(self, tactic_id_or_name: str) -> Optional[dict[str, str]]:
        """Lookup official tactic metadata."""
        key = tactic_id_or_name.strip().upper()
        if key in OFFICIAL_TACTICS:
            return OFFICIAL_TACTICS[key]
        for tid, data in OFFICIAL_TACTICS.items():
            if data["name"].upper() == key:
                return {"tactic_id": tid, **data}
        return None

    def get_tactics_list(self) -> list[dict[str, str]]:
        """Return list of all official Enterprise ATT&CK tactics."""
        return [{"id": k, **v} for k, v in OFFICIAL_TACTICS.items()]

    def search_techniques(self, query: str, limit: int = 50) -> list[MitreTechnique]:
        """Search techniques in official catalog by name, description, or tactic."""
        return self.db.search_mitre_techniques(query=query, limit=limit)

    def map_article_to_attack(
        self,
        article: Article,
        analysis: ArticleAnalysis,
    ) -> list[ArticleFrameworkMapping]:
        """
        Map article disclosure claims to official MITRE ATT&CK techniques with evidence.
        Distinguishes:
        - explicit: Source explicitly names or cites the technique ID / exact technique name.
        - inferred: Source describes attack behavior matching technique with strong contextual evidence.
        """
        mappings: list[ArticleFrameworkMapping] = []
        body_text = (article.content or "") + " " + (analysis.summary or "")
        body_lower = body_text.lower()

        # 1. Inspect techniques extracted during Phase 2 analysis
        extracted_techs = []
        for item in analysis.mitre_attack:
            if isinstance(item, dict):
                tid = item.get("technique_id")
                tname = item.get("technique_name") or tid
                if tid and validate_technique_id(str(tid)):
                    extracted_techs.append((str(tid).upper(), str(tname)))

        # Also check explicit T-codes in article content via regex
        found_t_codes = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", body_text, re.IGNORECASE))
        for tcode in found_t_codes:
            tcode_upper = tcode.upper()
            if tcode_upper not in [t[0] for t in extracted_techs]:
                extracted_techs.append((tcode_upper, tcode_upper))

        for tid, tname_hint in extracted_techs:
            official = self.get_technique(tid)
            if not official:
                logger.debug(f"Technique {tid} not found in official ATT&CK reference catalog. Skipping.")
                continue
            official_name = official.technique_name
            tactic_name = official.tactic_name or "Unknown"

            # Determine evidence snippet
            evidence_snippet = ""
            for sentence in re.split(r"[.\n]", body_text):
                if tid.lower() in sentence.lower() or (official and official.technique_name.lower() in sentence.lower()):
                    evidence_snippet = sentence.strip()
                    break

            if not evidence_snippet:
                evidence_snippet = f"Technique {tid} ({official_name}) referenced in article analysis."

            # Determine mapping method: explicit vs inferred
            is_explicit = (tid.lower() in body_lower) or (official and official.technique_name.lower() in body_lower)
            method = "explicit" if is_explicit else "inferred"
            confidence = "HIGH" if is_explicit else "MEDIUM"

            mapping = ArticleFrameworkMapping(
                mapping_id=f"map_attk_{article.article_id}_{tid.replace('.', '_')}",
                article_id=article.article_id,
                framework="MITRE_ATTACK",
                framework_item_id=tid,
                framework_item_name=official_name,
                evidence_text=evidence_snippet,
                mapping_method=method,
                confidence=confidence,
                dataset_version=self.version,
                metadata={
                    "tactic_name": tactic_name,
                    "url": official.url if official else f"https://attack.mitre.org/techniques/{tid}/",
                    "platforms": official.platforms if official else [],
                },
                created_at=utc_now_iso(),
            )
            self.db.save_framework_mapping(mapping)
            mappings.append(mapping)

        return mappings
