"""
JARVIS Cybersecurity Learning and Defensive Investigation Services (Phase 3.5).

Exposes core service functions for JARVIS voice, chat, and dashboard integration:
1. explain_thn_article(article_id, learning_level):
   - Multi-tier explanations: beginner, intermediate, advanced.
   - Structured curriculum: prerequisites, attack concept, evidence, detection, mitigation, knowledge-check question.
2. map_article_to_attack_framework(article_id):
   - Evidence-backed ATT&CK technique mapping with explicit vs. inferred provenance.
3. explain_owasp_relevance(article_id):
   - Web application security relevance, OWASP Top 10 2025 mappings, and secure coding guidance.
4. get_trending_threats(period):
   - High-velocity emerging and accelerating threats from Phase 3 engine.
5. compare_reported_threats_with_detections(period):
   - Correlates external news threats with Vectra AI detections (reports 'unavailable' when unconfigured).
6. explain_detection_evidence(event_id):
   - Investigates sensor evidence for a detection (reports 'unavailable' when unconfigured).
7. recommend_defensive_learning(article_id, learning_profile):
   - Personalized learning path, ethical safe lab exercises, and defense recommendations.

Strict Guardrails:
- No automated scanning, exploitation, or offensive actions against third parties.
- All suggested lab exercises are scoped exclusively to controlled local/educational environments.
"""

from __future__ import annotations
import logging
from typing import Any, Optional

from .db import IntelligenceDB
from .intelligence_engine import CybersecurityIntelligenceEngine
from .mitre_attack import MitreAttackConnector
from .models import Article, ArticleAnalysis, UserLearningProfile
from .owasp_top10 import OwaspTop10Connector
from .unified_schema import UnifiedIntelligenceEngine
from .vectra_provider import VectraProvider

logger = logging.getLogger(__name__)


class CybersecurityLearningService:
    """Core educational and investigation service layer for the JARVIS assistant."""

    def __init__(
        self,
        db: Optional[IntelligenceDB] = None,
        intelligence_engine: Optional[CybersecurityIntelligenceEngine] = None,
    ):
        self.db = db or IntelligenceDB("data/cyber_intel.db")
        self.intel_engine = intelligence_engine or CybersecurityIntelligenceEngine(db=self.db)
        self.mitre_connector = MitreAttackConnector(self.db)
        self.owasp_connector = OwaspTop10Connector(self.db)
        self.vectra_provider = VectraProvider()
        self.unified_engine = UnifiedIntelligenceEngine(self.db)

    # ── 1. Explain THN Article (Multi-Level) ──────────────────────────────────

    def explain_thn_article(
        self,
        article_id: str,
        learning_level: str = "intermediate",
    ) -> dict[str, Any]:
        """
        Explain a threat disclosure tailored to the user's technical background.
        Levels:
        - beginner: Simple analogies, foundational terms defined, non-jargon attack flow.
        - intermediate: Technical architecture, protocol mechanics, defensive indicators.
        - advanced: Memory/assembly primitives, kernel/runtime hooks, evasion tactics, advanced detection.
        """
        article = self.db.get_article_by_id(article_id)
        if not article:
            return {"error": f"Article '{article_id}' not found.", "status": "NOT_FOUND"}

        analysis = self.db.get_analysis_by_article_id(article_id)
        level = (learning_level or "intermediate").lower()

        # Retrieve or compute framework mappings
        attack_mappings = self.mitre_connector.map_article_to_attack(article, analysis) if analysis else []
        owasp_mappings = self.owasp_connector.map_article_to_owasp(article, analysis) if analysis else []

        cve_str = ", ".join(analysis.cves) if analysis and analysis.cves else "None specified"
        actor_str = ", ".join(analysis.threat_actors) if analysis and analysis.threat_actors else "Unattributed / Cybercriminals"
        malware_str = ", ".join(analysis.malware + analysis.ransomware) if analysis and (analysis.malware or analysis.ransomware) else "None specified"

        if level == "beginner":
            prerequisites = [
                "What is a computer network and IP address?",
                "Basic understanding that software has bugs which attackers can find.",
                "How accounts and passwords protect systems.",
            ]
            concept = (
                f"In simple terms, this report describes how attackers ({actor_str}) discovered a weak lock "
                f"({cve_str}) in a widely used program. Just like leaving a backdoor unlocked, attackers use "
                f"this mistake to slip in without permission and install malicious programs ({malware_str})."
            )
            detection = (
                "Defenders look for unusual activity, such as unknown programs running at night, "
                "or computers trying to send confidential information to foreign websites."
            )
            mitigation = [
                "Install the official software update/patch immediately to fix the bug.",
                "Turn on two-factor authentication (2FA) so stolen passwords alone aren't enough.",
                "Never open attachments or click links in unexpected emails.",
            ]
            question = {
                "question": "What is the most effective immediate action to prevent this vulnerability from being exploited?",
                "options": [
                    "A) Reinstall Windows on all computers.",
                    "B) Apply the official security patch/update provided by the vendor.",
                    "C) Unplug the internet forever.",
                    "D) Ignore it until an attacker breaks in.",
                ],
                "correct_option": "B",
                "explanation": "Applying the vendor's security patch permanently fixes the vulnerable software bug so attackers cannot exploit it.",
            }

        elif level == "advanced":
            prerequisites = [
                "In-depth knowledge of OS kernel architecture and memory management.",
                "Familiarity with binary exploitation, ROP gadgets, or auth bypass primitives.",
                "Expertise with EDR telemetry, Sysmon, auditd, and network protocol dissection.",
            ]
            concept = (
                f"Technical Analysis of '{article.title}': The root vulnerability ({cve_str}) enables an unauthenticated "
                f"threat actor ({actor_str}) to achieve initial access and execute unauthorized code within the process context. "
                f"Payload execution utilizes {malware_str}. Adversaries demonstrate advanced evasion tactics, such as "
                f"DLL search order hijacking (T1574.002) and memory-only staging to bypass standard file-integrity monitoring."
            )
            detection = (
                "Deep Telemetry Strategy: Monitor ETW (Event Tracing for Windows) for Microsoft-Windows-Kernel-Process, "
                "Sysmon Event ID 1 (Process Create with anomalous parentage) and Event ID 7 (ImageLoad from non-standard directories). "
                "Inspect API gateway reverse-proxy access logs for abnormal URI traversal sequences or malformed HTTP headers."
            )
            mitigation = [
                "Apply microcode and vendor patch diffing to confirm remediation of the vulnerable logic branch.",
                "Implement strict AppLocker / WDAC (Windows Defender Application Control) execution policies.",
                "Enforce mutual TLS (mTLS) and zero-trust segmentation between web tiers and internal datastores.",
            ]
            question = {
                "question": "Which detection telemetry provides the highest fidelity evidence of this execution technique?",
                "options": [
                    "A) Simple HTTP status code 200 counts.",
                    "B) Process creation events correlating anomalous parent-child execution with non-standard DLL image loads.",
                    "C) Looking at total CPU utilization spikes.",
                    "D) Checking whether the computer screen is flickering.",
                ],
                "correct_option": "B",
                "explanation": "Parent-child process deviation (e.g. web worker spawning cmd.exe) combined with anomalous module loads reliably exposes code execution and hijacking.",
            }

        else:  # Intermediate (default)
            prerequisites = [
                "Understanding of client-server architecture and HTTP request/response flows.",
                "Familiarity with CVE scoring, common vulnerabilities, and basic firewall rules.",
                "Knowledge of how operating systems manage user permissions and processes.",
            ]
            concept = (
                f"Overview of '{article.title}': Security researchers observed threat actors ({actor_str}) "
                f"targeting {cve_str}. The flaw allows attackers to bypass security boundaries, potentially deploying "
                f"{malware_str}. The attack exploits misconfigurations or unpatched software interfaces exposed to external access."
            )
            detection = (
                "Security Monitoring: Look for suspicious child processes spawned by web server daemons (e.g. w3wp.exe or nginx), "
                "detect unexpected outbound connections to unrecognized external IP addresses on non-standard ports, "
                "and monitor authentication logs for bursts of failed access attempts followed by anomalous privilege escalation."
            )
            mitigation = [
                "Deploy the vendor security update to all affected instances.",
                "Restrict network access to administrative interfaces using VPN and IP allow-lists.",
                "Implement least-privilege principles so web service accounts cannot write to executable directories.",
            ]
            question = {
                "question": "Why is it dangerous for a web server daemon process to spawn a command shell (e.g., cmd.exe or /bin/sh)?",
                "options": [
                    "A) It uses too much battery on mobile phones.",
                    "B) Web servers normally serve content; spawning a shell strongly indicates an attacker achieved remote command execution.",
                    "C) Command shells make the internet connection run slower.",
                    "D) It is standard practice for all web pages.",
                ],
                "correct_option": "B",
                "explanation": "Web servers should only handle web requests; an interactive shell spawn is a classic signature of a web shell or Remote Code Execution (RCE).",
            }

        # Synthesize unified links
        if analysis:
            self.unified_engine.synthesize_article_intelligence(article, analysis, attack_mappings + owasp_mappings)

        return {
            "article_id": article_id,
            "title": article.title,
            "url": article.url,
            "published_at": article.published_at,
            "learning_level": level,
            "prerequisites": prerequisites,
            "attack_concept": concept,
            "supporting_evidence": analysis.summary if analysis else (article.content[:300] if article.content else ""),
            "technical_evidence": analysis.summary if analysis else (article.content[:300] if article.content else ""),
            "defensive_detection": detection,
            "mitigation": mitigation,
            "mitigation_action": mitigation,
            "knowledge_check": question,
            "knowledge_check_question": question.get("question", ""),
            "associated_cves": analysis.cves if analysis else [],
            "mitre_techniques": [m.to_dict() for m in attack_mappings],
            "owasp_categories": [o.to_dict() for o in owasp_mappings],
        }

    # ── 2. Framework Mapping Services ─────────────────────────────────────────

    def map_article_to_attack_framework(self, article_id: str) -> dict[str, Any]:
        """Retrieve or compute evidence-backed MITRE ATT&CK technique mappings for an article."""
        article = self.db.get_article_by_id(article_id)
        if not article:
            return {"error": f"Article '{article_id}' not found.", "status": "NOT_FOUND"}

        analysis = self.db.get_analysis_by_article_id(article_id)
        mappings = self.mitre_connector.map_article_to_attack(article, analysis) if analysis else []

        return {
            "article_id": article_id,
            "title": article.title,
            "total_techniques_mapped": len(mappings),
            "mappings": [m.to_dict() for m in mappings],
        }

    def explain_owasp_relevance(self, article_id: str) -> dict[str, Any]:
        """Explain whether an article is relevant to web security and list OWASP Top 10 2025 mappings."""
        article = self.db.get_article_by_id(article_id)
        if not article:
            return {"error": f"Article '{article_id}' not found.", "status": "NOT_FOUND"}

        analysis = self.db.get_analysis_by_article_id(article_id)
        is_web, reason = self.owasp_connector.is_web_security_related(article, analysis) if analysis else (False, "No analysis")
        mappings = self.owasp_connector.map_article_to_owasp(article, analysis) if analysis and is_web else []

        return {
            "article_id": article_id,
            "title": article.title,
            "is_web_security_related": is_web,
            "evaluation_reason": reason,
            "owasp_categories_mapped": [m.to_dict() for m in mappings],
            "recommendation": (
                "Review OWASP ASVS and apply secure coding controls."
                if is_web and mappings else "Article describes non-web or host/network infrastructure threat."
            ),
        }

    # ── 3. Trends & Detection Comparison ──────────────────────────────────────

    def get_trending_threats(self, period: str = "30d") -> list[dict[str, Any]]:
        """Fetch high-velocity and accelerating threats from the Phase 3 intelligence engine."""
        return self.intel_engine.get_trending_threats(time_window=period, limit=10)

    def compare_reported_threats_with_detections(self, period: str = "30d") -> dict[str, Any]:
        """
        Compare external threat intelligence against internal Vectra AI network/host telemetry.
        When Vectra AI is unconfigured, reports 'unavailable' without fabricating events.
        """
        status_info = self.vectra_provider.get_status()
        if not self.vectra_provider.is_configured:
            return {
                "status": "unavailable",
                "available": False,
                "message": (
                    "Internal detection telemetry comparison is unavailable. Vectra AI platform credentials "
                    "(VECTRA_BASE_URL, VECTRA_CLIENT_ID, VECTRA_CLIENT_SECRET) are not configured."
                ),
                "external_threats_analyzed": len(self.intel_engine.get_trending_threats(time_window=period, limit=10)),
                "internal_detections_count": 0,
                "correlated_matches": [],
            }

        # If configured, fetch live detections
        detections = self.vectra_provider.poll_detections(limit=50)
        return {
            "status": "available",
            "available": True,
            "internal_detections_count": len(detections),
            "detections": [d.to_dict() for d in detections],
            "message": "Live telemetry comparison active.",
        }

    def explain_detection_evidence(self, event_id: str | int) -> dict[str, Any]:
        """
        Explain the evidence and sensor indicators behind a specific detection event.
        When Vectra AI is unconfigured, reports 'unavailable'.
        """
        if not self.vectra_provider.is_configured:
            return {
                "status": "unavailable",
                "available": False,
                "event_id": str(event_id),
                "message": "Vectra AI deployment is not configured. Live event evidence retrieval unavailable.",
            }

        detection = self.vectra_provider.get_detection_by_id(event_id)
        if not detection:
            return {"status": "NOT_FOUND", "available": False, "message": f"Detection event '{event_id}' not found on tenant."}

        return {
            "status": "available",
            "available": True,
            "event_id": str(event_id),
            "detection": detection.to_dict(),
        }

    # ── 4. Personalized Defensive Learning Recommendations ────────────────────

    def recommend_defensive_learning(
        self,
        article_id: str,
        learning_profile: Optional[UserLearningProfile] = None,
    ) -> dict[str, Any]:
        """
        Recommend tailored defensive learning modules, safe lab simulations,
        and mitigation priorities matching user skill level.
        """
        article = self.db.get_article_by_id(article_id)
        if not article:
            return {"error": f"Article '{article_id}' not found."}

        analysis = self.db.get_analysis_by_article_id(article_id)
        profile = learning_profile or self.db.get_or_create_learning_profile("default")

        # Map to OWASP and ATT&CK
        owasp_maps = self.owasp_connector.map_article_to_owasp(article, analysis) if analysis else []
        attk_maps = self.mitre_connector.map_article_to_attack(article, analysis) if analysis else []

        labs = []
        for o in owasp_maps:
            cat = self.owasp_connector.get_category(o.framework_item_id)
            if cat and cat.safe_lab_exercise:
                labs.append({"topic": cat.category_name, "exercise": cat.safe_lab_exercise})

        if not labs:
            labs.append({
                "topic": "Network & Log Analysis Lab",
                "exercise": "Analyze simulated pcap and Sysmon logs in Wireshark or Brim Security to identify C2 beacons.",
            })

        return {
            "article_id": article_id,
            "title": article.title,
            "user_level": profile.preferred_level,
            "recommended_focus_areas": [o.framework_item_name for o in owasp_maps] + [a.framework_item_name for a in attk_maps],
            "safe_lab_exercises": labs,
            "ethical_guidance": (
                "All security verification must be strictly scoped to authorized test environments "
                "or dedicated educational platforms (PortSwigger Web Security Academy, TryHackMe). "
                "Never target unauthorized third-party systems."
            ),
        }
