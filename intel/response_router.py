"""
intel/response_router.py — Smart Response Routing Service for JARVIS 24.

Determines the appropriate presentation format for each user request:
- CHAT: Conversational replies, short answers, greetings, confirmations.
- INFORMATION_PAGE: Detailed explanations, comprehensive research, deep dives.
- CYBERSECURITY_REPORT: Threat analysis, CVE breakdowns, MITRE ATT&CK, OWASP security evaluations.
- LEARNING_PAGE: Step-by-step lessons, hands-on examples, quizzes, and tutorials.
- PROJECT_DOCUMENT: Architecture designs, implementation guides, technical specifications.
- GENERATED_ARTIFACT: Downloadable exports (PDF, PPTX, reports).
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional


class PresentationMode:
    CHAT = "CHAT"
    INFORMATION_PAGE = "INFORMATION_PAGE"
    CYBERSECURITY_REPORT = "CYBERSECURITY_REPORT"
    LEARNING_PAGE = "LEARNING_PAGE"
    PROJECT_DOCUMENT = "PROJECT_DOCUMENT"
    GENERATED_ARTIFACT = "GENERATED_ARTIFACT"

    ALL_MODES = {
        CHAT,
        INFORMATION_PAGE,
        CYBERSECURITY_REPORT,
        LEARNING_PAGE,
        PROJECT_DOCUMENT,
        GENERATED_ARTIFACT,
    }


@dataclass
class RouteDecision:
    mode: str
    is_detailed: bool
    category: str
    topic: str
    reasoning: str
    confidence: float = 1.0


class SmartResponseRouter:
    """Intelligently routes requests to the optimal presentation container."""

    # Explicit phrases forcing CHAT mode (brief/short)
    BRIEF_PATTERNS = [
        r"\b(?:briefly|short answer|in short|summarize in one sentence|quick answer|concise(?:ly)?)\b",
        r"\b(?:keep it brief|short explanation|just tell me briefly|in 2 sentences)\b",
    ]

    # Explicit phrases forcing GENERATED_ARTIFACT
    ARTIFACT_PATTERNS = [
        r"\b(?:create a pdf|generate (?:a )?pdf|make a pdf|download as pdf|export to pdf)\b",
        r"\b(?:create a pptx|generate (?:a )?powerpoint|generate (?:a )?slides?|export to docx)\b",
        r"\b(?:downloadable (?:document|file|report))\b",
    ]

    # Explicit phrases forcing PROJECT_DOCUMENT
    PROJECT_DOC_PATTERNS = [
        r"\b(?:project architecture|system architecture|technical specification|tech spec)\b",
        r"\b(?:implementation guide|development plan|software design document|system design)\b",
        r"\b(?:full project architecture|architecture diagram|system components breakdown)\b",
    ]

    # Explicit phrases forcing LEARNING_PAGE
    LEARNING_PATTERNS = [
        r"\b(?:teach me|give me a lesson|step-by-step tutorial|interactive quiz)\b",
        r"\b(?:teach me with examples|learning guide|study guide|practice exercise|lab exercise)\b",
        r"\b(?:walk me through step by step|how do i learn|curriculum)\b",
    ]

    # Explicit phrases forcing CYBERSECURITY_REPORT
    CYBERSECURITY_PATTERNS = [
        r"\b(?:cybersecurity|threat report|threat analysis|vulnerability assessment)\b",
        r"\b(?:mitre att&ck|attack technique|owasp|cve-\d{4}-\d+|zero-day|cve analysis)\b",
        r"\b(?:malware analysis|ransomware|threat actor|apt\d+|phishing campaign)\b",
        r"\b(?:incident response report|security audit|penetration testing report)\b",
    ]

    # Explicit phrases forcing INFORMATION_PAGE
    INFO_PAGE_PATTERNS = [
        r"\b(?:in detail|explain in detail|comprehensive guide|deep dive|full explanation)\b",
        r"\b(?:detailed explanation|comprehensive overview|detailed research|full breakdown)\b",
        r"\b(?:compare and contrast|detailed comparison|complete guide to|everything about)\b",
        r"\b(?:thorough explanation|detailed breakdown|in-depth analysis)\b",
    ]

    # Conversational greetings, simple calculation, one-liners that must remain CHAT
    CHAT_GREETINGS = [
        r"^(?:hello|hi|hey|good morning|good afternoon|good evening|greetings)(?: jarvis)?\.?$",
        r"^(?:who are you|what is your name|how are you|are you there|system status|ping)\??$",
        r"^(?:thank you|thanks|great job|bye|goodbye|dismiss|cancel|stop|nevermind)\.?$",
        r"^(?:what time is it|what is the date|what day is it)\??$",
    ]

    def __init__(self):
        pass

    def route(self, query: str, context: Optional[dict] = None) -> RouteDecision:
        """Analyze query and classify it into the appropriate PresentationMode."""
        raw_text = query.strip()
        text_lower = raw_text.lower()

        # 1. Check for simple conversational greetings and status checks -> CHAT
        for pattern in self.CHAT_GREETINGS:
            if re.search(pattern, text_lower):
                return RouteDecision(
                    mode=PresentationMode.CHAT,
                    is_detailed=False,
                    category="Conversation",
                    topic=raw_text,
                    reasoning="Conversational greeting or simple status query.",
                    confidence=1.0,
                )

        # 2. Check for explicit brevity constraints -> CHAT
        for pattern in self.BRIEF_PATTERNS:
            if re.search(pattern, text_lower):
                return RouteDecision(
                    mode=PresentationMode.CHAT,
                    is_detailed=False,
                    category="Summary",
                    topic=self._extract_topic(raw_text),
                    reasoning="User explicitly requested a brief or short response in chat.",
                    confidence=0.98,
                )

        # 3. Check for downloadable artifact generation -> GENERATED_ARTIFACT
        for pattern in self.ARTIFACT_PATTERNS:
            if re.search(pattern, text_lower):
                return RouteDecision(
                    mode=PresentationMode.GENERATED_ARTIFACT,
                    is_detailed=True,
                    category="Export",
                    topic=self._extract_topic(raw_text),
                    reasoning="User explicitly requested a downloadable document or export artifact.",
                    confidence=0.95,
                )

        # 4. Check for project architecture & technical documentation -> PROJECT_DOCUMENT
        for pattern in self.PROJECT_DOC_PATTERNS:
            if re.search(pattern, text_lower):
                return RouteDecision(
                    mode=PresentationMode.PROJECT_DOCUMENT,
                    is_detailed=True,
                    category="Software Architecture",
                    topic=self._extract_topic(raw_text),
                    reasoning="User requested technical specification, system design, or project architecture.",
                    confidence=0.95,
                )

        # 5. Check for educational / teaching lessons -> LEARNING_PAGE
        for pattern in self.LEARNING_PATTERNS:
            if re.search(pattern, text_lower):
                return RouteDecision(
                    mode=PresentationMode.LEARNING_PAGE,
                    is_detailed=True,
                    category="Learning",
                    topic=self._extract_topic(raw_text),
                    reasoning="User requested a tutorial, interactive lesson, practice exercise, or quiz.",
                    confidence=0.95,
                )

        # 6. Check for cybersecurity reports and threat intelligence -> CYBERSECURITY_REPORT
        has_cyber = any(re.search(pat, text_lower) for pat in self.CYBERSECURITY_PATTERNS)
        is_detail_requested = any(re.search(pat, text_lower) for pat in self.INFO_PAGE_PATTERNS)

        if has_cyber and (is_detail_requested or "report" in text_lower or "analysis" in text_lower or "explain" in text_lower):
            return RouteDecision(
                mode=PresentationMode.CYBERSECURITY_REPORT,
                is_detailed=True,
                category="Cybersecurity",
                topic=self._extract_topic(raw_text),
                reasoning="Cybersecurity domain query with analysis or reporting requirements.",
                confidence=0.96,
            )

        # 7. Check for explicit detailed explanation / research request -> INFORMATION_PAGE
        if is_detail_requested:
            category = "Cybersecurity" if has_cyber else "Research & Technology"
            return RouteDecision(
                mode=PresentationMode.INFORMATION_PAGE,
                is_detailed=True,
                category=category,
                topic=self._extract_topic(raw_text),
                reasoning="User explicitly requested a detailed explanation or comprehensive breakdown.",
                confidence=0.95,
            )

        # 8. Check for research & tutorial intent keywords
        research_indicators = [
            r"\bhow does .* work\b",
            r"\bwhat is .* in detail\b",
            r"\bexplain .*\b",
            r"\bcomparison between .*\b",
            r"\bdifference between .*\b",
            r"\bdeep dive into .*\b",
            r"\bhistory of .*\b",
        ]
        for pat in research_indicators:
            if re.search(pat, text_lower):
                # If question length is substantial or asks for explanation of complex subject
                category = "Cybersecurity" if has_cyber else "Knowledge Base"
                mode = PresentationMode.CYBERSECURITY_REPORT if has_cyber else PresentationMode.INFORMATION_PAGE
                return RouteDecision(
                    mode=mode,
                    is_detailed=True,
                    category=category,
                    topic=self._extract_topic(raw_text),
                    reasoning="Subject exploration requires comprehensive structured information page.",
                    confidence=0.88,
                )

        # 9. Default to CHAT for short or standard conversational queries
        return RouteDecision(
            mode=PresentationMode.CHAT,
            is_detailed=False,
            category="General",
            topic=self._extract_topic(raw_text),
            reasoning="Default conversational chat mode for standard questions.",
            confidence=0.85,
        )

    def _extract_topic(self, query: str) -> str:
        """Extract a clean, readable topic string from the user's prompt."""
        cleaned = re.sub(
            r"^(?:jarvis,?\s*|can you\s*|please\s*|could you\s*|tell me\s*|explain\s*|teach me\s*|show me\s*)",
            "",
            query,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(
            r"\b(?:in detail|briefly|step by step|with examples|please|for me)\b",
            "",
            cleaned,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(r"[?!.]+$", "", cleaned).strip()
        if not cleaned:
            return "Information Overview"
        return cleaned[:80].strip()


_router_instance: Optional[SmartResponseRouter] = None


def get_response_router() -> SmartResponseRouter:
    """Return singleton instance of SmartResponseRouter."""
    global _router_instance
    if _router_instance is None:
        _router_instance = SmartResponseRouter()
    return _router_instance
