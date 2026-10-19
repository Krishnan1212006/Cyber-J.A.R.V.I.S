"""
Article Preprocessor and Sanitizer for JARVIS Cybersecurity Subsystem.

Features:
- Robust Prompt Injection Mitigation (structural delimiters, instruction containment, boundary escaping)
- Content Size Budgeting & Smart Truncation (preserves lead, technical middle, and indicators)
- Deterministic Entity Pre-extraction (CVEs, IOCs, Hashes, IPs, MITRE codes) to assist and cross-validate LLM output
- Defanging and safe handling of malicious strings
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Optional


# Regex Patterns for Cybersecurity Entities
CVE_PATTERN = re.compile(r"\bCVE-(?:199\d|20\d{2})-\d{4,7}\b", re.IGNORECASE)
MITRE_TECHNIQUE_PATTERN = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.IGNORECASE)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# IPv4 with boundary validation
IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# Known prompt injection signatures to neutralize inside untrusted data
INJECTION_SIGNATURES = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?system\s+prompt", re.IGNORECASE),
    re.compile(r"print\s+(?:your\s+)?system\s+prompt", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"assistant\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*/?\s*system\s*>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*instruction\s*>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*article_data\s*>", re.IGNORECASE),
    re.compile(r"give\s+me\s+(?:the\s+)?(?:api\s+keys?|passwords?|credentials?)", re.IGNORECASE),
]


class PreprocessedArticle:
    """Encapsulates preprocessed content and regex-detected candidate entities."""

    def __init__(
        self,
        article_id: str,
        title: str,
        clean_content: str,
        truncated: bool,
        original_length: int,
        processed_length: int,
        cve_candidates: list[str],
        mitre_candidates: list[str],
        ioc_candidates: list[dict[str, Any]],
    ):
        self.article_id = article_id
        self.title = title
        self.clean_content = clean_content
        self.truncated = truncated
        self.original_length = original_length
        self.processed_length = processed_length
        self.cve_candidates = cve_candidates
        self.mitre_candidates = mitre_candidates
        self.ioc_candidates = ioc_candidates


def sanitize_untrusted_text(text: str) -> str:
    """
    Sanitize text to neutralize prompt injection directives without corrupting technical reporting.
    Adversarial commands inside text are bracketed as [ARTICLE_LITERAL: ...] so LLM treats them as quoted data.
    """
    if not text:
        return ""

    sanitized = text
    for sig in INJECTION_SIGNATURES:
        sanitized = sig.sub(lambda m: f"[ARTICLE_LITERAL_TEXT: '{m.group(0)}']", sanitized)

    # Escape XML boundary delimiters
    sanitized = sanitized.replace("<article_content>", "&lt;article_content&gt;")
    sanitized = sanitized.replace("</article_content>", "&lt;/article_content&gt;")
    return sanitized


def is_valid_public_ip(ip_str: str) -> bool:
    """Validate that string is an external IPv4 address and not RFC 1918 internal, loopback, or multicast."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return False
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return False
        # Filter strictly internal RFC 1918 and link-local ranges
        internal_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
        return not any(ip in net for net in internal_networks)
    except ValueError:
        return False



def extract_cves(text: str) -> list[str]:
    """Extract distinct normalized uppercase CVE identifiers from text."""
    if not text:
        return []
    matches = CVE_PATTERN.findall(text)
    # Deduplicate while preserving order
    seen = set()
    result = []
    for cve in matches:
        norm = cve.upper()
        if norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


def extract_mitre_techniques(text: str) -> list[str]:
    """Extract distinct MITRE ATT&CK technique IDs (e.g. T1059, T1059.001) from text."""
    if not text:
        return []
    matches = MITRE_TECHNIQUE_PATTERN.findall(text)
    seen = set()
    result = []
    for tech in matches:
        norm = tech.upper()
        if norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result


def extract_candidate_iocs(text: str) -> list[dict[str, Any]]:
    """Extract candidate IOCs (Hashes, IPs) with validation."""
    if not text:
        return []

    iocs: list[dict[str, Any]] = []
    seen_values: set[str] = set()

    # SHA256
    for h in SHA256_PATTERN.findall(text):
        val = h.lower()
        if val not in seen_values:
            seen_values.add(val)
            iocs.append({
                "type": "sha256",
                "value": val,
                "context": "File hash identified in report",
                "confidence": "HIGH",
            })

    # SHA1
    for h in SHA1_PATTERN.findall(text):
        val = h.lower()
        if val not in seen_values:
            seen_values.add(val)
            iocs.append({
                "type": "sha1",
                "value": val,
                "context": "File hash identified in report",
                "confidence": "HIGH",
            })

    # MD5
    for h in MD5_PATTERN.findall(text):
        val = h.lower()
        if val not in seen_values:
            seen_values.add(val)
            iocs.append({
                "type": "md5",
                "value": val,
                "context": "File hash identified in report",
                "confidence": "HIGH",
            })

    # Valid Public IPv4 addresses
    for ip in IPV4_PATTERN.findall(text):
        if is_valid_public_ip(ip) and ip not in seen_values:
            seen_values.add(ip)
            iocs.append({
                "type": "ip",
                "value": ip,
                "context": "Network indicator identified in report",
                "confidence": "MEDIUM",
            })

    return iocs


def preprocess_article(
    article_id: str,
    title: str,
    content: str,
    summary: str = "",
    max_chars: int = 12000,
) -> PreprocessedArticle:
    """
    Preprocess an article for LLM intelligence extraction.
    Ensures safe injection boundaries, applies controlled smart truncation if needed,
    and extracts deterministic candidates for validation.
    """
    raw_full = f"{title}\n\n{summary}\n\n{content}".strip()
    original_length = len(raw_full)

    # 1. Deterministic entity extraction across the FULL un-truncated content first
    cves = extract_cves(raw_full)
    mitre = extract_mitre_techniques(raw_full)
    iocs = extract_candidate_iocs(raw_full)

    # 2. Sanitize against prompt injections
    clean = sanitize_untrusted_text(raw_full)

    # 3. Budget & Smart Truncation
    # If content exceeds max_chars, preserve beginning (60%) and ending/technical section (40%)
    truncated = False
    if len(clean) > max_chars:
        truncated = True
        head_budget = int(max_chars * 0.65)
        tail_budget = max_chars - head_budget - 100

        head_part = clean[:head_budget]
        tail_part = clean[-tail_budget:]
        clean = (
            f"{head_part}\n\n"
            f"[... Content truncated for analysis length budget ({original_length} chars down to {max_chars}) ...]\n\n"
            f"{tail_part}"
        )

    return PreprocessedArticle(
        article_id=article_id,
        title=title,
        clean_content=clean,
        truncated=truncated,
        original_length=original_length,
        processed_length=len(clean),
        cve_candidates=cves,
        mitre_candidates=mitre,
        ioc_candidates=iocs,
    )
