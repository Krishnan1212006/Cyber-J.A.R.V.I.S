"""
OWASP Top 10 2025 Connector and Defensive Learning Integration for JARVIS (Phase 3.5).

Provides:
- Official OWASP Top 10:2025 standard reference catalog (A01:2025 through A10:2025).
- Web application security relevance determination (avoids forcing non-web threats into OWASP).
- Evidence-backed mapping distinguishing 'confirmed' vs. 'ai_suggested' vs. 'not_applicable'.
- Defensive explanations, secure development recommendations, and safe lab validation guidance.
"""

from __future__ import annotations
import json
import logging
import re
from typing import Any, Optional

from .db import IntelligenceDB
from .models import Article, ArticleAnalysis, ArticleFrameworkMapping, OwaspCategory, utc_now_iso

logger = logging.getLogger(__name__)

OWASP_YEAR = "2025"

# Official OWASP Top 10:2025 Reference Catalog
OFFICIAL_OWASP_2025: list[dict[str, Any]] = [
    {
        "category_id": "A01:2025",
        "category_name": "Broken Access Control",
        "description": "Failures where users can act outside of their intended permissions. Includes IDOR, horizontal/vertical privilege escalation, missing authorization checks, and consolidated Server-Side Request Forgery (SSRF).",
        "common_cwes": ["CWE-200", "CWE-284", "CWE-285", "CWE-639", "CWE-918"],
        "prevention_guidance": "Deny access by default. Implement centralized role-based or attribute-based access control (RBAC/ABAC). Validate authorization on every request at the controller/domain boundary. Disable directory listing and restrict SSRF with strict URL parsing and network egress firewalls.",
        "safe_lab_exercise": "PortSwigger Web Security Academy: Access Control & SSRF Labs; OWASP Juice Shop 'Admin Access' challenge.",
    },
    {
        "category_id": "A02:2025",
        "category_name": "Security Misconfiguration",
        "description": "Insecure default settings, unhardened cloud configurations, open cloud storage buckets, exposed administrative interfaces, unpatched legacy features, and verbose debug error banners.",
        "common_cwes": ["CWE-16", "CWE-209", "CWE-311", "CWE-1004"],
        "prevention_guidance": "Implement automated infrastructure-as-code (IaC) security scanning. Disable unnecessary ports, services, and default credentials. Implement Content Security Policy (CSP) headers and ensure error handlers return sanitized messages without stack traces.",
        "safe_lab_exercise": "OWASP Juice Shop: 'Security Misconfiguration'; TryHackMe: 'Cloud Security Fundamentals' lab.",
    },
    {
        "category_id": "A03:2025",
        "category_name": "Software Supply Chain Failures",
        "description": "Risks, compromises, and vulnerabilities introduced across third-party dependencies, open-source packages, build pipelines, package registries, and developer toolchains.",
        "common_cwes": ["CWE-1104", "CWE-1357", "CWE-829"],
        "prevention_guidance": "Maintain a verified Software Bill of Materials (SBOM). Automate software composition analysis (SCA) with tools like Trivy or Snyk. Pin dependency hashes, sign container images, and restrict build pipeline network egress.",
        "safe_lab_exercise": "Local Docker container vulnerability scanning lab using Trivy; GitHub Dependabot security remediation lab.",
    },
    {
        "category_id": "A04:2025",
        "category_name": "Cryptographic Failures",
        "description": "Exposure of sensitive data (PII, credentials, healthcare records) due to lack of encryption, weak cryptographic algorithms (MD5, SHA1, DES), deprecated TLS protocols, or hardcoded secrets.",
        "common_cwes": ["CWE-259", "CWE-326", "CWE-327", "CWE-328"],
        "prevention_guidance": "Encrypt all data in transit using modern TLS (TLS 1.3). Encrypt data at rest with authenticated encryption (AES-256-GCM). Never store passwords in plaintext; use modern salted hashing (Argon2id, bcrypt). Never hardcode encryption keys in source repositories.",
        "safe_lab_exercise": "Cryptohack or PortSwigger: 'Cryptographic Weaknesses' lab; GitGuardian secret detection workshop.",
    },
    {
        "category_id": "A05:2025",
        "category_name": "Injection",
        "description": "Hostile or untrusted user input is sent to an interpreter as part of a command or query, resulting in unintended command execution (SQLi, OS command injection, NoSQL injection, LDAP, SSTI).",
        "common_cwes": ["CWE-77", "CWE-78", "CWE-89", "CWE-94", "CWE-1336"],
        "prevention_guidance": "Use parameterized queries / prepared statements for all database access. Avoid invoking shell interpreters directly (e.g. use subprocess with list arguments instead of shell=True). Implement strict input allow-listing and context-aware output encoding.",
        "safe_lab_exercise": "PortSwigger Web Security Academy: 'SQL Injection' and 'Server-Side Template Injection (SSTI)' interactive labs.",
    },
    {
        "category_id": "A06:2025",
        "category_name": "Insecure Design",
        "description": "Flaws stemming from architectural and design defects that cannot be fixed by perfect implementation alone (e.g. lack of threat modeling, unbounded resource allocation, missing business logic limits).",
        "common_cwes": ["CWE-20", "CWE-400", "CWE-601"],
        "prevention_guidance": "Incorporate threat modeling (STRIDE) during sprint planning. Establish architectural secure design patterns. Apply rate limiting, defense in depth, and failure isolation throughout microservice topologies.",
        "safe_lab_exercise": "Threat modeling exercise with OWASP Threat Dragon on a three-tier architecture.",
    },
    {
        "category_id": "A07:2025",
        "category_name": "Authentication Failures",
        "description": "Weaknesses in user identity verification and session management allowing credential stuffing, brute force, session hijacking, or MFA bypasses.",
        "common_cwes": ["CWE-287", "CWE-384", "CWE-613", "CWE-799"],
        "prevention_guidance": "Enforce phishing-resistant multi-factor authentication (FIDO2 / WebAuthn). Implement account lockout or exponential backoff against brute-force attacks. Invalidate session tokens upon logout and enforce secure cookie flags (HttpOnly, Secure, SameSite=Strict).",
        "safe_lab_exercise": "PortSwigger: 'Authentication Vulnerabilities' labs; local Keycloak MFA configuration lab.",
    },
    {
        "category_id": "A08:2025",
        "category_name": "Software or Data Integrity Failures",
        "description": "Code and infrastructure that fails to protect against integrity violations, including insecure deserialization, unsigned auto-updates, and untrusted CI/CD pipeline triggers.",
        "common_cwes": ["CWE-502", "CWE-565", "CWE-829"],
        "prevention_guidance": "Do not deserialize untrusted data with native object serializers (pickle, Java ObjectInputStream, PHP unserialize). Use safe data interchange formats (JSON, Protocol Buffers) with strict schema validation. Sign and verify firmware/update payloads using asymmetric digital signatures.",
        "safe_lab_exercise": "PortSwigger: 'Insecure Deserialization' lab; Sigstore / Cosign container signing demonstration.",
    },
    {
        "category_id": "A09:2025",
        "category_name": "Security Logging and Alerting Failures",
        "description": "Insufficient logging of security-critical actions, missing centralized audit trails, and absence of real-time alerting that delays breach detection and incident response.",
        "common_cwes": ["CWE-778", "CWE-117"],
        "prevention_guidance": "Log all authentication attempts, access control failures, and high-impact administrative actions. Ensure log entries cannot be modified by attackers (append-only central SIEM). Implement automated alerting on abnormal velocity spikes.",
        "safe_lab_exercise": "Setting up Elastic Security / Wazuh to detect web application attacks in a local lab.",
    },
    {
        "category_id": "A10:2025",
        "category_name": "Mishandling of Exceptional Conditions",
        "description": "Security vulnerabilities arising from improper, incomplete, or unsafe error and exception handling, leading to state corruption, security check bypasses, or denial of service.",
        "common_cwes": ["CWE-754", "CWE-755", "CWE-391"],
        "prevention_guidance": "Implement structured try-catch-finally blocks that fail closed. Ensure security authorization decisions do not default to permit when an exception occurs. Handle resource allocation cleanups in ensure/finally blocks.",
        "safe_lab_exercise": "Testing fail-open authentication handlers in a local mock web service.",
    },
]

# Keywords indicating web application security context
WEB_SECURITY_INDICATORS = {
    "web", "http", "api", "rest", "graphql", "endpoint", "browser", "html", "javascript",
    "xss", "csrf", "ssrf", "injection", "sql", "authentication", "session", "jwt",
    "cookie", "oauth", "token", "header", "cors", "portal", "dashboard", "url",
    "proxy", "gateway", "apache", "nginx", "tomcat", "iis", "php", "django", "spring"
}

# Non-web keywords (to ensure articles about physical, firmware, or kernel exploits aren't forced into OWASP)
NON_WEB_DOMINANT_INDICATORS = {
    "hardware tap", "satellite uplink", "physical cable", "submarine cable",
    "bootloader", "kernel rootkit", "firmware flashing", "scada plc ladder logic",
    "kernel driver", "win32k", "ioctl", "baseband", "firmware exploit",
    "local kernel exploit", "local privilege escalation",
}


def is_web_security_related(
    article: Article,
    analysis: ArticleAnalysis,
) -> tuple[bool, str]:
    """
    Determine whether an article genuinely concerns web application security.
    Prevents forcing unrelated threats (firmware, kernel drivers, physical espionage) into OWASP.
    Returns (is_web_related, reason).
    """
    combined_text = (
        f"{article.title} {article.content or ''} {analysis.severity_reason or ''} "
        f"{' '.join(analysis.affected_products)} {' '.join(analysis.attack_types)} "
        f"{' '.join(analysis.threat_types)}"
    ).lower()

    # Check for non-web dominant indicators
    for nw in NON_WEB_DOMINANT_INDICATORS:
        if nw in combined_text and not any(w in combined_text for w in ("web", "api", "http", "portal")):
            return False, f"Article pertains to non-web domain ({nw})."

    # Check for web indicators
    matched_indicators = [ind for ind in WEB_SECURITY_INDICATORS if ind in combined_text]
    if len(matched_indicators) >= 2 or any(p in combined_text for p in ("web server", "web application", "rest api", "portal", "cloud gateway", "ssrf")):
        return True, f"Article describes web/API application domain (Matched indicators: {', '.join(matched_indicators[:4])})."

    # Check if CVE affected products are web applications
    web_products = {"server", "portal", "gateway", "gitlab", "sharepoint", "apache", "nginx", "tomcat", "wordpress"}
    for prod in analysis.affected_products:
        if any(wp in prod.lower() for wp in web_products):
            return True, f"Affected product '{prod}' is a web/server application."

    return False, "Insufficient web application security evidence (Not Applicable)."


class OwaspTop10Connector:
    """Official OWASP Top 10:2025 Reference Catalog and evidence-based mapping engine."""

    def __init__(self, db: IntelligenceDB):
        self.db = db
        self.year = OWASP_YEAR
        self._ensure_dataset_initialized()

    def _ensure_dataset_initialized(self) -> None:
        """Seed official OWASP Top 10 2025 categories into database if missing."""
        try:
            stored = self.db.get_all_owasp_categories()
            if not stored:
                self.ingest_core_dataset()
        except Exception as e:
            logger.warning(f"Error checking OWASP Top 10 dataset: {e}")

    def ingest_core_dataset(self) -> int:
        """Populate database with official OWASP Top 10:2025 standard categories."""
        count = 0
        now = utc_now_iso()
        for item in OFFICIAL_OWASP_2025:
            cat = OwaspCategory(
                category_id=item["category_id"],
                category_name=item["category_name"],
                year=self.year,
                description=item["description"],
                common_cwes=item.get("common_cwes", []),
                prevention_guidance=item.get("prevention_guidance", ""),
                safe_lab_exercise=item.get("safe_lab_exercise", ""),
                updated_at=now,
            )
            self.db.upsert_owasp_category(cat)
            count += 1
        logger.info(f"Ingested {count} official OWASP Top 10 {self.year} categories.")
        return count

    def get_category(self, category_id: str) -> Optional[OwaspCategory]:
        """Lookup OWASP category by ID (e.g. 'A01:2025' or 'A01')."""
        clean = category_id.strip().upper()
        if not clean.endswith(f":{self.year}") and len(clean) == 3:
            clean = f"{clean}:{self.year}"
        return self.db.get_owasp_category(clean)

    def is_web_security_related(
        self,
        article: Article,
        analysis: ArticleAnalysis,
    ) -> tuple[bool, str]:
        """Delegate to module-level is_web_security_related function."""
        return is_web_security_related(article, analysis)

    def map_article_to_owasp(
        self,
        article: Article,
        analysis: ArticleAnalysis,
    ) -> list[ArticleFrameworkMapping]:
        """
        Map article disclosure to OWASP Top 10:2025 categories when evidence exists.
        Returns:
        - Confirmed or AI-suggested mappings when web-related.
        - Empty list when unmapped / not applicable.
        """
        is_web, reason = self.is_web_security_related(article, analysis)
        if not is_web:
            return []

        mappings: list[ArticleFrameworkMapping] = []
        body_text = f"{article.title} {article.content or ''} {analysis.summary}".lower()
        sentences = re.split(r"[.\n]", f"{article.title}. {article.content or ''}. {analysis.summary}")

        def _find_evidence(keywords: list[str]) -> str:
            for s in sentences:
                s_clean = s.strip()
                s_lower = s_clean.lower()
                if any(k in s_lower for k in keywords):
                    return s_clean
            return analysis.summary[:200]

        # Rule 1: A01:2025 - Broken Access Control / SSRF
        if any(k in body_text for k in ("access control", "bypass auth", "idor", "privilege escalation", "unauthorized access", "ssrf", "server-side request forgery")):
            ev = _find_evidence(["access control", "bypass", "unauthorized", "ssrf", "privilege escalation"])
            cat = self.get_category("A01:2025")
            is_confirmed = any(k in body_text for k in ("access control", "ssrf", "idor", "privilege escalation"))
            mappings.append(
                ArticleFrameworkMapping(
                    mapping_id=f"map_owasp_{article.article_id}_A01",
                    article_id=article.article_id,
                    framework="OWASP_TOP10",
                    framework_item_id="A01:2025",
                    framework_item_name=cat.category_name if cat else "Broken Access Control",
                    evidence_text=ev or "Flaw permits unauthorized actions or access control bypass.",
                    mapping_method="confirmed" if is_confirmed else "ai_suggested",
                    confidence="HIGH" if is_confirmed else "MEDIUM",
                    dataset_version=self.year,
                    metadata={"year": self.year, "cwes": cat.common_cwes if cat else []},
                    created_at=utc_now_iso(),
                )
            )

        # Rule 2: A02:2025 - Security Misconfiguration
        if any(k in body_text for k in ("misconfiguration", "default credential", "exposed bucket", "unhardened", "open port", "insecure default")):
            ev = _find_evidence(["misconfiguration", "default", "exposed", "unhardened"])
            cat = self.get_category("A02:2025")
            mappings.append(
                ArticleFrameworkMapping(
                    mapping_id=f"map_owasp_{article.article_id}_A02",
                    article_id=article.article_id,
                    framework="OWASP_TOP10",
                    framework_item_id="A02:2025",
                    framework_item_name=cat.category_name if cat else "Security Misconfiguration",
                    evidence_text=ev or "Vulnerability stems from insecure configuration or exposed defaults.",
                    mapping_method="confirmed",
                    confidence="HIGH",
                    dataset_version=self.year,
                    metadata={"year": self.year, "cwes": cat.common_cwes if cat else []},
                    created_at=utc_now_iso(),
                )
            )

        # Rule 3: A03:2025 - Software Supply Chain Failures
        if any(k in body_text for k in ("supply chain", "dependency", "npm", "pypi", "third-party library", "malicious package", "build pipeline")):
            ev = _find_evidence(["supply chain", "dependency", "package", "library"])
            cat = self.get_category("A03:2025")
            mappings.append(
                ArticleFrameworkMapping(
                    mapping_id=f"map_owasp_{article.article_id}_A03",
                    article_id=article.article_id,
                    framework="OWASP_TOP10",
                    framework_item_id="A03:2025",
                    framework_item_name=cat.category_name if cat else "Software Supply Chain Failures",
                    evidence_text=ev or "Compromise introduced via third-party dependencies or upstream package registries.",
                    mapping_method="confirmed",
                    confidence="HIGH",
                    dataset_version=self.year,
                    metadata={"year": self.year, "cwes": cat.common_cwes if cat else []},
                    created_at=utc_now_iso(),
                )
            )

        # Rule 4: A05:2025 - Injection
        if any(k in body_text for k in ("sql injection", "sqli", "command injection", "code injection", "rce via injection", "ssti")):
            ev = _find_evidence(["injection", "sqli", "command injection"])
            cat = self.get_category("A05:2025")
            mappings.append(
                ArticleFrameworkMapping(
                    mapping_id=f"map_owasp_{article.article_id}_A05",
                    article_id=article.article_id,
                    framework="OWASP_TOP10",
                    framework_item_id="A05:2025",
                    framework_item_name=cat.category_name if cat else "Injection",
                    evidence_text=ev or "Hostile input supplied to interpreter allows command or query execution.",
                    mapping_method="confirmed",
                    confidence="HIGH",
                    dataset_version=self.year,
                    metadata={"year": self.year, "cwes": cat.common_cwes if cat else []},
                    created_at=utc_now_iso(),
                )
            )

        # Rule 5: A07:2025 - Authentication Failures
        if any(k in body_text for k in ("authentication bypass", "credential stuffing", "weak password", "mfa bypass", "session hijacking")):
            ev = _find_evidence(["authentication", "credential", "session", "mfa"])
            cat = self.get_category("A07:2025")
            mappings.append(
                ArticleFrameworkMapping(
                    mapping_id=f"map_owasp_{article.article_id}_A07",
                    article_id=article.article_id,
                    framework="OWASP_TOP10",
                    framework_item_id="A07:2025",
                    framework_item_name=cat.category_name if cat else "Authentication Failures",
                    evidence_text=ev or "Flaw in user identity verification, session management, or authentication controls.",
                    mapping_method="confirmed",
                    confidence="HIGH",
                    dataset_version=self.year,
                    metadata={"year": self.year, "cwes": cat.common_cwes if cat else []},
                    created_at=utc_now_iso(),
                )
            )

        # Save to database
        for m in mappings:
            self.db.save_framework_mapping(m)

        return mappings
