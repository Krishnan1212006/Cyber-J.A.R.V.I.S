"""
Validation and JSON repair engine for JARVIS Cybersecurity Subsystem.

Enforces:
- Markdown and malformed JSON repair
- Strict type and schema constraints
- CVE format compliance (CVE-YYYY-NNNN+)
- MITRE ATT&CK technique syntax (Txxxx or Txxxx.xxx)
- IOC syntax (IP addresses, hash lengths, domains)
- Severity and Confidence enumerations
- Entity deduplication and hallucination guards
"""

from __future__ import annotations
import ipaddress
import json
import logging
import re
from typing import Any, Optional

from .preprocessor import CVE_PATTERN, MITRE_TECHNIQUE_PATTERN, PreprocessedArticle

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
VALID_IOC_TYPES = {"ip", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "filename", "email", "registry"}


class ValidationError(Exception):
    """Raised when LLM output violates essential schema requirements beyond repair."""
    pass


def extract_json_block(text: str) -> str:
    """Extract raw JSON substring from text, handling markdown fences and extraneous prose."""
    if not text:
        return ""

    s = text.strip()

    # Strip markdown code blocks: ```json ... ``` or ``` ... ```
    if "```" in s:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", s, re.IGNORECASE)
        if match:
            s = match.group(1).strip()

    # Find opening brace and matching closing brace
    first_brace = s.find("{")
    last_brace = s.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        s = s[first_brace : last_brace + 1]

    # Clean common trailing commas before closing braces/brackets
    s = re.sub(r",\s*([\]}])", r"\1", s)
    return s


def validate_cve_format(cve: str) -> bool:
    """Validate CVE string format."""
    return bool(CVE_PATTERN.fullmatch(cve.strip()))


def validate_mitre_id(tech_id: str) -> bool:
    """Validate MITRE technique ID format (e.g. T1190 or T1059.001)."""
    return bool(MITRE_TECHNIQUE_PATTERN.fullmatch(tech_id.strip()))


def deduplicate_list(items: list[Any]) -> list[Any]:
    """Deduplicate list while preserving order, discarding empty strings."""
    seen = set()
    result = []
    for item in items:
        if isinstance(item, str):
            clean_item = item.strip()
            if clean_item and clean_item.lower() not in seen:
                seen.add(clean_item.lower())
                result.append(clean_item)
        elif isinstance(item, dict):
            # Serialize for hashing
            serialized = json.dumps(item, sort_keys=True)
            if serialized not in seen:
                seen.add(serialized)
                result.append(item)
        elif item is not None:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return result


def validate_and_repair_analysis(
    raw_response: str,
    preprocessed: Optional[PreprocessedArticle] = None,
) -> tuple[dict[str, Any], list[str]]:
    """
    Parse, validate, and safely repair LLM-generated cybersecurity intelligence JSON.
    Returns (repaired_dict, list_of_warnings).
    Raises ValidationError if JSON cannot be parsed or essential fields cannot be recovered.
    """
    warnings: list[str] = []
    json_str = extract_json_block(raw_response)
    if not json_str:
        raise ValidationError("No JSON object could be extracted from LLM response.")

    try:
        data = json.loads(json_str)
    except Exception as e:
        logger.warning("JSON decode failed: %s. Attempting secondary repair...", e)
        # Secondary repair: replace unescaped control characters
        cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", json_str)
        try:
            data = json.loads(cleaned)
        except Exception as e2:
            raise ValidationError(f"Invalid JSON response: {e2}") from e2

    if not isinstance(data, dict):
        raise ValidationError(f"Expected JSON root object/dict, got {type(data).__name__}")

    repaired: dict[str, Any] = {}

    # 1. Summary
    raw_summary = data.get("summary") or ""
    if isinstance(raw_summary, list):
        raw_summary = " ".join(str(x) for x in raw_summary)
    repaired["summary"] = str(raw_summary).strip()
    if not repaired["summary"]:
        warnings.append("Missing summary; generated fallback from article title")
        repaired["summary"] = f"Cybersecurity intelligence report for: {preprocessed.title if preprocessed else 'Incident'}."

    # 2. String list fields
    list_keys = [
        "threat_types",
        "attack_types",
        "attack_vectors",
        "threat_actors",
        "threat_groups",
        "malware",
        "ransomware",
        "vulnerabilities",
        "affected_products",
        "affected_vendors",
        "affected_versions",
        "target_sectors",
        "target_countries",
        "target_organizations",
        "tools",
        "technologies",
        "detection_methods",
        "mitigation",
        "remediation",
        "security_recommendations",
        "facts",
        "inferences",
    ]

    for key in list_keys:
        val = data.get(key)
        if isinstance(val, list):
            repaired[key] = deduplicate_list(val)
        elif isinstance(val, str) and val.strip():
            repaired[key] = [val.strip()]
        else:
            repaired[key] = []

    # 3. CVE Validation & Cross-referencing
    raw_cves = data.get("cves") or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]

    valid_cves: list[str] = []
    seen_cves: set[str] = set()

    for item in raw_cves:
        cve_str = ""
        if isinstance(item, str):
            cve_str = item.strip().upper()
        elif isinstance(item, dict) and "id" in item:
            cve_str = str(item["id"]).strip().upper()

        if cve_str and validate_cve_format(cve_str):
            if cve_str not in seen_cves:
                seen_cves.add(cve_str)
                valid_cves.append(cve_str)
        elif cve_str:
            warnings.append(f"Discarded invalid CVE format: {cve_str}")

    # Merge verified pre-extracted candidate CVEs if present in original article
    if preprocessed and preprocessed.cve_candidates:
        for cand in preprocessed.cve_candidates:
            if cand.upper() not in seen_cves:
                valid_cves.append(cand.upper())
                seen_cves.add(cand.upper())

    repaired["cves"] = valid_cves

    # 4. CVSS Validation
    raw_cvss = data.get("cvss")
    repaired_cvss: dict[str, Any] = {}
    if isinstance(raw_cvss, dict):
        score = raw_cvss.get("score")
        if isinstance(score, (int, float)) and 0.0 <= score <= 10.0:
            repaired_cvss["score"] = float(score)
        vector = raw_cvss.get("vector")
        if isinstance(vector, str) and vector.strip():
            repaired_cvss["vector"] = vector.strip()
        sev = raw_cvss.get("severity")
        if isinstance(sev, str) and sev.upper() in VALID_SEVERITIES:
            repaired_cvss["severity"] = sev.upper()
    repaired["cvss"] = repaired_cvss

    # 5. MITRE ATT&CK Validation
    raw_mitre = data.get("mitre_attack") or []
    if not isinstance(raw_mitre, list):
        raw_mitre = []

    valid_mitre: list[dict[str, Any]] = []
    for item in raw_mitre:
        if isinstance(item, dict):
            tech_id = str(item.get("technique_id") or item.get("id") or "").strip().upper()
            if validate_mitre_id(tech_id):
                valid_mitre.append({
                    "tactic": str(item.get("tactic") or "Threat Action").strip(),
                    "technique_id": tech_id,
                    "technique_name": str(item.get("technique_name") or item.get("name") or tech_id).strip(),
                    "evidence": str(item.get("evidence") or "").strip(),
                    "confidence": str(item.get("confidence") or "HIGH").upper()
                    if str(item.get("confidence") or "").upper() in VALID_CONFIDENCES
                    else "MEDIUM",
                })
            elif tech_id:
                warnings.append(f"Discarded invalid MITRE technique ID: {tech_id}")
    repaired["mitre_attack"] = deduplicate_list(valid_mitre)

    # 6. IOC Validation
    raw_iocs = data.get("iocs") or []
    if not isinstance(raw_iocs, list):
        raw_iocs = []

    valid_iocs: list[dict[str, Any]] = []
    for item in raw_iocs:
        if isinstance(item, dict):
            ioc_type = str(item.get("type") or "indicator").strip().lower()
            val = str(item.get("value") or "").strip()
            if not val:
                continue

            # Verify IP
            if ioc_type in ("ip", "ipv4"):
                try:
                    ipaddress.ip_address(val)
                except ValueError:
                    warnings.append(f"Discarded invalid IP IOC: {val}")
                    continue

            # Verify Hash
            if ioc_type in ("sha256", "sha1", "md5"):
                expected_lens = {"sha256": 64, "sha1": 40, "md5": 32}
                if len(val) != expected_lens.get(ioc_type):
                    warnings.append(f"Discarded malformed {ioc_type} hash IOC: {val}")
                    continue

            valid_iocs.append({
                "type": ioc_type,
                "value": val,
                "context": str(item.get("context") or "").strip(),
                "confidence": str(item.get("confidence") or "MEDIUM").upper()
                if str(item.get("confidence") or "").upper() in VALID_CONFIDENCES
                else "MEDIUM",
            })
    repaired["iocs"] = deduplicate_list(valid_iocs)

    # 7. Technical Explanation
    raw_tech = data.get("technical_explanation")
    if isinstance(raw_tech, dict):
        repaired["technical_explanation"] = {
            k: str(v).strip() for k, v in raw_tech.items() if isinstance(v, (str, list, dict)) and v
        }
    else:
        repaired["technical_explanation"] = {}

    # 8. Impact
    raw_impact = data.get("impact")
    if isinstance(raw_impact, dict):
        repaired["impact"] = {str(k): str(v).strip() for k, v in raw_impact.items() if v}
    else:
        repaired["impact"] = {}

    # 9. Severity
    raw_sev = str(data.get("severity") or "MEDIUM").strip().upper()
    if raw_sev not in VALID_SEVERITIES:
        warnings.append(f"Invalid severity '{raw_sev}', defaulted to 'MEDIUM'")
        raw_sev = "MEDIUM"
    repaired["severity"] = raw_sev

    raw_reason = str(data.get("severity_reason") or "").strip()
    if not raw_reason:
        raw_reason = f"Classified as {raw_sev} based on threat analysis and affected systems."
    repaired["severity_reason"] = raw_reason

    # 10. Confidence
    raw_conf = str(data.get("confidence") or "HIGH").strip().upper()
    if raw_conf not in VALID_CONFIDENCES:
        raw_conf = "HIGH"
    repaired["confidence"] = raw_conf

    return repaired, warnings
