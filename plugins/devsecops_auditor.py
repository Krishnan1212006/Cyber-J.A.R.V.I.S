"""
DevSecOps Continuous Compliance, Security Gating & Reporting Plugin for JARVIS.
Integrates shift-left security gate enforcement, OWASP Top 10 coverage matrix generation,
and executive PDF audit report compilation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from plugins._sec_engine import (
    OWASP_TAXONOMY,
    SECURITY_REPORTS_DIR,
    compute_risk_score,
    generate_audit_pdf,
)

logger = logging.getLogger("jarvis.devsecops_auditor")

PLUGIN = {
    "name": "devsecops_auditor",
    "description": (
        "Evaluate DevSecOps security gates, generate OWASP Top 10 compliance matrices, "
        "and export PDF security reports. Enforces shift-left CI/CD security policies "
        "(max critical/high findings, minimum risk score). "
        "Use when the user asks to check security gates, evaluate build compliance, "
        "view OWASP coverage, or generate an audit report."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {
                "type": "STRING",
                "description": (
                    "DevSecOps action: 'evaluate_gate' (check if findings pass policy threshold), "
                    "'owasp_matrix' (generate OWASP Top 10 coverage matrix), "
                    "or 'export_report' (generate executive PDF report for past assessment)."
                ),
            },
            "target": {
                "type": "STRING",
                "description": "Target name or domain associated with the audit.",
            },
            "max_critical": {
                "type": "INTEGER",
                "description": "Maximum allowable critical findings for the gate to pass (default: 0).",
            },
            "max_high": {
                "type": "INTEGER",
                "description": "Maximum allowable high findings for the gate to pass (default: 0).",
            },
            "min_score": {
                "type": "NUMBER",
                "description": "Minimum overall risk score (0-100) required to pass the gate (default: 75.0).",
            },
        },
        "required": ["action"],
    },
}


def _find_latest_target_report(target: str = "") -> Optional[Path]:
    """Finds the most recent JSON audit report in the security reports directory."""
    json_files = sorted(SECURITY_REPORTS_DIR.glob("audit_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not json_files:
        return None
    if not target:
        return json_files[0]
    clean = target.lower().replace("http://", "").replace("https://", "").split("/")[0]
    for p in json_files:
        if clean in p.name.lower():
            return p
    return json_files[0]


def run(parameters: dict, player=None, session_memory=None) -> str:
    action = str(parameters.get("action", "evaluate_gate")).lower().strip()
    target = str(parameters.get("target", "")).strip()
    max_critical = int(parameters.get("max_critical", 0))
    max_high = int(parameters.get("max_high", 0))
    min_score = float(parameters.get("min_score", 75.0))

    if player:
        try:
            player.write_log(f"JARVIS: DevSecOps Auditor running '{action}'...")
        except Exception:
            pass

    # Load findings from latest or specific report
    report_file = _find_latest_target_report(target)
    findings: list[dict[str, Any]] = []
    target_name = target or "Unknown Target"
    risk_summary: dict[str, Any] = {}

    if report_file and report_file.exists():
        try:
            data = json.loads(report_file.read_text(encoding="utf-8"))
            findings = data.get("findings", [])
            target_name = data.get("target", target_name)
            risk_summary = data.get("risk_summary", compute_risk_score(findings))
        except Exception as exc:
            logger.warning(f"Failed to read report file {report_file}: {exc}")

    if not risk_summary:
        risk_summary = compute_risk_score(findings)

    # 1. DevSecOps Security Gate Evaluation
    if action in ("evaluate_gate", "security_gate", "policy"):
        score = risk_summary.get("score", 100.0)
        crit_count = risk_summary.get("confirmed", {}).get("critical", 0) + risk_summary.get("potential", {}).get("critical", 0)
        high_count = risk_summary.get("confirmed", {}).get("high", 0) + risk_summary.get("potential", {}).get("high", 0)

        violations = []
        if crit_count > max_critical:
            violations.append(f"Critical findings ({crit_count}) exceed threshold ({max_critical})")
        if high_count > max_high:
            violations.append(f"High-severity findings ({high_count}) exceed threshold ({max_high})")
        if score < min_score:
            violations.append(f"Overall risk score ({score}) is below minimum allowable ({min_score})")

        gate_passed = len(violations) == 0
        status_text = "PASSED" if gate_passed else "FAILED"

        if player:
            try:
                player.write_log(f"JARVIS DevSecOps Gate [{status_text}]: Score {score}/100 | Critical: {crit_count} | High: {high_count}")
                if violations:
                    for v in violations:
                        player.write_log(f"  ❌ Policy Violation: {v}")
            except Exception:
                pass

        if gate_passed:
            return (
                f"Sir, DevSecOps Security Gate PASSED for {target_name}. "
                f"Risk score is {score}/100 with 0 policy violations."
            )
        else:
            reasons = "; ".join(violations)
            return (
                f"Warning Sir: DevSecOps Security Gate FAILED for {target_name}. "
                f"Status: {reasons}. Remediation required before release."
            )

    # 2. OWASP Top 10 Coverage Matrix
    if action in ("owasp_matrix", "owasp", "coverage"):
        matrix: dict[str, list[str]] = {cat_id: [] for cat_id in OWASP_TAXONOMY}
        for f in findings:
            cat = str(f.get("category", "")).strip()
            cat_id = cat.split(" ")[0].upper()
            if cat_id in matrix:
                matrix[cat_id].append(f.get("title", "Observation"))

        flagged_categories = [
            f"{cat_id} ({OWASP_TAXONOMY[cat_id]['name']}: {len(items)} issues)"
            for cat_id, items in matrix.items() if items
        ]

        if player:
            try:
                player.write_log("JARVIS: OWASP Top 10 Assessment Matrix:")
                for cat_id, info in OWASP_TAXONOMY.items():
                    issues = matrix[cat_id]
                    mark = "⚠️" if issues else "✅"
                    player.write_log(f"  {mark} {cat_id}: {info['name']} ({len(issues)} findings)")
            except Exception:
                pass

        if flagged_categories:
            summary_str = ", ".join(flagged_categories[:3])
            return f"Sir, OWASP Top 10 assessment identified exposures in: {summary_str}."
        return "Sir, no OWASP Top 10 vulnerabilities are currently flagged for this target."

    # 3. Export PDF Report
    if action in ("export_report", "pdf", "report"):
        pdf_path = generate_audit_pdf(target_name, findings, risk_summary)
        if player:
            try:
                player.write_log(f"JARVIS: Generated executive audit report at {pdf_path}")
            except Exception:
                pass
        return f"Sir, the executive PDF security audit report has been compiled and saved to {pdf_path.name}."

    return "Sir, choose action: 'evaluate_gate', 'owasp_matrix', or 'export_report'."
