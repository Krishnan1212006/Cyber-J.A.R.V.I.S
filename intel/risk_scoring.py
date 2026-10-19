"""
Deterministic, explainable JARVIS Intelligence Risk Scoring Model.

Transparent multi-factor mathematical formulation:
Total Risk Score (0-100) =
    Severity Weight (max 30)
  + Exploitation Weight (max 20)
  + Trend Acceleration Weight (max 15)
  + Critical Sector Targeting Weight (max 15)
  + Scope & Frequency Weight (max 10)
  + Recency Weight (max 10)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .models import ArticleAnalysis
from .time_windows import parse_iso, utc_now

CRITICAL_SECTOR_KEYWORDS = {
    "government",
    "critical infrastructure",
    "defense",
    "healthcare",
    "financial services",
    "finance",
    "banking",
    "energy",
    "telecommunications",
    "nuclear",
    "transportation",
    "water",
}


@dataclass
class RiskScoreResult:
    """Detailed result of deterministic risk score calculation."""

    score: float
    category: str  # 'LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'
    factor_breakdown: dict[str, float]
    reasons: list[str]
    evidence_count: int
    article_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "category": self.category,
            "metric_name": "JARVIS Intelligence Risk Score",
            "factor_breakdown": {k: round(v, 2) for k, v in self.factor_breakdown.items()},
            "reasons": self.reasons,
            "evidence_count": self.evidence_count,
            "article_ids": self.article_ids,
        }


def classify_risk_category(
    score: float,
    thresholds: Optional[dict[str, float]] = None,
) -> str:
    """Map numeric risk score (0-100) to standard categorical level."""
    t = thresholds or {
        "LOW": 20.0,
        "MODERATE": 40.0,
        "MEDIUM": 60.0,
        "HIGH": 80.0,
    }
    if score <= t["LOW"]:
        return "LOW"
    elif score <= t["MODERATE"]:
        return "MODERATE"
    elif score <= t["MEDIUM"]:
        return "MEDIUM"
    elif score <= t["HIGH"]:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_risk_score(
    analyses: list[ArticleAnalysis],
    trend_status: str = "STABLE",
    ref_time: Optional[datetime] = None,
    thresholds: Optional[dict[str, float]] = None,
) -> RiskScoreResult:
    """
    Calculate deterministic JARVIS Intelligence Risk Score for a collection of analyzed articles.
    """
    if not analyses:
        return RiskScoreResult(
            score=0.0,
            category="LOW",
            factor_breakdown={
                "severity": 0.0,
                "exploitation": 0.0,
                "trend_acceleration": 0.0,
                "critical_sector": 0.0,
                "scope_frequency": 0.0,
                "recency": 0.0,
            },
            reasons=["No active threat intelligence reports in selected window."],
            evidence_count=0,
            article_ids=[],
        )

    now = ref_time or utc_now()
    reasons: list[str] = []
    article_ids = [a.article_id for a in analyses]
    count = len(analyses)

    # 1. Severity Factor (Max 30)
    sev_weights = {"CRITICAL": 30.0, "HIGH": 20.0, "MEDIUM": 10.0, "LOW": 4.0, "INFO": 1.0}
    crit_count = sum(1 for a in analyses if a.severity == "CRITICAL")
    high_count = sum(1 for a in analyses if a.severity == "HIGH")
    med_count = sum(1 for a in analyses if a.severity == "MEDIUM")

    # Aggregate severity score with bonus for multiple criticals
    base_sev = max((sev_weights.get(a.severity, 10.0) for a in analyses), default=0.0)
    if crit_count > 1:
        base_sev = min(30.0, base_sev + (crit_count - 1) * 2.0)
    severity_factor = min(30.0, base_sev)

    if crit_count > 0:
        reasons.append(f"Contains {crit_count} CRITICAL severity disclosure(s).")
    elif high_count > 0:
        reasons.append(f"Contains {high_count} HIGH severity threat report(s).")

    # 2. Exploitation Evidence Factor (Max 20)
    # Check if active exploitation or weaponized attacks were confirmed
    has_active_exploit = False
    has_ransomware = False
    for a in analyses:
        txt = (a.summary + " " + a.severity_reason + " " + " ".join(a.attack_types)).lower()
        if "active exploitation" in txt or "actively exploited" in txt or "weaponiz" in txt or "in the wild" in txt:
            has_active_exploit = True
        if a.ransomware or "ransomware" in txt:
            has_ransomware = True

    if has_active_exploit:
        exploitation_factor = 20.0
        reasons.append("Evidence of active, in-the-wild exploitation confirmed.")
    elif has_ransomware:
        exploitation_factor = 16.0
        reasons.append("Weaponized ransomware deployment observed.")
    else:
        has_cve = any(bool(a.cves) for a in analyses)
        exploitation_factor = 8.0 if has_cve else 2.0
        if has_cve:
            reasons.append("Identified specific software vulnerabilities (CVEs) without verified wild exploitation.")

    # 3. Trend Acceleration Factor (Max 15)
    trend_weights = {
        "EMERGING": 15.0,
        "INCREASING": 12.0,
        "STABLE": 6.0,
        "INSUFFICIENT_DATA": 3.0,
        "DECREASING": 1.0,
        "DECLINING": 0.0,
    }
    trend_factor = trend_weights.get(trend_status.upper(), 6.0)
    if trend_status.upper() in ("EMERGING", "INCREASING"):
        reasons.append(f"Threat activity is accelerating (Trend: {trend_status.upper()}).")

    # 4. Critical Sector Targeting Factor (Max 15)
    targeted_crit_sectors: set[str] = set()
    for a in analyses:
        for s in a.target_sectors:
            s_clean = s.strip().lower()
            if any(k in s_clean for k in CRITICAL_SECTOR_KEYWORDS):
                targeted_crit_sectors.add(s.strip())

    if len(targeted_crit_sectors) >= 2:
        critical_sector_factor = 15.0
        reasons.append(f"Multiple high-value critical sectors targeted: {', '.join(sorted(targeted_crit_sectors)[:3])}.")
    elif len(targeted_crit_sectors) == 1:
        critical_sector_factor = 10.0
        reasons.append(f"Critical sector targeted: {list(targeted_crit_sectors)[0]}.")
    else:
        critical_sector_factor = 2.0

    # 5. Scope & Frequency Factor (Max 10)
    # Scales with volume of distinct reports and products affected
    all_products = {p for a in analyses for p in a.affected_products if p.strip()}
    scope_pts = min(6.0, len(analyses) * 1.5) + min(4.0, len(all_products) * 1.0)
    scope_factor = min(10.0, scope_pts)
    if len(all_products) >= 2:
        reasons.append(f"Broad operational impact affecting {len(all_products)} product lines.")

    # 6. Recency Factor (Max 10)
    # Most recent article publication time
    recency_factor = 2.0
    try:
        latest_pub = max(parse_iso(a.published_at) for a in analyses if a.published_at)
        delta = now - latest_pub
        if delta.total_seconds() <= 86400 * 2:  # within 48h
            recency_factor = 10.0
            reasons.append("Recent activity reported within the last 48 hours.")
        elif delta.total_seconds() <= 86400 * 7:  # within 7 days
            recency_factor = 7.0
        elif delta.total_seconds() <= 86400 * 30:  # within 30 days
            recency_factor = 4.0
    except Exception:
        recency_factor = 5.0

    # Sum total score (0 to 100)
    total_score = severity_factor + exploitation_factor + trend_factor + critical_sector_factor + scope_factor + recency_factor
    clamped_score = max(0.0, min(100.0, total_score))
    category = classify_risk_category(clamped_score, thresholds=thresholds)

    breakdown = {
        "severity": severity_factor,
        "exploitation": exploitation_factor,
        "trend_acceleration": trend_factor,
        "critical_sector": critical_sector_factor,
        "scope_frequency": scope_factor,
        "recency": recency_factor,
    }

    return RiskScoreResult(
        score=clamped_score,
        category=category,
        factor_breakdown=breakdown,
        reasons=reasons,
        evidence_count=count,
        article_ids=article_ids,
    )
