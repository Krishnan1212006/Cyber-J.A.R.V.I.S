"""
Deterministic statistical trend detection, entity frequency analysis, and emerging threat classification.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TrendResult:
    """Calculated trend metrics for a specific entity or metric."""

    metric_name: str
    current_count: int
    previous_count: int
    change: int
    percentage_change: Optional[float]
    trend_status: str  # 'INCREASING', 'DECREASING', 'STABLE', 'EMERGING', 'DECLINING', 'INSUFFICIENT_DATA'
    trend_reason: str
    trend_score: float  # -1.0 (steep decline) to +1.0 (steep rise)
    evidence_count: int
    unique_dates_count: int
    confidence: str  # 'HIGH', 'MEDIUM', 'LOW'
    supporting_article_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def absolute_change(self) -> int:
        return self.change

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.metric_name,
            "metric_name": self.metric_name,
            "current_count": self.current_count,
            "previous_count": self.previous_count,
            "change": self.change,
            "absolute_change": self.change,
            "percentage_change": self.percentage_change,
            "trend_status": self.trend_status,
            "trend_reason": self.trend_reason,
            "trend_score": round(self.trend_score, 2),
            "evidence_count": self.evidence_count,
            "unique_dates_count": self.unique_dates_count,
            "confidence": self.confidence,
            "supporting_article_ids": self.supporting_article_ids,
            "metadata": self.metadata,
        }



def calculate_trend(
    metric_name: str,
    current_count: int,
    previous_count: int,
    supporting_article_ids: Optional[list[str]] = None,
    unique_dates: Optional[set[str]] = None,
    min_evidence_threshold: int = 2,
    has_critical_severity: bool = False,
) -> TrendResult:
    """
    Calculate deterministic trend indicators with robust zero-baseline handling.
    """
    article_ids = supporting_article_ids or []
    dates = unique_dates or set()
    num_dates = len(dates)
    evidence_count = current_count
    change = current_count - previous_count

    # Confidence calculation based on evidence depth & date diversity
    if evidence_count >= 3 and num_dates >= 2:
        confidence = "HIGH"
    elif evidence_count >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Case 1: Zero activity in both periods
    if current_count == 0 and previous_count == 0:
        return TrendResult(
            metric_name=metric_name,
            current_count=0,
            previous_count=0,
            change=0,
            percentage_change=None,
            trend_status="INSUFFICIENT_DATA",
            trend_reason="No occurrences reported in current or previous period.",
            trend_score=0.0,
            evidence_count=0,
            unique_dates_count=0,
            confidence="LOW",
            supporting_article_ids=[],
        )

    # Case 2: Zero activity in current period (Declining)
    if current_count == 0 and previous_count > 0:
        return TrendResult(
            metric_name=metric_name,
            current_count=0,
            previous_count=previous_count,
            change=-previous_count,
            percentage_change=-100.0,
            trend_status="DECLINING",
            trend_reason=f"Activity ceased: 0 occurrences compared to {previous_count} in previous period.",
            trend_score=-1.0,
            evidence_count=0,
            unique_dates_count=0,
            confidence="HIGH" if previous_count >= 2 else "MEDIUM",
            supporting_article_ids=[],
        )

    # Case 3: Zero baseline in previous period (Newly Emerged or Insufficient)
    if previous_count == 0:
        if current_count >= min_evidence_threshold or (current_count >= 1 and has_critical_severity):
            trend_status = "EMERGING"
            trend_reason = (
                f"Newly emerged threat with {current_count} report(s) in current period "
                f"after 0 reported occurrences in previous window."
            )
            trend_score = 0.8
        else:
            trend_status = "INSUFFICIENT_DATA"
            trend_reason = f"Initial occurrence ({current_count}) below statistical significance threshold ({min_evidence_threshold})."
            trend_score = 0.2

        return TrendResult(
            metric_name=metric_name,
            current_count=current_count,
            previous_count=0,
            change=current_count,
            percentage_change=None,  # Do not calculate misleading division by zero
            trend_status=trend_status,
            trend_reason=trend_reason,
            trend_score=trend_score,
            evidence_count=evidence_count,
            unique_dates_count=num_dates,
            confidence=confidence,
            supporting_article_ids=article_ids,
        )

    # Case 4: Non-zero previous baseline — calculate standard percentage change
    pct_change = round(((current_count - previous_count) / previous_count) * 100.0, 1)

    # Normalized trend score between -1.0 and +1.0
    # Map percentage change: +100% -> 1.0, -100% -> -1.0
    norm_score = max(-1.0, min(1.0, pct_change / 100.0))

    if pct_change >= 50.0 and current_count >= min_evidence_threshold:
        # Rapid surge
        trend_status = "EMERGING" if previous_count <= 1 else "INCREASING"
        trend_reason = f"Surge of +{pct_change}% ({current_count} vs {previous_count} previously)."
    elif pct_change >= 20.0 and current_count >= min_evidence_threshold:
        trend_status = "INCREASING"
        trend_reason = f"Upward trend of +{pct_change}% ({current_count} vs {previous_count} previously)."
    elif pct_change <= -20.0:
        trend_status = "DECREASING"
        trend_reason = f"Downward trend of {pct_change}% ({current_count} vs {previous_count} previously)."
    else:
        trend_status = "STABLE"
        trend_reason = f"Stable reporting volume ({current_count} vs {previous_count} previously, change {pct_change}%)."

    return TrendResult(
        metric_name=metric_name,
        current_count=current_count,
        previous_count=previous_count,
        change=change,
        percentage_change=pct_change,
        trend_status=trend_status,
        trend_reason=trend_reason,
        trend_score=norm_score,
        evidence_count=evidence_count,
        unique_dates_count=num_dates,
        confidence=confidence,
        supporting_article_ids=article_ids,
    )
