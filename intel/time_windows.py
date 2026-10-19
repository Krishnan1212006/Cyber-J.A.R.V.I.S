"""
Time window parsing and temporal comparison utilities for JARVIS Cybersecurity Intelligence.
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Optional


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def parse_iso(ts_str: str) -> datetime:
    """Parse ISO 8601 UTC timestamp string into timezone-aware datetime."""
    clean = ts_str.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def format_iso(dt: datetime) -> str:
    """Format datetime as standard ISO 8601 UTC string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_time_window(
    window: str = "7d",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    ref_time: Optional[datetime] = None,
) -> tuple[datetime, datetime]:
    """
    Resolve start and end datetimes for an analysis window.
    Supports preset codes ('24h', '7d', '30d', '90d', '6m', '1y', 'all') or custom ISO date strings.
    """
    now = ref_time or utc_now()

    if start_date and end_date:
        s_dt = parse_iso(start_date)
        e_dt = parse_iso(end_date)
        if s_dt > e_dt:
            s_dt, e_dt = e_dt, s_dt
        return s_dt, e_dt

    win_lower = window.strip().lower()
    if win_lower in ("24h", "1d"):
        return now - timedelta(days=1), now
    elif win_lower == "7d":
        return now - timedelta(days=7), now
    elif win_lower == "30d":
        return now - timedelta(days=30), now
    elif win_lower == "90d":
        return now - timedelta(days=90), now
    elif win_lower in ("6m", "180d"):
        return now - timedelta(days=180), now
    elif win_lower in ("1y", "365d"):
        return now - timedelta(days=365), now
    elif win_lower == "all":
        return datetime(2000, 1, 1, tzinfo=timezone.utc), now
    else:
        # Default fallback to 7 days
        return now - timedelta(days=7), now


def get_previous_period(start_dt: datetime, end_dt: datetime) -> tuple[datetime, datetime]:
    """
    Calculate the previous comparative period of identical duration immediately preceding start_dt.
    """
    duration = end_dt - start_dt
    prev_end = start_dt
    prev_start = start_dt - duration
    return prev_start, prev_end
