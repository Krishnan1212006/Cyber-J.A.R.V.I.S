"""
Command-Line Interface for JARVIS Cybersecurity Intelligence Collector.

Examples:
    # Ingest 5 latest articles from The Hacker News
    python -m intel.collector_cli --latest --limit 5

    # Run historical ingestion between dates
    python -m intel.collector_cli --historical --start 2026-09-01 --end 2026-10-03 --limit 20

    # View database metrics & statistics
    python -m intel.collector_cli --stats

    # View recent collection runs
    python -m intel.collector_cli --runs

    # Run system diagnostic health check (doctor)
    python -m intel.collector_cli --doctor

    # Search ingested articles using Full-Text Search (FTS5)
    python -m intel.collector_cli --search "ransomware"
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
import time

# Force UTF-8 output on Windows consoles that default to CP1252/CP1250.
# Mirrors the same fix already in main.py.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .config import load_cyber_config
from .collector_service import THNCollectorService
from .db import IntelligenceDB
from .thn_provider import THNDataProvider


def setup_cli_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def run_doctor(service: THNCollectorService) -> int:
    """Run environmental and connectivity diagnostics."""
    print("\n[DOCTOR] Running JARVIS Cyber-Intel Diagnostics...")
    print("=" * 60)

    all_ok = True

    # 1. Database Check
    try:
        count = service.db.get_article_count()
        print(f"  [OK ] Database connected: {service.db.db_path} ({count:,} articles)")
    except Exception as e:
        print(f"  [ERR] Database error: {e}")
        all_ok = False

    # 2. Network & Blogger Feed Reachability Check
    try:
        t0 = time.monotonic()
        entries = service.provider.collect_latest(limit=2)
        latency = (time.monotonic() - t0) * 1000
        if entries:
            print(f"  [OK ] THN feed reachable: {len(entries)} sample entries ({latency:.0f}ms)")
        else:
            print("  [!  ] THN feed reachable but returned 0 entries")
    except Exception as e:
        print(f"  [ERR] THN feed connectivity failed: {e}")
        all_ok = False

    # 3. FTS5 Search Index Check
    try:
        _ = service.db.search_articles_fts("security", limit=1)
        print("  [OK ] SQLite FTS5 full-text search: operational")
    except Exception as e:
        print(f"  [ERR] FTS5 search error: {e}")
        all_ok = False

    print("=" * 60)
    if all_ok:
        print("All diagnostic checks passed. System is ready.\n")
        return 0
    else:
        print("Some checks failed. Review errors above.\n")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="JARVIS Cybersecurity Intelligence Data Collector (Phase 1)"
    )
    parser.add_argument("--latest", action="store_true",
                        help="Ingest latest articles from The Hacker News")
    parser.add_argument("--historical", action="store_true",
                        help="Ingest historical articles across a date range")
    parser.add_argument("--start", type=str,
                        help="Start date for historical ingestion (YYYY-MM-DD)")
    parser.add_argument("--end", type=str,
                        help="End date for historical ingestion (YYYY-MM-DD)")
    parser.add_argument("--limit", type=int, default=20,
                        help="Max articles to ingest / rows to show (default: 20)")
    parser.add_argument("--no-full-body", action="store_true",
                        help="Skip fetching full article HTML bodies")
    parser.add_argument("--no-resume", action="store_true",
                        help="Do not resume historical collection from checkpoint")
    parser.add_argument("--stats", action="store_true",
                        help="Display database and collection metrics")
    parser.add_argument("--runs", action="store_true",
                        help="Show recent collection runs")
    parser.add_argument("--search", type=str,
                        help="Full-text search query across stored articles")
    parser.add_argument("--doctor", action="store_true",
                        help="Run health check and diagnostics")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose debug logging")

    args = parser.parse_args()
    setup_cli_logging(args.verbose)

    config = load_cyber_config()
    db = IntelligenceDB(config["db_path"])
    provider = THNDataProvider(config)
    service = THNCollectorService(db=db, provider=provider, config=config)

    # ── Doctor ────────────────────────────────────────────────────────────────
    if args.doctor:
        return run_doctor(service)

    # ── Stats ─────────────────────────────────────────────────────────────────
    if args.stats:
        stats = db.get_stats()
        print("\n[STATS] JARVIS Cyber-Intel Database Metrics")
        print("=" * 54)
        print(f"  Total Articles:     {stats['total_articles']:,}")
        print(f"  Unique Authors:     {stats['unique_authors']:,}")
        print(f"  Earliest Article:   {stats['earliest_article'] or 'N/A'}")
        print(f"  Latest Article:     {stats['latest_article'] or 'N/A'}")
        print(f"  Pending Analysis:   {stats['pending_analysis']:,}")
        print(f"  Total Runs Logged:  {stats['total_runs']:,}")
        print(f"  Database Size:      {stats['db_size_bytes'] / (1024 * 1024):.2f} MB")
        print(f"  Database Path:      {db.db_path}")
        print("=" * 54 + "\n")
        return 0

    # ── Runs ──────────────────────────────────────────────────────────────────
    if args.runs:
        runs = db.get_latest_runs(limit=args.limit or 10)
        print("\n[RUNS] Recent Collection Runs")
        print("=" * 90)
        for r in runs:
            print(
                f"  [{r.run_id}] {r.started_at} | Mode: {r.mode:<10} | Status: {r.status:<9} | "
                f"Found: {r.discovered_count:>4} | New: {r.new_count:>4} | "
                f"Dup: {r.duplicate_count:>4} | Fail: {r.failed_count:>4}"
            )
        print("=" * 90 + "\n")
        return 0

    # ── Search ────────────────────────────────────────────────────────────────
    if args.search:
        results = db.search_articles_fts(args.search, limit=args.limit or 10)
        print(f"\n[SEARCH] Results for '{args.search}' ({len(results)} matches):")
        print("=" * 70)
        for i, art in enumerate(results, 1):
            print(f"  {i:>2}. [{art.published_at[:10]}] {art.title}")
            print(f"      URL: {art.url}")
            if art.summary:
                print(f"      Summary: {art.summary[:140]}...")
            print()
        print("=" * 70 + "\n")
        return 0

    # ── Latest ────────────────────────────────────────────────────────────────
    if args.latest:
        print(f"\n[COLLECT] Running Latest Collection (limit={args.limit})...")
        stats = service.collect_latest(
            limit=args.limit,
            fetch_full_body=not args.no_full_body,
        )
        print("\n[DONE] Collection Completed:")
        print(json.dumps(stats, indent=2))
        return 0

    # ── Historical ────────────────────────────────────────────────────────────
    if args.historical:
        if not args.start or not args.end:
            print("Error: --historical requires both --start YYYY-MM-DD and --end YYYY-MM-DD")
            return 1
        print(
            f"\n[COLLECT] Historical Collection | {args.start} to {args.end} | "
            f"max={args.limit} | resume={not args.no_resume}"
        )
        stats = service.collect_historical(
            start_date=args.start,
            end_date=args.end,
            max_articles=args.limit,
            resume=not args.no_resume,
            fetch_full_body=not args.no_full_body,
        )
        print("\n[DONE] Historical Collection Completed:")
        print(json.dumps(stats, indent=2))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
