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
from .collector_service import CyberNewsCollector, THNCollectorService
from .db import IntelligenceDB
from .models import ALL_CYBER_SOURCES
from .thn_provider import THNDataProvider


def setup_cli_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def run_doctor(collector: CyberNewsCollector) -> int:
    """Run environmental and connectivity diagnostics across all 4 sources."""
    print("\n[DOCTOR] Running JARVIS Cyber-Intel Diagnostics...")
    print("=" * 65)

    all_ok = True

    # 1. Database Check
    try:
        count = collector.db.get_article_count()
        print(f"  [OK ] Database connected: {collector.db.db_path} ({count:,} articles)")
    except Exception as e:
        print(f"  [ERR] Database error: {e}")
        all_ok = False

    # 2. Network & Feed Reachability Check for all 4 sources
    for src, provider in collector.connectors.items():
        try:
            t0 = time.monotonic()
            entries = provider.collect_latest(limit=2)
            latency = (time.monotonic() - t0) * 1000
            if entries:
                print(f"  [OK ] {src:<18} reachable: {len(entries)} sample entries ({latency:.0f}ms)")
            else:
                print(f"  [!  ] {src:<18} reachable but returned 0 entries")
        except Exception as e:
            print(f"  [ERR] {src:<18} connectivity failed: {e}")
            all_ok = False

    # 3. FTS5 Search Index Check
    try:
        _ = collector.db.search_articles_fts("security", limit=1)
        print("  [OK ] SQLite FTS5 full-text search: operational")
    except Exception as e:
        print(f"  [ERR] FTS5 search error: {e}")
        all_ok = False

    print("=" * 65)
    if all_ok:
        print("All diagnostic checks passed. System is ready.\n")
        return 0
    else:
        print("Some checks failed. Review errors above.\n")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="JARVIS Cybersecurity Intelligence Multi-Source Data Collector"
    )
    parser.add_argument("--latest", action="store_true",
                        help="Ingest latest articles from cybersecurity news sources")
    parser.add_argument("--historical", action="store_true",
                        help="Ingest historical articles across a date range")
    parser.add_argument("--source", type=str, default="all",
                        choices=["all"] + list(ALL_CYBER_SOURCES),
                        help="Source to collect from (default: all)")
    parser.add_argument("--start", type=str,
                        help="Start date for historical ingestion (YYYY-MM-DD)")
    parser.add_argument("--end", type=str,
                        help="End date for historical ingestion (YYYY-MM-DD)")
    parser.add_argument("--limit", type=int, default=20,
                        help="Max articles per source to ingest / rows to show (default: 20)")
    parser.add_argument("--no-full-body", action="store_true",
                        help="Skip fetching full article HTML bodies")
    parser.add_argument("--no-resume", action="store_true",
                        help="Do not resume historical collection from checkpoint")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Retry collection for sources in ERROR/DEGRADED status")
    parser.add_argument("--health", action="store_true",
                        help="Show per-source connector health status")
    parser.add_argument("--stats", action="store_true",
                        help="Display database and collection metrics")
    parser.add_argument("--runs", action="store_true",
                        help="Show recent collection runs")
    parser.add_argument("--search", type=str,
                        help="Full-text search query across stored articles")
    parser.add_argument("--doctor", action="store_true",
                        help="Run health check and diagnostics across all 4 sources")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose debug logging")

    args = parser.parse_args()
    setup_cli_logging(args.verbose)

    config = load_cyber_config()
    db = IntelligenceDB(config["db_path"])
    collector = CyberNewsCollector(db=db, config=config)

    # ── Doctor ────────────────────────────────────────────────────────────────
    if args.doctor:
        return run_doctor(collector)

    # ── Health ────────────────────────────────────────────────────────────────
    if args.health:
        statuses = collector.get_source_health()
        print("\n[HEALTH] Per-Source Connector Health")
        print("=" * 80)
        for h in statuses:
            print(
                f"  {h.connector_id:<28} | Status: {h.status:<12} | "
                f"Processed: {h.records_processed:>5} | Last Run: {h.last_run_at or 'N/A'}"
            )
            if h.last_error:
                print(f"    Error: {h.last_error}")
        print("=" * 80 + "\n")
        return 0

    # ── Retry Failed ──────────────────────────────────────────────────────────
    if args.retry_failed:
        res = collector.retry_failed_jobs()
        print("\n[RETRY] Retry Failed Collection Jobs:")
        print(json.dumps(res, indent=2))
        return 0

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
        print("=" * 105)
        for r in runs:
            print(
                f"  [{r.run_id}] {r.started_at} | Src: {r.source:<18} | Mode: {r.mode:<10} | Status: {r.status:<9} | "
                f"Found: {r.discovered_count:>3} | New: {r.new_count:>3} | "
                f"Dup: {r.duplicate_count:>3} | Fail: {r.failed_count:>3}"
            )
        print("=" * 105 + "\n")
        return 0

    # ── Search ────────────────────────────────────────────────────────────────
    if args.search:
        src_filter = None if args.source == "all" else args.source
        results = db.search_articles_fts(args.search, limit=args.limit or 10, source=src_filter)
        print(f"\n[SEARCH] Results for '{args.search}' ({len(results)} matches):")
        print("=" * 70)
        for i, art in enumerate(results, 1):
            print(f"  {i:>2}. [{art.source}] [{art.published_at[:10]}] {art.title}")
            print(f"      URL: {art.url}")
            if art.summary:
                print(f"      Summary: {art.summary[:140]}...")
            print()
        print("=" * 70 + "\n")
        return 0

    # ── Latest ────────────────────────────────────────────────────────────────
    if args.latest:
        print(f"\n[COLLECT] Running Latest Collection (source={args.source}, limit={args.limit})...")
        stats = collector.collect_latest(
            source=args.source,
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
            f"\n[COLLECT] Historical Collection | source={args.source} | {args.start} to {args.end} | "
            f"max={args.limit} | resume={not args.no_resume}"
        )
        stats = collector.collect_historical(
            start_date=args.start,
            end_date=args.end,
            source=args.source,
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
