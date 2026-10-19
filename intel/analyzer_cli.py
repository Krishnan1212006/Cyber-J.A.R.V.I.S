"""
Command-Line Interface for JARVIS Cybersecurity Threat Intelligence Analyzer.

Examples:
    # Analyze pending unprocessed articles (batch of 5)
    python -m intel.analyzer_cli --pending --limit 5

    # Analyze or re-analyze a specific article by ID
    python -m intel.analyzer_cli --article thn_4229660375357553012 --force

    # Display structured intelligence analysis for an article
    python -m intel.analyzer_cli --show thn_4229660375357553012

    # View intelligence metrics and threat breakdown
    python -m intel.analyzer_cli --metrics
"""

from __future__ import annotations
import argparse
import json
import sys

# Ensure UTF-8 stdout for Windows console compatibility
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from .analyzer_service import CybersecurityAnalyzer
from .config import load_cyber_config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JARVIS Cybersecurity Intelligence Analyzer (Phase 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pending", action="store_true", help="Analyze batch of pending articles")
    parser.add_argument("--limit", type=int, default=10, help="Batch size limit (default: 10)")
    parser.add_argument("--article", type=str, help="Analyze single article by ID")
    parser.add_argument("--show", type=str, help="Display structured analysis for article ID")
    parser.add_argument("--force", action="store_true", help="Force re-analysis even if already completed")
    parser.add_argument("--version", type=str, default="v1", help="Analysis schema version (default: v1)")
    parser.add_argument("--metrics", action="store_true", help="Display overall intelligence metrics")
    parser.add_argument("--provider", type=str, help="Override LLM provider (gemini, ollama, openai, mock)")
    parser.add_argument("--model", type=str, help="Override LLM model name")

    args = parser.parse_args()

    cfg = load_cyber_config()
    if args.provider:
        cfg["llm_provider"] = args.provider
    if args.model:
        cfg["llm_model"] = args.model

    analyzer = CybersecurityAnalyzer(config=cfg)

    # 1. Metrics
    if args.metrics:
        metrics = analyzer.get_intelligence_metrics()
        stats = analyzer.db.get_stats()
        print("\n[METRICS] JARVIS Cybersecurity Intelligence Overview")
        print("=" * 60)
        print(f"  Total Articles in DB:      {stats.get('total_articles', 0)}")
        print(f"  Articles Analyzed:         {metrics.get('total_analyzed', 0)}")
        print(f"  Pending Analysis:          {stats.get('pending_analysis', 0)}")
        print(f"  Distinct CVEs Identified:  {metrics.get('distinct_cve_count', 0)}")
        print(f"  Top CVEs:                  {', '.join(metrics.get('top_cves', [])) or 'None'}")
        print("\n  Severity Distribution:")
        for sev, count in metrics.get("severity_distribution", {}).items():
            print(f"    - {sev:<10}: {count}")

        print("\n  Top Threat Actors:")
        for actor, cnt in metrics.get("top_threat_actors", {}).items():
            print(f"    - {actor:<25}: {cnt}")

        print("\n  Top Malware Families:")
        for mal, cnt in metrics.get("top_malware_families", {}).items():
            print(f"    - {mal:<25}: {cnt}")

        print("\n  Top Target Sectors:")
        for sec, cnt in metrics.get("top_target_sectors", {}).items():
            print(f"    - {sec:<25}: {cnt}")
        print("=" * 60)
        return

    # 2. Show analysis
    if args.show:
        analysis = analyzer.get_article_analysis(args.show, version=args.version)
        if not analysis:
            print(f"[ERROR] No analysis found for article {args.show} (version {args.version})")
            sys.exit(1)

        print("\n[ANALYSIS] Structured Cybersecurity Intelligence")
        print("=" * 60)
        print(f"  Article ID:     {analysis.article_id}")
        print(f"  Title:          {analysis.title}")
        print(f"  Published:      {analysis.published_at}")
        print(f"  URL:            {analysis.url}")
        print(f"  Severity:       [{analysis.severity}] - {analysis.severity_reason}")
        print(f"  Confidence:     {analysis.confidence}")
        print(f"  Model/Version:  {analysis.analysis_model} ({analysis.analysis_version})")
        print("\n  Executive Summary:")
        print(f"  {analysis.summary}")
        print("\n  Threat Information:")
        print(f"    Threat Types:     {', '.join(analysis.threat_types) or 'None'}")
        print(f"    Attack Types:     {', '.join(analysis.attack_types) or 'None'}")
        print(f"    Attack Vectors:   {', '.join(analysis.attack_vectors) or 'None'}")
        print(f"    Threat Actors:    {', '.join(analysis.threat_actors) or 'None'}")
        print(f"    Malware/Ransom:   {', '.join(analysis.malware + analysis.ransomware) or 'None'}")
        print(f"    CVEs:             {', '.join(analysis.cves) or 'None'}")
        print(f"    CVSS:             {json.dumps(analysis.cvss) if analysis.cvss else 'Not reported'}")
        print(f"    Affected Products:{', '.join(analysis.affected_products) or 'None'}")
        print(f"    Target Sectors:   {', '.join(analysis.target_sectors) or 'None'}")
        print(f"    Target Countries: {', '.join(analysis.target_countries) or 'None'}")

        if analysis.mitre_attack:
            print("\n  MITRE ATT&CK Techniques:")
            for m in analysis.mitre_attack:
                print(f"    - [{m.get('technique_id')}] {m.get('technique_name')}: {m.get('evidence', '')}")

        if analysis.iocs:
            print("\n  Indicators of Compromise (IOCs):")
            for ioc in analysis.iocs:
                print(f"    - [{ioc.get('type')}] {ioc.get('value')} ({ioc.get('context', '')})")

        print("\n  Defensive Guidance:")
        print(f"    Mitigation:       {'; '.join(analysis.mitigation) or 'None'}")
        print(f"    Remediation:      {'; '.join(analysis.remediation) or 'None'}")
        print(f"    Recommendations:  {'; '.join(analysis.security_recommendations) or 'None'}")
        print("=" * 60)
        return

    # 3. Analyze single article
    if args.article:
        print(f"[START] Analyzing article {args.article} (version {args.version})...")
        try:
            analysis = analyzer.analyze_article(
                args.article,
                force_reprocess=args.force,
                version=args.version,
            )
            print(f"[SUCCESS] Analysis completed for {analysis.article_id}")
            print(f"  Severity:   [{analysis.severity}]")
            print(f"  CVEs:       {', '.join(analysis.cves) or 'None'}")
            print(f"  Actors:     {', '.join(analysis.threat_actors) or 'None'}")
            print(f"  Summary:    {analysis.summary[:150]}...")
        except Exception as e:
            print(f"[ERROR] Failed to analyze article {args.article}: {e}")
            sys.exit(1)
        return

    # 4. Batch analyze pending articles
    if args.pending:
        print(f"[START] Processing batch of pending articles (limit: {args.limit}, version: {args.version})...")
        results = analyzer.analyze_pending_articles(limit=args.limit, version=args.version)
        print("\n[RESULT] Batch Analysis Complete:")
        print(f"  Pending Found:   {results['found_pending']}")
        print(f"  Processed:       {results['processed']}")
        print(f"  Succeeded:       {results['succeeded']}")
        print(f"  Failed:          {results['failed']}")

        for item in results["analyses"]:
            print(f"  - [{item['severity']}] {item['article_id']}: {item['title'][:50]}... (CVEs: {item['cves']})")

        if results["errors"]:
            print("\n[ERRORS]")
            for aid, err in results["errors"].items():
                print(f"  - {aid}: {err}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
