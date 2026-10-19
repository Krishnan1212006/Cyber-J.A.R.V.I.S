"""
Command-Line Interface for JARVIS Cybersecurity Intelligence & Trend Analysis (Phase 3).

Examples:
    # High-level threat overview & risk score for the last 7 days
    python -m intel.intelligence_cli --overview --window 7d

    # Trending threats (surges, accelerations) over 30 days
    python -m intel.intelligence_cli --trends --window 30d

    # Newly emerging threats
    python -m intel.intelligence_cli --emerging

    # Top CVEs and active exploitation status
    python -m intel.intelligence_cli --cves

    # Threat actors, targeted sectors, and malware relationships
    python -m intel.intelligence_cli --correlations

    # Complete intelligence executive report
    python -m intel.intelligence_cli --report
"""

from __future__ import annotations
import argparse
import json
import sys

# Windows console UTF-8 safety
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from .intelligence_engine import CybersecurityIntelligenceEngine, get_intelligence_engine


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JARVIS Cybersecurity Intelligence & Trend Engine (Phase 3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--overview", action="store_true", help="Display threat overview and risk score")
    parser.add_argument("--trends", action="store_true", help="Display trending threats")
    parser.add_argument("--emerging", action="store_true", help="Display newly emerging threats")
    parser.add_argument("--cves", action="store_true", help="Display CVE intelligence and exploitation status")
    parser.add_argument("--malware", action="store_true", help="Display top malware/ransomware families")
    parser.add_argument("--actors", action="store_true", help="Display top threat actors and targeted sectors")
    parser.add_argument("--mitre", action="store_true", help="Display MITRE ATT&CK technique trends")
    parser.add_argument("--sectors", action="store_true", help="Display targeted industry sector trends")
    parser.add_argument("--risk", action="store_true", help="Display JARVIS Intelligence Risk Score details")
    parser.add_argument("--correlations", action="store_true", help="Display threat entity relationships")
    parser.add_argument("--timeline", action="store_true", help="Display chronological threat timeline")
    parser.add_argument("--snapshot", action="store_true", help="Compute and persist trend snapshot to DB")
    parser.add_argument("--report", action="store_true", help="Generate full cybersecurity intelligence report")
    parser.add_argument("--freshness", action="store_true", help="Check data freshness timestamps")
    parser.add_argument("--connectors", action="store_true", help="Display health and telemetry status of all connectors")
    parser.add_argument("--explain", type=str, metavar="ARTICLE_ID", help="Explain an article with structured cybersecurity curriculum")
    parser.add_argument("--level", type=str, default="intermediate", choices=["beginner", "intermediate", "advanced"], help="Learning level for explanations")
    parser.add_argument("--owasp", type=str, metavar="ARTICLE_ID", help="Evaluate web security relevance and OWASP Top 10:2025 mappings")
    parser.add_argument("--attack-map", type=str, metavar="ARTICLE_ID", help="Map article claims to official MITRE ATT&CK techniques")
    parser.add_argument("--learning", type=str, metavar="ARTICLE_ID", help="Recommend personalized defensive learning path and safe lab simulations")
    parser.add_argument("--vectra-status", action="store_true", help="Check Vectra AI platform deployment status")
    parser.add_argument("--window", type=str, default="7d", help="Analysis time window: 24h, 7d, 30d, 90d, all (default: 7d)")
    parser.add_argument("--limit", type=int, default=10, help="Output limit (default: 10)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    args = parser.parse_args()
    engine = get_intelligence_engine()

    # 1. Full Report
    if args.report:
        report = engine.generate_intelligence_report(time_window=args.window)
        if args.json:
            print(json.dumps(report, indent=2))
            return

        print("\n" + "=" * 70)
        print("          JARVIS CYBERSECURITY THREAT INTELLIGENCE REPORT")
        print("=" * 70)
        p = report["period"]
        print(f"  Analysis Window:   {p['window']} ({p['start'][:10]} to {p['end'][:10]})")
        ov = report["overview"]
        print(f"  Total Articles:    {ov['total_articles']} (Volume Change: {ov['volume_change']} / {ov['volume_percentage_change']}%)")
        print(f"  Severity Profile:  CRITICAL: {ov['critical']} | HIGH: {ov['high']} | MEDIUM: {ov['medium']} | LOW: {ov['low']} | INFO: {ov['info']}")

        risk = report["risk_overview"]
        print(f"\n  [RISK LEVEL] {risk['category']} (Score: {risk['score']}/100)")
        print("  Key Risk Drivers:")
        for r in risk["reasons"]:
            print(f"    * {r}")

        print("\n  Top CVE Disclosures:")
        if report["top_cves"]:
            for c in report["top_cves"]:
                prods = ", ".join(c["affected_products"][:2]) or "General"
                print(f"    - {c['cve_id']:<16} ({c['article_count']} reports) [{c['exploitation_status']}] - {prods}")
        else:
            print("    - None reported in window.")

        print("\n  Top Threat Actors:")
        if report["top_threat_actors"]:
            for a in report["top_threat_actors"]:
                mal = ", ".join(a["associated_malware"][:2]) or "None specified"
                print(f"    - {a['actor_name']:<25} ({a['article_count']} reports) Malware: {mal}")
        else:
            print("    - None reported in window.")

        print("\n  Targeted Sectors:")
        if report["top_sectors"]:
            for s in report["top_sectors"]:
                print(f"    - {s['sector']:<25} ({s['article_count']} reports) Trend: {s['trend_status']}")
        else:
            print("    - None reported in window.")

        fresh = report["data_freshness"]
        print(f"\n  Data Freshness:    {fresh['last_analysis_time'] or 'N/A'}")
        print("=" * 70 + "\n")
        return

    # 2. Freshness
    if args.freshness:
        f = engine.get_data_freshness()
        print("\n[FRESHNESS] JARVIS Cyber Intelligence Status")
        print("=" * 55)
        print(f"  Latest Ingestion:         {f['last_ingestion_time'] or 'Never'}")
        print(f"  Latest Analysis:          {f['last_analysis_time'] or 'Never'}")
        print(f"  Latest Trend Snapshot:    {f['last_trend_calculation_time'] or 'Never'}")
        print(f"  Pipeline Status:          {'UP TO DATE' if f['is_fresh'] else 'PENDING SYNC'}")
        print("=" * 55)
        return

    # 3. Overview
    if args.overview:
        ov = engine.get_threat_overview(time_window=args.window)
        if args.json:
            print(json.dumps(ov, indent=2))
            return
        print(f"\n[OVERVIEW] Threat Landscape ({args.window})")
        print("=" * 55)
        o = ov["overview"]
        print(f"  Total Disclosures:   {o['total_articles']}")
        print(f"  Trend Velocity:      {o['volume_trend_status']} ({o['volume_change']:+d} articles)")
        print(f"  Severity Breakdown:  CRITICAL: {o['critical']} | HIGH: {o['high']} | MED: {o['medium']}")
        ro = ov["risk_overview"]
        print(f"  Risk Evaluation:     [{ro['category']}] Score: {ro['score']}/100")
        for r in ro["reasons"]:
            print(f"    - {r}")
        print("=" * 55)
        return

    # 4. Risk Details
    if args.risk:
        ov = engine.get_threat_overview(time_window=args.window)
        ro = ov["risk_overview"]
        if args.json:
            print(json.dumps(ro, indent=2))
            return
        print(f"\n[RISK SCORE] JARVIS Intelligence Risk Model ({args.window})")
        print("=" * 55)
        print(f"  Score:      {ro['score']} / 100")
        print(f"  Category:   {ro['category']}")
        print("  Factor Weight Contribution:")
        for factor, weight in ro["factor_breakdown"].items():
            print(f"    - {factor:<20}: {weight:>5.1f} pts")
        print("  Justifications:")
        for reason in ro["reasons"]:
            print(f"    * {reason}")
        print("=" * 55)
        return

    # 5. Trends & Accelerations
    if args.trends:
        trends = engine.get_trending_threats(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(trends, indent=2))
            return
        print(f"\n[TRENDS] Top Threat Trends ({args.window})")
        print("=" * 60)
        for t in trends:
            chg = f"{t['percentage_change']:+.1f}%" if t['percentage_change'] is not None else "NEW"
            print(f"  [{t['trend_status']:<11}] {t['metric_name']:<25} Count: {t['current_count']} ({chg})")
            print(f"      Reason: {t['trend_reason']}")
        print("=" * 60)
        return

    # 6. Emerging Threats
    if args.emerging:
        emerging = engine.get_emerging_threats(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(emerging, indent=2))
            return
        print(f"\n[EMERGING] Newly Observed Threats ({args.window})")
        print("=" * 60)
        if not emerging:
            print("  No newly emerging anomalies detected in this window.")
        for e in emerging:
            print(f"  * {e['metric_name']} (Current: {e['current_count']}, Previously: {e['previous_count']})")
            print(f"    {e['trend_reason']}")
        print("=" * 60)
        return

    # 7. CVEs
    if args.cves:
        cves = engine.get_top_cves(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(cves, indent=2))
            return
        print(f"\n[CVE INTELLIGENCE] Top Reported Vulnerabilities ({args.window})")
        print("=" * 65)
        for c in cves:
            cvss = c["cvss"].get("score", "N/A") if c["cvss"] else "N/A"
            prods = ", ".join(c["affected_products"][:2]) or "Not specified"
            print(f"  {c['cve_id']:<16} CVSS: {cvss:<5} [{c['exploitation_status']:<18}] Reports: {c['article_count']}")
            print(f"      Products: {prods}")
        print("=" * 65)
        return

    # 8. Malware
    if args.malware:
        malware = engine.get_top_malware(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(malware, indent=2))
            return
        print(f"\n[MALWARE] Top Malware & Ransomware Families ({args.window})")
        print("=" * 60)
        for m in malware:
            print(f"  {m['malware_name']:<22} [{m['type']:<10}] Reports: {m['article_count']} Trend: {m['trend_status']}")
        print("=" * 60)
        return

    # 9. Actors
    if args.actors:
        actors = engine.get_top_threat_actors(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(actors, indent=2))
            return
        print(f"\n[THREAT ACTORS] Active Threat Groups ({args.window})")
        print("=" * 60)
        for a in actors:
            mal = ", ".join(a["associated_malware"][:2]) or "None"
            print(f"  {a['actor_name']:<25} Reports: {a['article_count']:<3} Malware: {mal}")
        print("=" * 60)
        return

    # 10. MITRE
    if args.mitre:
        mitre = engine.get_mitre_trends(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(mitre, indent=2))
            return
        print(f"\n[MITRE ATT&CK] Technique Frequency & Trends ({args.window})")
        print("=" * 60)
        for m in mitre:
            print(f"  [{m['technique_id']}] {m['technique_name']:<35} Reports: {m['article_count']} ({m['trend_status']})")
        print("=" * 60)
        return

    # 11. Sectors
    if args.sectors:
        sectors = engine.get_sector_trends(time_window=args.window, limit=args.limit)
        if args.json:
            print(json.dumps(sectors, indent=2))
            return
        print(f"\n[TARGET SECTORS] Targeted Industries ({args.window})")
        print("=" * 60)
        for s in sectors:
            print(f"  {s['sector']:<25} Reports: {s['article_count']:<3} Trend: {s['trend_status']}")
        print("=" * 60)
        return

    # 12. Correlations
    if args.correlations:
        corr = engine.get_threat_correlations(time_window=args.window)
        if args.json:
            print(json.dumps(corr, indent=2))
            return
        print(f"\n[THREAT CORRELATIONS] Entity Relationships ({args.window})")
        print("=" * 65)
        print("  Direct Factual Associations:")
        for r in corr["direct_relationships"]:
            print(f"    - ({r['source_type']}) {r['source_name']} ==[{r['relationship']}]==> ({r['target_type']}) {r['target_name']}")

        if corr["cross_article_correlations"]:
            print("\n  Cross-Article Multi-Hop Correlations:")
            for c in corr["cross_article_correlations"]:
                print(f"    * Threat Actor '{c['threat_actor']}' -> Malware '{c['malware']}' -> Techniques: {c['correlated_techniques']}")
        print("=" * 65)
        return

    # 13. Snapshot
    if args.snapshot:
        snaps = engine.generate_snapshot(time_window=args.window)
        print(f"[SUCCESS] Generated and saved {len(snaps)} trend snapshot records into database.")
        for s in snaps:
            print(f"  - [{s.metric_type}] {s.metric_name}: {s.value} (Trend: {s.trend_status}, Risk: {s.risk_score})")
        return

    # 14. Connector Health Status
    if args.connectors:
        from .scheduler import ConnectorScheduler
        scheduler = ConnectorScheduler(db=engine.db)
        health = scheduler.get_all_health()
        if args.json:
            print(json.dumps(health, indent=2))
            return
        print(f"\n[CONNECTORS HEALTH] Intelligence Pipeline Connectors")
        print("=" * 70)
        for c in health:
            status_badge = f"[{c['status']}]"
            print(f"  {c['connector_name']:<35} {status_badge:<16} Freshness: {c.get('data_freshness') or 'N/A'}")
            if c.get("last_error"):
                print(f"      Notice: {c['last_error']}")
        print("=" * 70)
        return

    # 15. Explain Article
    if args.explain:
        from .learning_service import CybersecurityLearningService
        service = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        explanation = service.explain_thn_article(article_id=args.explain, learning_level=args.level)
        if args.json:
            print(json.dumps(explanation, indent=2))
            return
        if "error" in explanation:
            print(f"[ERROR] {explanation['error']}")
            return
        print(f"\n[DEFENSIVE LEARNING] {explanation['title']}")
        print(f"Level: {explanation['learning_level'].upper()} | Published: {explanation['published_at']}")
        print("=" * 70)
        print("\n--- PREREQUISITES ---")
        for p in explanation["prerequisites"]:
            print(f"  * {p}")
        print("\n--- ATTACK CONCEPT ---")
        print(f"  {explanation['attack_concept']}")
        print("\n--- SUPPORTING EVIDENCE ---")
        print(f"  \"{explanation['supporting_evidence'][:250]}...\"")
        print("\n--- DEFENSIVE DETECTION ---")
        print(f"  {explanation['defensive_detection']}")
        print("\n--- RECOMMENDED MITIGATION ---")
        for m in explanation["mitigation"]:
            print(f"  [+] {m}")
        print("\n--- KNOWLEDGE-CHECK QUESTION ---")
        q = explanation["knowledge_check"]
        print(f"  {q['question']}")
        for opt in q["options"]:
            print(f"    {opt}")
        print(f"\n  Correct Answer: {q['correct_option']}")
        print(f"  Explanation: {q['explanation']}")
        print("=" * 70)
        return

    # 16. OWASP Top 10 Evaluation
    if args.owasp:
        from .learning_service import CybersecurityLearningService
        service = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        res = service.explain_owasp_relevance(article_id=args.owasp)
        if args.json:
            print(json.dumps(res, indent=2))
            return
        if "error" in res:
            print(f"[ERROR] {res['error']}")
            return
        print(f"\n[OWASP TOP 10:2025 EVALUATION] {res['title']}")
        print("=" * 70)
        print(f"  Web Security Related: {'YES' if res['is_web_security_related'] else 'NO'}")
        print(f"  Assessment:           {res['evaluation_reason']}")
        if res["owasp_categories_mapped"]:
            print("\n  Mapped Categories:")
            for m in res["owasp_categories_mapped"]:
                print(f"    - [{m['framework_item_id']}] {m['framework_item_name']} ({m['mapping_method']})")
                print(f"      Evidence: \"{m['evidence_text'][:120]}...\"")
        print("=" * 70)
        return

    # 17. MITRE ATT&CK Mapping
    if args.attack_map:
        from .learning_service import CybersecurityLearningService
        service = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        res = service.map_article_to_attack_framework(article_id=args.attack_map)
        if args.json:
            print(json.dumps(res, indent=2))
            return
        if "error" in res:
            print(f"[ERROR] {res['error']}")
            return
        print(f"\n[MITRE ATT&CK ENTERPRISE MAPPINGS] {res['title']}")
        print("=" * 70)
        for m in res["mappings"]:
            tactic = m.get("metadata", {}).get("tactic_name", "General")
            print(f"  [{m['framework_item_id']}] {m['framework_item_name']:<35} ({tactic}) [{m['mapping_method']}]")
            print(f"      Evidence: \"{m['evidence_text'][:120]}...\"")
        print("=" * 70)
        return

    # 18. Learning Recommendations
    if args.learning:
        from .learning_service import CybersecurityLearningService
        service = CybersecurityLearningService(db=engine.db, intelligence_engine=engine)
        res = service.recommend_defensive_learning(article_id=args.learning)
        if args.json:
            print(json.dumps(res, indent=2))
            return
        if "error" in res:
            print(f"[ERROR] {res['error']}")
            return
        print(f"\n[RECOMMENDED DEFENSIVE LABS] {res['title']}")
        print("=" * 70)
        print(f"  Target User Level: {res['user_level'].upper()}")
        print("\n  Safe Simulation Labs:")
        for lab in res["safe_lab_exercises"]:
            print(f"    * {lab['topic']}: {lab['exercise']}")
        print(f"\n  [SAFETY NOTICE] {res['ethical_guidance']}")
        print("=" * 70)
        return

    # 19. Vectra Status
    if args.vectra_status:
        from .vectra_provider import VectraProvider
        provider = VectraProvider()
        st = provider.get_status()
        if args.json:
            print(json.dumps(st, indent=2))
            return
        print(f"\n[VECTRA AI PLATFORM STATUS]")
        print("=" * 60)
        print(f"  Status:       [{st['status']}]")
        print(f"  Available:    {st['available']}")
        print(f"  API Version:  {st['api_version']}")
        print(f"  Message:      {st['message']}")
        print("=" * 60)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
