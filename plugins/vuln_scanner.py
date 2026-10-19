"""
Vulnerability & Penetration Testing Scanner Plugin for JARVIS.
Integrates Nmap, Nikto, Wapiti, SQLMap, Gobuster, Wappalyzer, and HTTP security headers.
Features SSRF protection, secret redaction, OWASP Top 10 mapping, Tri-Level classification,
and automatic ReportLab PDF report generation.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from plugins._sec_engine import (
    ScannerRuntime,
    SSRFProtectionError,
    audit_http_headers,
    compute_risk_score,
    generate_audit_pdf,
    map_to_owasp,
    redact_text,
    validate_target_safety,
    SECURITY_REPORTS_DIR,
)
from intel.mitre_navigator import AttackNavigatorEngine

logger = logging.getLogger("jarvis.vuln_scanner")

PLUGIN = {
    "name": "vuln_scanner",
    "description": (
        "Run authorized cybersecurity vulnerability scans and security audits against target IPs, "
        "domains, or URLs using Nmap, Nikto, Wapiti, SQLMap, Gobuster, Wappalyzer, or HTTP defense headers. "
        "Correlates findings into OWASP Top 10, calculates risk score (0-100), and outputs PDF reports. "
        "Use when the user asks to scan a target, check vulnerabilities, audit ports, or test web security."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "target": {
                "type": "STRING",
                "description": "The target domain, URL, or IP address to assess (e.g., '192.168.1.1', 'http://target.local', 'scanme.nmap.org').",
            },
            "scan_type": {
                "type": "STRING",
                "description": (
                    "Type of assessment: 'quick' (headers + wappalyzer), 'network' (nmap port/service discovery), "
                    "'web_server' (nikto config audit), 'web_app' (wapiti vulnerability audit), "
                    "'sqli' (sqlmap database injection test), 'dirs' (gobuster directory brute-force), "
                    "or 'unified' (combined multi-engine scan). Defaults to 'quick'."
                ),
            },
            "authorized": {
                "type": "BOOLEAN",
                "description": "Explicit confirmation that the user owns or is authorized to assess this target.",
            },
            "generate_report": {
                "type": "BOOLEAN",
                "description": "Whether to generate a styled executive PDF and JSON audit report (default: True).",
            },
        },
        "required": ["target"],
    },
}


def _run_nmap_scan(runtime: ScannerRuntime, target_ip_or_host: str) -> dict[str, Any]:
    """Runs fast top ports scan with service version detection."""
    # -sV: service versions, -T4: aggressive timing, -F: fast top 100 ports
    cmd = ["nmap", "-sV", "-T4", "-F", "--open", target_ip_or_host]
    res = runtime.execute_command(cmd, timeout=90.0)
    stdout = res["stdout"]

    open_ports = []
    findings = []

    port_line_re = re.compile(r"^(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
    for m in port_line_re.finditer(stdout):
        port_proto, service, version = m.group(1), m.group(2), m.group(3).strip()
        open_ports.append({"port": port_proto, "service": service, "version": version})

        # Heuristic checks on dangerous / cleartext ports
        port_num = int(port_proto.split("/")[0])
        if port_num in (21, 23):  # FTP or Telnet
            findings.append({
                "title": f"Cleartext Service Port Exposed: {port_proto} ({service})",
                "severity": "medium",
                "verification": "confirmed",
                "category": "A02 - Cryptographic Failures",
                "remediation": f"Disable legacy cleartext {service} and replace with SSH/SFTP or TLS encrypted channels.",
            })
        elif port_num in (3389, 445, 139):  # RDP or SMB
            findings.append({
                "title": f"Sensitive Infrastructure Port Exposed: {port_proto} ({service})",
                "severity": "medium",
                "verification": "potential",
                "category": "A01 - Broken Access Control",
                "remediation": "Restrict SMB and RDP access behind VPN or strict host firewalls.",
            })

    return {
        "engine": "nmap",
        "success": res["success"],
        "open_ports": open_ports,
        "findings": findings,
        "raw_output": redact_text(stdout[:2000]),
        "duration": res["duration"],
    }


def _run_nikto_scan(runtime: ScannerRuntime, target_url: str) -> dict[str, Any]:
    """Runs Nikto web server vulnerability scanner."""
    cmd = ["nikto", "-h", target_url, "-Tuning", "1,2,3,b", "-timeout", "10", "-maxtime", "60s"]
    res = runtime.execute_command(cmd, timeout=75.0)
    stdout = res["stdout"]

    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("+ ") and not line.startswith("+ Target") and not line.startswith("+ End"):
            clean_line = line[2:].strip()
            # Determine severity
            sev = "low"
            if any(k in clean_line.lower() for k in ("vulnerable", "exploit", "unauthenticated", "remote code", "overflow")):
                sev = "high"
            elif any(k in clean_line.lower() for k in ("outdated", "leak", "directory indexing", "backup", "forbidden")):
                sev = "medium"

            owasp = map_to_owasp(clean_line, "")
            findings.append({
                "title": clean_line[:120],
                "severity": sev,
                "verification": "potential",
                "category": f"{owasp['id']} - {owasp['name']}",
                "remediation": "Review server configuration or upgrade components according to Nikto advisory.",
            })

    return {
        "engine": "nikto",
        "success": res["success"],
        "findings": findings[:10],
        "raw_output": redact_text(stdout[:1500]),
        "duration": res["duration"],
    }


def _run_wapiti_scan(runtime: ScannerRuntime, target_url: str) -> dict[str, Any]:
    """Runs Wapiti web application vulnerability auditor."""
    # Scope restricted to fast check with 1 depth
    cmd = ["wapiti", "-u", target_url, "-m", "xss,sql,ssrf,crlf", "--max-scan-time", "60", "--flush-session"]
    res = runtime.execute_command(cmd, timeout=75.0)
    stdout = res["stdout"]

    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if any(term in line.lower() for term in ("vulnerability found", "sql injection", "cross site scripting", "xss")):
            findings.append({
                "title": f"Wapiti Web Audit: {line[:120]}",
                "severity": "high",
                "verification": "confirmed",
                "category": "A03 - Injection",
                "remediation": "Sanitize and validate all user inputs and apply parameterized queries.",
            })

    return {
        "engine": "wapiti",
        "success": res["success"],
        "findings": findings,
        "raw_output": redact_text(stdout[:1500]),
        "duration": res["duration"],
    }


def _run_sqlmap_scan(runtime: ScannerRuntime, target_url: str) -> dict[str, Any]:
    """Runs SQLMap targeted test."""
    cmd = ["sqlmap", "-u", target_url, "--batch", "--smart", "--threads=2", "--timeout=10", "--time-sec=3"]
    res = runtime.execute_command(cmd, timeout=60.0)
    stdout = res["stdout"]

    findings = []
    if "is vulnerable" in stdout.lower() or "sqlmap identified the following injection point" in stdout.lower():
        findings.append({
            "title": f"Confirmed SQL Injection on {target_url}",
            "severity": "critical",
            "verification": "confirmed",
            "category": "A03 - Injection",
            "remediation": "Immediately switch to prepared statements / parameterized queries and ORM escaping.",
        })

    return {
        "engine": "sqlmap",
        "success": res["success"],
        "findings": findings,
        "raw_output": redact_text(stdout[:1500]),
        "duration": res["duration"],
    }


def _run_gobuster_scan(runtime: ScannerRuntime, target_url: str) -> dict[str, Any]:
    """Runs Gobuster directory brute-forcing with common web paths."""
    # Use WSL wordlist or fallback
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-t", "10", "--timeout", "5s", "-q", "--no-error"]
    res = runtime.execute_command(cmd, timeout=45.0)
    stdout = res["stdout"]

    discovered_endpoints = []
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and "(" in line:
            discovered_endpoints.append(line)
            lower = line.lower()
            if any(sensitive in lower for sensitive in ("/admin", "/backup", "/config", "/.git", "/.env", "/phpmyadmin")):
                findings.append({
                    "title": f"Sensitive Exposed Path Discovered: {line[:80]}",
                    "severity": "medium",
                    "verification": "confirmed",
                    "category": "A01 - Broken Access Control",
                    "remediation": "Restrict access to administrative paths and remove exposed configuration or backup files.",
                })

    return {
        "engine": "gobuster",
        "success": res["success"],
        "discovered_endpoints": discovered_endpoints[:15],
        "findings": findings,
        "raw_output": redact_text(stdout[:1500]),
        "duration": res["duration"],
    }


def run(parameters: dict, player=None, session_memory=None) -> str:
    target = str(parameters.get("target", "")).strip()
    scan_type = str(parameters.get("scan_type", "quick")).lower().strip()
    authorized = bool(parameters.get("authorized", False))
    generate_report = bool(parameters.get("generate_report", True))

    if not target:
        return "Sir, please provide a target domain, URL, or IP address to assess."

    # Step 1: Safety & SSRF Validation
    try:
        sanitized_target, target_type = validate_target_safety(target, allow_local_lab=authorized)
    except SSRFProtectionError as err:
        return f"Sir, assessment halted by security safety policy: {err}"

    if player:
        try:
            player.write_log(f"JARVIS: Initializing {scan_type.upper()} security assessment for target '{sanitized_target}'...")
        except Exception:
            pass

    runtime = ScannerRuntime(wsl_distro="kali-linux")
    all_findings: list[dict[str, Any]] = []
    technologies: list[str] = []
    open_ports_summary: list[dict[str, Any]] = []
    incomplete_count = 0

    target_url = f"http://{sanitized_target}" if not sanitized_target.startswith("http") else sanitized_target

    # Step 2: HTTP Defensive Header Audit & Wappalyzer Fingerprint
    if scan_type in ("quick", "headers", "unified"):
        http_res = audit_http_headers(target_url)
        all_findings.extend(http_res.get("findings", []))
        technologies.extend(http_res.get("technologies", []))
        if player and http_res.get("technologies"):
            try:
                player.write_log(f"JARVIS: Technologies fingerprinted: {', '.join(http_res['technologies'])}")
            except Exception:
                pass

    # Step 3: Network Host & Port Discovery via Nmap
    if scan_type in ("network", "nmap", "unified"):
        if player:
            try:
                player.write_log(f"JARVIS: Executing Nmap port and service audit against {sanitized_target}...")
            except Exception:
                pass
        nmap_res = _run_nmap_scan(runtime, sanitized_target)
        if nmap_res["success"]:
            all_findings.extend(nmap_res["findings"])
            open_ports_summary = nmap_res["open_ports"]
        else:
            incomplete_count += 1

    # Step 4: Web Server Assessment via Nikto
    if scan_type in ("web_server", "nikto", "unified"):
        if not authorized:
            return "Sir, running active Nikto server vulnerability scanning requires authorized=True confirmation."
        if player:
            try:
                player.write_log(f"JARVIS: Executing Nikto web server vulnerability scan...")
            except Exception:
                pass
        nikto_res = _run_nikto_scan(runtime, target_url)
        if nikto_res["success"]:
            all_findings.extend(nikto_res["findings"])
        else:
            incomplete_count += 1

    # Step 5: Web Application Audit via Wapiti
    if scan_type in ("web_app", "wapiti"):
        if not authorized:
            return "Sir, running Wapiti web application penetration testing requires authorized=True confirmation."
        wapiti_res = _run_wapiti_scan(runtime, target_url)
        if wapiti_res["success"]:
            all_findings.extend(wapiti_res["findings"])
        else:
            incomplete_count += 1

    # Step 6: SQL Injection Audit via SQLMap
    if scan_type in ("sqli", "sqlmap"):
        if not authorized:
            return "Sir, running SQLMap database exploit engine requires authorized=True confirmation."
        sqlmap_res = _run_sqlmap_scan(runtime, target_url)
        if sqlmap_res["success"]:
            all_findings.extend(sqlmap_res["findings"])
        else:
            incomplete_count += 1

    # Step 7: Path Brute-Forcing via Gobuster
    if scan_type in ("dirs", "gobuster"):
        if not authorized:
            return "Sir, running Gobuster directory enumeration requires authorized=True confirmation."
        gobuster_res = _run_gobuster_scan(runtime, target_url)
        if gobuster_res["success"]:
            all_findings.extend(gobuster_res["findings"])
        else:
            incomplete_count += 1

    # Step 8: Risk Scoring & Report Compilation
    risk_summary = compute_risk_score(all_findings, incomplete_scanners=incomplete_count)

    report_pdf_path = None
    report_json_path = None
    nav_path = None
    if generate_report:
        report_pdf_path = generate_audit_pdf(sanitized_target, all_findings, risk_summary)
        try:
            _, nav_path = AttackNavigatorEngine.generate_findings_layer(sanitized_target, all_findings)
        except Exception as exc:
            logger.warning(f"Failed to generate Navigator layer: {exc}")
        # Also save JSON report
        json_file = SECURITY_REPORTS_DIR / f"audit_{sanitized_target.replace(':', '_')}.json"
        json_file.write_text(json.dumps({
            "target": sanitized_target,
            "scan_type": scan_type,
            "risk_summary": risk_summary,
            "technologies": technologies,
            "open_ports": open_ports_summary,
            "findings": all_findings,
            "navigator_layer": nav_path.name if nav_path else None,
        }, indent=2), encoding="utf-8")
        report_json_path = json_file

    # Build concise spoken response for JARVIS
    score = risk_summary["score"]
    level = risk_summary["risk_level"]
    crit_count = risk_summary["confirmed"]["critical"] + risk_summary["potential"]["critical"]
    high_count = risk_summary["confirmed"]["high"] + risk_summary["potential"]["high"]

    spoken_parts = [
        f"Sir, assessment of {sanitized_target} completed with a security score of {score} out of 100 ({level})."
    ]

    if open_ports_summary:
        ports_str = ", ".join(f"{p['port']} ({p['service']})" for p in open_ports_summary[:4])
        spoken_parts.append(f"Identified {len(open_ports_summary)} open ports: {ports_str}.")

    if crit_count > 0 or high_count > 0:
        spoken_parts.append(f"Warning: Discovered {crit_count} critical and {high_count} high-severity findings.")
    elif all_findings:
        spoken_parts.append(f"Discovered {len(all_findings)} moderate or defensive configuration issues.")
    else:
        spoken_parts.append("No critical vulnerabilities were detected.")

    if report_pdf_path:
        spoken_parts.append(f"Executive audit report compiled to {report_pdf_path.name}.")
    if nav_path:
        spoken_parts.append(f"ATT&CK Navigator layer saved to {nav_path.name}.")

    full_spoken = " ".join(spoken_parts)
    if player:
        try:
            player.write_log(f"JARVIS: {full_spoken}")
        except Exception:
            pass

    return full_spoken
