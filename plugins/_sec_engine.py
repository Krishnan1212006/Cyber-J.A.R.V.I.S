"""
Shared Security & DevSecOps Core Engine for JARVIS Plugins.
Integrates scanner runtimes (WSL2 Kali & native), SSRF validation, OUI MAC vendor lookup,
ARP device discovery, wireless IDS threat analysis, OWASP Top 10 mapping,
tri-level finding classification, risk scoring, and ReportLab PDF reporting.
"""

from __future__ import annotations

import asyncio
import copy
import csv
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx

logger = logging.getLogger("jarvis.sec_engine")

# ---------------------------------------------------------------------------
# Paths and Storage
# ---------------------------------------------------------------------------
JARVIS_ROOT = Path(__file__).resolve().parent.parent
SECURITY_REPORTS_DIR = JARVIS_ROOT / "data" / "security_reports"
SECURITY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR = JARVIS_ROOT / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# OUI MAC Vendor Registry (Curated Top Hardware Vendors)
# ---------------------------------------------------------------------------
OUI_DATABASE: dict[str, str] = {
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:05:69": "VMware, Inc.",
    "00:1A:11": "Google, Inc.",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "24:0A:C4": "Espressif Inc. (ESP32/ESP8266)",
    "30:AE:A4": "Espressif Inc. (ESP32)",
    "84:F3:EB": "Espressif Inc. (ESP8266)",
    "A4:CF:12": "Espressif Inc. (ESP32)",
    "AC:D0:74": "Espressif Inc. (ESP32-S3)",
    "3C:71:BF": "Espressif Inc.",
    "7C:DF:A1": "Espressif Inc.",
    "48:E7:29": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "BC:D0:74": "Apple, Inc.",
    "A4:83:E7": "Apple, Inc.",
    "3C:06:30": "Apple, Inc.",
    "00:1B:63": "Apple, Inc.",
    "70:85:C2": "Intel Corporate",
    "00:15:00": "Intel Corporate",
    "34:E6:D7": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "5C:F9:DD": "Dell Inc.",
    "00:25:B3": "Hewlett Packard Enterprise",
    "3C:D9:2B": "HP Inc.",
    "00:11:32": "Synology Incorporated",
    "00:17:88": "Philips Lighting (Hue)",
    "F0:9F:C2": "Ubiquiti Inc.",
    "78:8A:20": "Ubiquiti Inc.",
    "AC:8B:A3": "Cisco Systems",
    "00:00:0C": "Cisco Systems",
    "00:1E:13": "Cisco-Linksys",
    "50:C7:BF": "TP-Link Corporation",
    "E8:48:B8": "TP-Link Corporation",
    "14:EB:B6": "TP-Link Corporation",
    "A0:F3:C1": "TP-Link Corporation",
    "60:A4:4C": "Netgear Inc.",
    "20:E5:2A": "Netgear Inc.",
    "74:DA:38": "Edimax Technology",
    "00:13:EF": "Huawei Technologies",
    "48:57:02": "Huawei Technologies",
    "F4:60:E2": "Samsung Electronics",
    "00:07:AB": "Samsung Electronics",
}


def normalize_mac(mac: str) -> str:
    """Normalize MAC string to uppercase standard XX:XX:XX:XX:XX:XX."""
    cleaned = re.sub(r"[^a-fA-F0-9]", "", mac or "").upper()
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    return mac.strip().upper()


def lookup_mac_vendor(mac: str) -> str:
    norm = normalize_mac(mac)
    prefix_6 = norm[:8]
    if prefix_6 in OUI_DATABASE:
        return OUI_DATABASE[prefix_6]
    # Check if local/randomized bit is set
    try:
        first_byte = int(norm[:2], 16)
        if first_byte & 0x02:
            return "Randomized / Private MAC (Locally Administered)"
    except Exception:
        pass
    return "Unknown Vendor / Custom Hardware"


# ---------------------------------------------------------------------------
# SSRF & Safety Protection
# ---------------------------------------------------------------------------
BLOCKED_METADATA_IPS = {"169.254.169.254", "169.254.170.2"}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


class SSRFProtectionError(ValueError):
    pass


def validate_target_safety(target: str, allow_local_lab: bool = False) -> Tuple[str, str]:
    """
    Validates target URL or IP against SSRF attacks.
    Blocks cloud instance metadata endpoints and unapproved private subnets.
    Returns (sanitized_target, target_type) e.g. ('example.com', 'domain') or ('192.168.1.1', 'ip').
    """
    target = target.strip()
    if not target:
        raise SSRFProtectionError("Target cannot be empty.")

    # Remove protocol if present
    parsed = urlsplit(target if "://" in target else f"http://{target}")
    hostname = parsed.hostname or target.split("/")[0].split(":")[0]

    # Check direct IP
    try:
        ip = ipaddress.ip_address(hostname)
        if str(ip) in BLOCKED_METADATA_IPS:
            raise SSRFProtectionError(f"Access to Cloud Metadata Service ({ip}) is strictly forbidden.")

        for net in PRIVATE_NETWORKS:
            if ip in net:
                if not allow_local_lab:
                    raise SSRFProtectionError(
                        f"Target IP {ip} is in a private network ({net}). "
                        "Set authorized=True to confirm this is an intentional local assessment."
                    )
                return str(ip), "private_ip"

        return str(ip), "public_ip"
    except ValueError:
        pass

    # Domain name resolution safety
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1") and not allow_local_lab:
        raise SSRFProtectionError("Loopback scanning requires authorized=True.")

    # Try resolving hostname to check underlying IP
    try:
        resolved_ip_str = socket.gethostbyname(hostname)
        resolved_ip = ipaddress.ip_address(resolved_ip_str)
        if str(resolved_ip) in BLOCKED_METADATA_IPS:
            raise SSRFProtectionError("Target resolves to Cloud Metadata Service.")
        for net in PRIVATE_NETWORKS:
            if resolved_ip in net and not allow_local_lab:
                raise SSRFProtectionError(
                    f"Target '{hostname}' resolves to private IP {resolved_ip}. "
                    "Set authorized=True to run on local subnets."
                )
    except socket.gaierror:
        # Host might not resolve if offline/isolated
        pass

    return hostname, "domain"


# ---------------------------------------------------------------------------
# Redaction Engine (Masks Secrets, Keys & Credentials)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(api[_\-]?key[\s:=]+)[A-Za-z0-9_\-]{16,}", re.IGNORECASE), r"\1[REDACTED_API_KEY]"),
    (re.compile(r"(password[\s:=]+)[^\s,;\"]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(token[\s:=]+)[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def redact_text(text: str) -> str:
    if not text:
        return ""
    result = text
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


# ---------------------------------------------------------------------------
# Scanner Runtime (Executes in WSL2 Kali Linux or Host)
# ---------------------------------------------------------------------------
class ScannerRuntime:
    """Manages secure subprocess invocation into WSL2 Kali or native Windows binaries."""

    def __init__(self, wsl_distro: str = "kali-linux"):
        self.wsl_distro = wsl_distro
        self.has_wsl = (platform.system() == "Windows")

    def execute_command(self, cmd_args: Sequence[str], timeout: float = 60.0) -> dict[str, Any]:
        """
        Executes scanner tool without shell interpolation (shell=False) to prevent command injection.
        Wraps with wsl.exe -d kali-linux on Windows if available.
        """
        full_command: list[str] = []
        if self.has_wsl:
            full_command = ["wsl.exe", "-d", self.wsl_distro, "--", *cmd_args]
        else:
            full_command = list(cmd_args)

        start_time = time.time()
        try:
            proc = subprocess.run(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                shell=False,
            )
            duration = round(time.time() - start_time, 2)
            stdout = proc.stdout.decode("utf-8", errors="replace").strip()
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()
            return {
                "success": proc.returncode == 0,
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration": duration,
                "command": " ".join(cmd_args),
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds.",
                "duration": round(time.time() - start_time, 2),
                "command": " ".join(cmd_args),
            }
        except Exception as exc:
            return {
                "success": False,
                "exit_code": -2,
                "stdout": "",
                "stderr": str(exc),
                "duration": round(time.time() - start_time, 2),
                "command": " ".join(cmd_args),
            }


# ---------------------------------------------------------------------------
# Finding Normalization, OWASP Top 10 Mapping & Risk Scoring
# ---------------------------------------------------------------------------
OWASP_TAXONOMY = {
    "A01": {"name": "Broken Access Control", "keywords": ["path traversal", "directory traversal", "admin", "unauthorized", "idor", "forbidden"]},
    "A02": {"name": "Cryptographic Failures", "keywords": ["tls", "ssl", "hsts", "cipher", "cleartext", "certificate", "crypto"]},
    "A03": {"name": "Injection", "keywords": ["sqli", "sql injection", "command injection", "xss", "cross-site scripting", "crlf", "ldap"]},
    "A04": {"name": "Insecure Design", "keywords": ["rate limit", "brute force", "threat model", "flawed"]},
    "A05": {"name": "Security Misconfiguration", "keywords": ["header", "options", "default", "debug", "nikto", "config", "banner", "cors", "clickjacking", "x-frame-options", "csp"]},
    "A06": {"name": "Vulnerable and Outdated Components", "keywords": ["outdated", "deprecated", "cve-", "apache", "nginx", "version", "wordpress", "plugin"]},
    "A07": {"name": "Identification and Authentication Failures", "keywords": ["session", "cookie", "auth", "credential", "password", "jwt", "login"]},
    "A08": {"name": "Software and Data Integrity Failures", "keywords": ["subresource", "sri", "unsigned", "deserialization"]},
    "A09": {"name": "Security Logging and Monitoring Failures", "keywords": ["audit", "logging", "telemetry", "unmonitored"]},
    "A10": {"name": "Server-Side Request Forgery (SSRF)", "keywords": ["ssrf", "request forgery", "metadata", "internal url"]},
}


def map_to_owasp(title: str, description: str) -> dict[str, str]:
    text = f"{title} {description}".lower()
    for cat_id, cat_info in OWASP_TAXONOMY.items():
        for kw in cat_info["keywords"]:
            if kw in text:
                return {"id": cat_id, "name": cat_info["name"]}
    return {"id": "A05", "name": "Security Misconfiguration"}


def compute_risk_score(findings: list[dict[str, Any]], incomplete_scanners: int = 0) -> dict[str, Any]:
    """
    Algorithmic VulnAI / JARVIS Risk Scoring (0–100).
    Base score: 100.
    Deductions:
      - Confirmed Critical: -25.0, High: -15.0, Medium: -6.0, Low: -2.0
      - Potential Critical: -12.0, High: -8.0, Medium: -3.0, Low: -1.0
      - Informational: 0.0
      - Incomplete scanner penalty: -4.0 per failed tool
    """
    base_score = 100.0
    confirmed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    potential_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    info_counts = 0

    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        verif = str(f.get("verification", "potential")).lower()

        if verif == "confirmed":
            if sev in confirmed_counts:
                confirmed_counts[sev] += 1
            if sev == "critical":
                base_score -= 25.0
            elif sev == "high":
                base_score -= 15.0
            elif sev == "medium":
                base_score -= 6.0
            elif sev == "low":
                base_score -= 2.0
        elif verif == "potential":
            if sev in potential_counts:
                potential_counts[sev] += 1
            if sev == "critical":
                base_score -= 12.0
            elif sev == "high":
                base_score -= 8.0
            elif sev == "medium":
                base_score -= 3.0
            elif sev == "low":
                base_score -= 1.0
        else:
            info_counts += 1

    base_score -= (incomplete_scanners * 4.0)
    final_score = max(0.0, min(100.0, round(base_score, 1)))

    if final_score >= 85:
        risk_level = "LOW RISK"
    elif final_score >= 65:
        risk_level = "MODERATE RISK"
    elif final_score >= 40:
        risk_level = "ELEVATED RISK"
    else:
        risk_level = "CRITICAL RISK"

    return {
        "score": final_score,
        "risk_level": risk_level,
        "confirmed": confirmed_counts,
        "potential": potential_counts,
        "informational_count": info_counts,
        "incomplete_scanners": incomplete_scanners,
    }


# ---------------------------------------------------------------------------
# HTTP Headers & Technology Fingerprinting (Wappalyzer & Active Probing)
# ---------------------------------------------------------------------------
def audit_http_headers(target_url: str) -> dict[str, Any]:
    """Inspects target HTTP response headers for defensive security posture."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    try:
        with httpx.Client(verify=False, timeout=10.0, follow_redirects=True) as client:
            resp = client.get(target_url)
    except Exception as exc:
        return {"error": f"Failed to connect to {target_url}: {exc}", "headers": {}, "findings": []}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[dict[str, Any]] = []

    # 1. HSTS
    if "strict-transport-security" not in headers:
        findings.append({
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "severity": "medium",
            "verification": "confirmed",
            "category": "A02 - Cryptographic Failures",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        })

    # 2. CSP
    if "content-security-policy" not in headers:
        findings.append({
            "title": "Missing Content-Security-Policy (CSP) Header",
            "severity": "medium",
            "verification": "confirmed",
            "category": "A05 - Security Misconfiguration",
            "remediation": "Configure a Content-Security-Policy header to mitigate XSS and data injection.",
        })

    # 3. X-Frame-Options (Clickjacking)
    if "x-frame-options" not in headers:
        findings.append({
            "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
            "severity": "low",
            "verification": "confirmed",
            "category": "A05 - Security Misconfiguration",
            "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        })

    # 4. X-Content-Type-Options (MIME Sniffing)
    if "x-content-type-options" not in headers or headers.get("x-content-type-options") != "nosniff":
        findings.append({
            "title": "Missing X-Content-Type-Options: nosniff",
            "severity": "low",
            "verification": "confirmed",
            "category": "A05 - Security Misconfiguration",
            "remediation": "Set 'X-Content-Type-Options: nosniff'.",
        })

    # 5. Information Disclosure in Server Banner
    server_header = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")
    technologies: list[str] = []

    if server_header:
        technologies.append(f"Server: {server_header}")
        if any(char.isdigit() for char in server_header):
            findings.append({
                "title": f"Server Software Version Disclosed: {server_header}",
                "severity": "low",
                "verification": "confirmed",
                "category": "A05 - Security Misconfiguration",
                "remediation": "Mask or disable detailed software version banners in server config.",
            })

    if x_powered_by:
        technologies.append(f"Framework: {x_powered_by}")
        findings.append({
            "title": f"Technology Disclosure via X-Powered-By: {x_powered_by}",
            "severity": "low",
            "verification": "confirmed",
            "category": "A05 - Security Misconfiguration",
            "remediation": "Disable the X-Powered-By response header in your application framework.",
        })

    # Basic HTML heuristics
    body = resp.text[:50000].lower()
    if "wp-content" in body or "wordpress" in body:
        technologies.append("CMS: WordPress")
    if "react" in body or "_react" in body:
        technologies.append("Frontend: React")
    if "vue" in body:
        technologies.append("Frontend: Vue.js")
    if "bootstrap" in body:
        technologies.append("CSS: Bootstrap")

    return {
        "status_code": resp.status_code,
        "technologies": technologies,
        "headers_found": list(headers.keys()),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Network Asset Discovery (ARP & Neighbor Table Parsing)
# ---------------------------------------------------------------------------
def discover_local_network_devices() -> list[dict[str, Any]]:
    """
    Parses Windows/Linux ARP cache to inventory live devices on local subnets.
    Associates hardware MAC addresses with vendor identities.
    """
    devices: list[dict[str, Any]] = []
    try:
        if platform.system() == "Windows":
            res = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
            output = res.stdout
        else:
            res = subprocess.run(["ip", "neigh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
            output = res.stdout

        ip_mac_pattern = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F\:\-]{11,17})",
            re.IGNORECASE
        )
        seen_ips = set()
        for match in ip_mac_pattern.finditer(output):
            ip, raw_mac = match.group(1), match.group(2)
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239.") or ip in seen_ips:
                continue
            seen_ips.add(ip)
            normalized_mac = normalize_mac(raw_mac.replace("-", ":"))
            if normalized_mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                continue

            vendor = lookup_mac_vendor(normalized_mac)
            devices.append({
                "ip": ip,
                "mac": normalized_mac,
                "vendor": vendor,
                "is_randomized": "Randomized" in vendor,
                "status": "online",
            })
    except Exception as exc:
        logger.error(f"Error parsing ARP table: {exc}")

    return devices


# ---------------------------------------------------------------------------
# Wireless IDS Telemetry Analyzer (SNID 802.11 Deauth & Rogue AP)
# ---------------------------------------------------------------------------
class WirelessIDSAnalyzer:
    """Evaluates wireless packet observations for deauth floods and rogue APs."""

    @staticmethod
    def evaluate_telemetry(
        deauth_count_last_minute: int,
        observed_aps: list[dict[str, Any]],
        known_authorized_ssids: list[str] | None = None,
    ) -> dict[str, Any]:
        alerts: list[dict[str, Any]] = []
        authorized_ssids = set(known_authorized_ssids or [])

        # 1. 802.11 Deauthentication Burst Threshold
        if deauth_count_last_minute >= 15:
            severity = "critical" if deauth_count_last_minute >= 50 else "high"
            alerts.append({
                "type": "DEAUTH_FLOOD_DETECTED",
                "severity": severity,
                "verification": "confirmed",
                "message": (
                    f"Active 802.11 Deauthentication burst detected: {deauth_count_last_minute} frames/min. "
                    "Possible Wi-Fi disruption or WPA 4-way handshake capture attack."
                ),
                "metric": deauth_count_last_minute,
            })

        # 2. Rogue AP / Evil Twin Heuristics
        ssid_to_bssids: dict[str, list[dict[str, Any]]] = {}
        for ap in observed_aps:
            ssid = ap.get("ssid", "").strip()
            bssid = normalize_mac(ap.get("bssid", ""))
            channel = ap.get("channel", 0)
            signal = ap.get("signal_dbm", -70)
            vendor = lookup_mac_vendor(bssid)

            if not ssid:
                # Hidden SSID
                alerts.append({
                    "type": "HIDDEN_SSID_BROADCAST",
                    "severity": "low",
                    "verification": "informational",
                    "message": f"Hidden / Cloaked Access Point detected (BSSID: {bssid}, Ch: {channel}, Vendor: {vendor}).",
                })
                continue

            if ssid not in ssid_to_bssids:
                ssid_to_bssids[ssid] = []
            ssid_to_bssids[ssid].append({"bssid": bssid, "channel": channel, "vendor": vendor, "signal": signal})

        # Check for multiple BSSIDs broadcasting the same corporate SSID with disparate vendors
        for ssid, bssids in ssid_to_bssids.items():
            if len(bssids) > 1 and (not authorized_ssids or ssid in authorized_ssids):
                vendors = {b["vendor"] for b in bssids}
                if len(vendors) > 1:
                    alerts.append({
                        "type": "EVIL_TWIN_SUSPECTED",
                        "severity": "high",
                        "verification": "potential",
                        "message": (
                            f"Suspected Evil Twin / Rogue AP for SSID '{ssid}'. Multiple disparate vendors broadcasting "
                            f"same SSID: {', '.join(vendors)}."
                        ),
                        "ssid": ssid,
                        "bssids": bssids,
                    })

        return {
            "status": "THREAT_DETECTED" if any(a["severity"] in ("high", "critical") for a in alerts) else "NORMAL",
            "alerts": alerts,
            "aps_analyzed": len(observed_aps),
            "deauth_rate": deauth_count_last_minute,
        }


# ---------------------------------------------------------------------------
# PDF Report Generator (ReportLab)
# ---------------------------------------------------------------------------
def generate_audit_pdf(
    target: str,
    findings: list[dict[str, Any]],
    risk_summary: dict[str, Any],
    output_filename: Optional[str] = None,
) -> Path:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    clean_target = re.sub(r"[^a-zA-Z0-9_\-]", "_", target)[:40]
    file_name = output_filename or f"jarvis_sec_audit_{clean_target}_{timestamp_str}.pdf"
    pdf_path = SECURITY_REPORTS_DIR / file_name

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=48,
        bottomMargin=48,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "HeaderTitle",
        parent=styles["Heading1"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "HeaderSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("🛡️ JARVIS DEVSECOPS SECURITY ASSESSMENT REPORT", title_style))
    elements.append(Paragraph(f"Target: <b>{target}</b> | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # Executive Summary Table
    score = risk_summary.get("score", 100.0)
    risk_level = risk_summary.get("risk_level", "LOW RISK")
    confirmed = risk_summary.get("confirmed", {})
    potential = risk_summary.get("potential", {})

    summary_data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Assessment Result</b>", body_style)],
        [Paragraph("Security Risk Score", body_style), Paragraph(f"<b>{score}/100</b> ({risk_level})", body_style)],
        [Paragraph("Confirmed Critical / High", body_style), Paragraph(f"{confirmed.get('critical', 0)} Critical / {confirmed.get('high', 0)} High", body_style)],
        [Paragraph("Potential Observations", body_style), Paragraph(f"{potential.get('critical', 0)} Crit / {potential.get('high', 0)} High / {potential.get('medium', 0)} Med", body_style)],
        [Paragraph("Total Findings Logged", body_style), Paragraph(str(len(findings)), body_style)],
    ]

    t_summary = Table(summary_data, colWidths=[200, 304])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 14))

    # Detailed Findings
    elements.append(Paragraph("Vulnerability & Threat Findings", section_style))

    if not findings:
        elements.append(Paragraph("✅ No active security vulnerabilities or misconfigurations discovered.", body_style))
    else:
        table_rows = [
            [
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Title / Description</b>", body_style),
                Paragraph("<b>OWASP Category</b>", body_style),
                Paragraph("<b>Verification</b>", body_style),
            ]
        ]
        for f in findings:
            sev = str(f.get("severity", "LOW")).upper()
            verif = str(f.get("verification", "potential")).title()
            title = f.get("title", "Observation")
            remed = f.get("remediation", "")
            cat = f.get("category", "A05 - Security Misconfiguration")

            desc_text = f"<b>{title}</b>"
            if remed:
                desc_text += f"<br/><font color='#0284c7'>Remediation: {remed}</font>"

            table_rows.append([
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(desc_text, body_style),
                Paragraph(cat, body_style),
                Paragraph(verif, body_style),
            ])

        t_findings = Table(table_rows, colWidths=[70, 254, 110, 70])
        t_findings.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(t_findings)

    doc.build(elements)
    return pdf_path
