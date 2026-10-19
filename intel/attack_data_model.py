"""
ATT&CK Data Model (ADM) & Detection Telemetry Engine for JARVIS (attack-data-model).
Maps MITRE ATT&CK Data Sources and Data Components to concrete log telemetry:
- Windows Security Event Log IDs (4688, 4624, 4697, 4768, 1102)
- Microsoft Sysmon Event IDs (EID 1, 3, 7, 8, 10, 11, 12, 13, 22)
- PowerShell Script Block Logging (EID 4104)
- Linux auditd system call logs (EXECVE, CONNECT, SYSCALL)
- Network Sensor logs (Zeek, Suricata, DNS queries)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from intel.mitre_attack_stix import MitreStixEngine

logger = logging.getLogger("jarvis.intel.adm")

# Curated Telemetry & Sensor Mappings for ATT&CK Data Components
DATA_COMPONENT_TELEMETRY: dict[str, dict[str, Any]] = {
    "Process: Process Creation": {
        "telemetry_sources": [
            "Microsoft Sysmon Event ID 1 (Process Create)",
            "Windows Security Event ID 4688 (A new process has been created with command line enabled)",
            "Linux auditd SYSCALL/EXECVE",
            "EDR Process Execution Telemetry",
        ],
        "key_fields": ["ProcessId", "Image / ParentImage", "CommandLine", "User", "ProcessGuid"],
        "sample_query": "Sysmon EventID 1: Image != ParentImage AND CommandLine != ''",
    },
    "Process: OS API Execution": {
        "telemetry_sources": [
            "Microsoft Sysmon Event ID 7 (Image loaded)",
            "Microsoft Sysmon Event ID 8 (CreateRemoteThread)",
            "Microsoft Sysmon Event ID 10 (ProcessAccess / OpenProcess LSASS)",
            "Windows ETW (Microsoft-Windows-Kernel-Process)",
        ],
        "key_fields": ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
        "sample_query": "Sysmon EventID 10: TargetImage =~ 'lsass.exe' AND GrantedAccess == '0x1010'",
    },
    "Command: Command Execution": {
        "telemetry_sources": [
            "PowerShell Event ID 4104 (Script Block Logging)",
            "PowerShell Event ID 4103 (Module Logging)",
            "Bash / Zsh History Auditing (pam_tty_audit / auditd)",
        ],
        "key_fields": ["ScriptBlockText", "Path", "UserId", "HostApplication"],
        "sample_query": "EventID 4104: ScriptBlockText =~ /(?i)(DownloadString|Invoke-Expression|IEX|EncodedCommand)/",
    },
    "Network Traffic: Network Connection Creation": {
        "telemetry_sources": [
            "Microsoft Sysmon Event ID 3 (Network Connect)",
            "Windows Filtering Platform Event ID 5156 (Permitted Connection)",
            "Zeek conn.log",
            "Suricata flow logs",
        ],
        "key_fields": ["SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Protocol"],
        "sample_query": "Sysmon EventID 3: DestinationPort IN (4444, 1337, 8080, 8443) OR DestinationIsIpv6 == false",
    },
    "Network Traffic: DNS Query": {
        "telemetry_sources": [
            "Microsoft Sysmon Event ID 22 (DNSEvent)",
            "Windows DNS Client Event ID 3008",
            "Zeek dns.log",
        ],
        "key_fields": ["QueryName", "QueryStatus", "QueryResults"],
        "sample_query": "Sysmon EventID 22: QueryName =~ /\\.onion|\\.top|\\.xyz/ OR len(QueryName) > 40",
    },
    "File: File Creation": {
        "telemetry_sources": [
            "Microsoft Sysmon Event ID 11 (FileCreate)",
            "Windows Security Event ID 4663 (An attempt was made to access an object)",
            "Linux auditd path watch (fsnotify)",
        ],
        "key_fields": ["TargetFilename", "CreationUtcTime", "Image"],
        "sample_query": "Sysmon EventID 11: TargetFilename =~ /\\.(exe|dll|ps1|vbs|bat|jsp|aspx)$/ In 'C:\\Users\\*\\AppData\\*'",
    },
    "Logon Session: User Account Authentication": {
        "telemetry_sources": [
            "Windows Security Event ID 4624 (Successful Logon, Type 2, 3, 10)",
            "Windows Security Event ID 4625 (Failed Logon)",
            "Windows Kerberos Event ID 4768 / 4769 (TGT / Service Ticket Requested)",
            "Linux /var/log/auth.log or secure (sshd / PAM)",
        ],
        "key_fields": ["TargetUserName", "LogonType", "IpAddress", "WorkstationName"],
        "sample_query": "EventID 4624: LogonType == 10 (RemoteInteractive / RDP) OR LogonType == 3 (Network)",
    },
    "Service: Service Installation": {
        "telemetry_sources": [
            "Windows System Event ID 7045 (A new service was installed in the system)",
            "Windows Security Event ID 4697 (A service was installed in the system)",
            "Microsoft Sysmon Event ID 12/13 (Registry Event: HKLM\\SYSTEM\\CurrentControlSet\\Services)",
        ],
        "key_fields": ["ServiceName", "ImagePath", "ServiceType", "StartType"],
        "sample_query": "EventID 7045: ImagePath =~ /AppData|Temp|cmd\\.exe|powershell\\.exe/",
    },
}


class AttackDataModelEngine:
    """Provides detection engineers with exact telemetry data sources and rule templates."""

    @classmethod
    def get_detection_blueprint(cls, technique_id_or_name: str) -> dict[str, Any]:
        stix = MitreStixEngine.get_instance()
        tech = stix.get_technique(technique_id_or_name)
        if not tech:
            return {"error": f"Technique '{technique_id_or_name}' not found."}

        data_sources = tech.get("data_sources", [])
        telemetry_recommendations: list[dict[str, Any]] = []

        for ds in data_sources:
            # Check direct match or component match
            if ds in DATA_COMPONENT_TELEMETRY:
                telemetry_recommendations.append({
                    "data_source": ds,
                    **DATA_COMPONENT_TELEMETRY[ds],
                })
            else:
                # Sub-match e.g. "Process" or "Network"
                for comp_key, comp_data in DATA_COMPONENT_TELEMETRY.items():
                    if any(part.lower() in comp_key.lower() for part in ds.split(":")):
                        if not any(r["data_source"] == comp_key for r in telemetry_recommendations):
                            telemetry_recommendations.append({
                                "data_source": comp_key,
                                **comp_data,
                            })

        # Fallback if no specific data component mapped
        if not telemetry_recommendations:
            telemetry_recommendations.append({
                "data_source": "Process: Process Creation",
                **DATA_COMPONENT_TELEMETRY["Process: Process Creation"],
            })

        return {
            "technique_id": tech["id"],
            "technique_name": tech["name"],
            "platforms": tech.get("platforms", []),
            "official_detection_guidance": tech.get("detection_guidance", ""),
            "telemetry_prerequisites": telemetry_recommendations,
        }
