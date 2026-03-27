#!/usr/bin/env python3
"""
Generate a MISP-compatible event JSON for CVE-2026-24061.

The output file can be imported directly into any MISP instance via:
    Events > Add Event > Import > JSON

Contains:
    - Event metadata (CVE ID, TLP, threat level, MITRE tags)
    - Vulnerability object (CVE, CVSS, affected software)
    - Network indicators (port 23, Snort signature)
    - Attack pattern attributes

Output:
    indicators/misp_event.json

Usage:
    python3 scripts/generate_misp_event.py
"""

import json
import os
import uuid
from datetime import date, datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
IND_DIR = os.path.join(ROOT, "indicators")

TODAY = date.today().isoformat()
TIMESTAMP = str(int(datetime.now().timestamp()))


def generate_misp_event() -> dict:
    """Build a MISP event structure following the MISP JSON format."""

    event = {
        "Event": {
            "info": "CVE-2026-24061 - GNU InetUtils telnetd Unauthenticated Root via NEW-ENVIRON Injection",
            "date": TODAY,
            "threat_level_id": "1",  # 1 = High
            "analysis": "2",  # 2 = Completed
            "distribution": "3",  # 3 = All communities
            "published": False,
            "Tag": [
                {"name": "tlp:white"},
                {"name": "misp-galaxy:mitre-attack-pattern=\"Exploit Public-Facing Application - T1190\""},
                {"name": "misp-galaxy:mitre-attack-pattern=\"Abuse Elevation Control Mechanism - T1548\""},
                {"name": "type:OSINT"},
                {"name": "osint:source-type=\"technical-report\""},
                {"name": "workflow:state=\"complete\""},
            ],
            "Attribute": [
                {
                    "type": "vulnerability",
                    "category": "External analysis",
                    "value": "CVE-2026-24061",
                    "comment": "GNU InetUtils telnetd unauthenticated root shell via NEW-ENVIRON USER=\"-f root\" injection",
                    "to_ids": False,
                },
                {
                    "type": "text",
                    "category": "External analysis",
                    "value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)",
                    "comment": "CVSS v3.1 vector and score",
                    "to_ids": False,
                },
                {
                    "type": "ip-dst|port",
                    "category": "Network activity",
                    "value": "0.0.0.0|23",
                    "comment": "Default Telnet port targeted by the exploit (any IP)",
                    "to_ids": True,
                },
                {
                    "type": "snort",
                    "category": "Network activity",
                    "value": (
                        'alert tcp any any -> any 23 ('
                        'msg:"CVE-2026-24061 telnetd USER=-f root exploit attempt"; '
                        'flow:to_server,established; '
                        'content:"|FF FA 27 00 00 55 53 45 52 01 2D 66 20 72 6F 6F 74 FF F0|"; '
                        'reference:cve,2026-24061; '
                        'classtype:attempted-admin; '
                        'sid:2026240610; rev:1;)'
                    ),
                    "comment": "Snort/Suricata signature detecting the exact exploit payload",
                    "to_ids": True,
                },
                {
                    "type": "text",
                    "category": "Payload delivery",
                    "value": "IAC SB NEW-ENVIRON IS VAR \"USER\" VALUE \"-f root\" IAC SE",
                    "comment": "Telnet protocol payload injected during NEW-ENVIRON sub-negotiation (RFC 1572)",
                    "to_ids": False,
                },
                {
                    "type": "hex",
                    "category": "Payload delivery",
                    "value": "FF FA 27 00 00 55 53 45 52 01 2D 66 20 72 6F 6F 74 FF F0",
                    "comment": "Raw hex bytes of the NEW-ENVIRON injection payload",
                    "to_ids": True,
                },
                {
                    "type": "link",
                    "category": "External analysis",
                    "value": "https://github.com/franckferman/CVE_2026_24061",
                    "comment": "PoC repository",
                    "to_ids": False,
                },
                {
                    "type": "link",
                    "category": "External analysis",
                    "value": "https://datatracker.ietf.org/doc/html/rfc1572",
                    "comment": "RFC 1572 - Telnet Environment Option (NEW-ENVIRON)",
                    "to_ids": False,
                },
                {
                    "type": "text",
                    "category": "Attribution",
                    "value": "GNU InetUtils telnetd <= 2.x",
                    "comment": "Affected software and version range",
                    "to_ids": False,
                },
                {
                    "type": "text",
                    "category": "External analysis",
                    "value": "T1190, T1059, T1078.004, T1548, T1046",
                    "comment": "MITRE ATT&CK technique IDs",
                    "to_ids": False,
                },
            ],
            "Object": [
                {
                    "name": "vulnerability",
                    "meta-category": "vulnerability",
                    "description": "Vulnerability object describing CVE-2026-24061",
                    "Attribute": [
                        {"object_relation": "id", "type": "vulnerability", "value": "CVE-2026-24061"},
                        {"object_relation": "cvss-score", "type": "float", "value": "9.8"},
                        {"object_relation": "summary", "type": "text", "value": (
                            "GNU InetUtils telnetd fails to sanitize client-supplied environment "
                            "variables received via the Telnet NEW-ENVIRON option (RFC 1572). "
                            "By injecting USER=\"-f root\", an unauthenticated attacker obtains "
                            "a root shell via login(1) pre-authentication bypass."
                        )},
                        {"object_relation": "vulnerable-configuration", "type": "text", "value": "cpe:2.3:a:gnu:inetutils:*:*:*:*:*:*:*:*"},
                        {"object_relation": "references", "type": "link", "value": "https://github.com/franckferman/CVE_2026_24061"},
                    ]
                },
            ],
        }
    }

    return event


def main():
    os.makedirs(IND_DIR, exist_ok=True)

    event = generate_misp_event()
    output_path = os.path.join(IND_DIR, "misp_event.json")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(event, f, indent=2, ensure_ascii=False)

    print(f"[+] MISP event -> {output_path}")
    print(f"[+] Attributes: {len(event['Event']['Attribute'])}")
    print(f"[+] Objects: {len(event['Event']['Object'])}")
    print(f"[+] Import via: Events > Add Event > Import > JSON")


if __name__ == "__main__":
    main()
