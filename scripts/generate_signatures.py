#!/usr/bin/env python3
"""
Generate IDS signatures (Snort/Suricata + Sigma) from the exploit payload.

Extracts the exact NEW-ENVIRON injection bytes from the PoC and produces
detection rules that match the exploit in transit. If the payload changes,
re-running this script updates the signatures automatically.

Output:
    signatures/snort.rules    Snort/Suricata rules
    signatures/sigma.yml      Sigma rule (DNS/network)

Usage:
    python3 scripts/generate_signatures.py
"""

import os
import sys
from datetime import date

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
SIG_DIR = os.path.join(ROOT, "signatures")

# The exact payload bytes that telnetd receives:
# IAC SB NEW-ENVIRON IS VAR "USER" VALUE "-f root" IAC SE
#
# FF FA 27 00 00 55 53 45 52 01 2D 66 20 72 6F 6F 74 FF F0
IAC  = b'\xff'
SB   = b'\xfa'
SE   = b'\xf0'
NEW_ENVIRON = b'\x27'
IS    = b'\x00'
VAR   = b'\x00'
VALUE = b'\x01'

PAYLOAD = (
    IAC + SB + NEW_ENVIRON + IS
    + VAR + b"USER"
    + VALUE + b"-f root"
    + IAC + SE
)

# Convert to Snort hex content string: |FF FA 27 00 ...|
PAYLOAD_HEX = " ".join(f"{b:02X}" for b in PAYLOAD)
# Convert to pipe-delimited Snort format
PAYLOAD_SNORT = f"|{PAYLOAD_HEX}|"

TODAY = date.today().isoformat()


def generate_snort() -> str:
    """Generate Snort/Suricata rules."""
    rules = []

    # Rule 1: Detect the exact exploit payload
    rules.append(
        f'# CVE-2026-24061 - GNU InetUtils telnetd NEW-ENVIRON auth bypass\n'
        f'# Auto-generated on {TODAY} from exploit payload\n'
        f'# Payload hex: {PAYLOAD_HEX}\n'
        f'\n'
        f'# Detect exploit attempt (client -> server)\n'
        f'alert tcp any any -> any 23 (\n'
        f'  msg:"CVE-2026-24061 telnetd USER=-f root exploit attempt";\n'
        f'  flow:to_server,established;\n'
        f'  content:"{PAYLOAD_SNORT}";\n'
        f'  reference:cve,2026-24061;\n'
        f'  classtype:attempted-admin;\n'
        f'  sid:2026240610; rev:1;\n'
        f')\n'
    )

    # Rule 2: Detect any NEW-ENVIRON with "-f" flag injection (generic)
    rules.append(
        f'# Generic detection: any USER value starting with "-f" via NEW-ENVIRON\n'
        f'alert tcp any any -> any 23 (\n'
        f'  msg:"Telnet NEW-ENVIRON USER -f flag injection (generic)";\n'
        f'  flow:to_server,established;\n'
        f'  content:"|FF FA 27 00 00|USER|01|-f";\n'
        f'  reference:cve,2026-24061;\n'
        f'  reference:cve,2001-0797;\n'
        f'  classtype:attempted-admin;\n'
        f'  sid:2026240611; rev:1;\n'
        f')\n'
    )

    # Rule 3: Detect successful exploitation (server -> client: uid=0)
    rules.append(
        f'# Post-exploitation: root shell confirmation in telnet session\n'
        f'alert tcp any 23 -> any any (\n'
        f'  msg:"CVE-2026-24061 successful root shell via telnetd";\n'
        f'  flow:to_client,established;\n'
        f'  content:"uid=0(root)";\n'
        f'  reference:cve,2026-24061;\n'
        f'  classtype:successful-admin;\n'
        f'  sid:2026240612; rev:1;\n'
        f')\n'
    )

    return "\n".join(rules)


def generate_sigma() -> str:
    """Generate a Sigma rule for SIEM detection."""
    return f"""# CVE-2026-24061 - Telnet NEW-ENVIRON Authentication Bypass
# Auto-generated on {TODAY}
# Sigma specification: https://sigmahq.io/

title: CVE-2026-24061 Telnet NEW-ENVIRON Auth Bypass Attempt
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: |
    Detects exploitation attempts of CVE-2026-24061 where an attacker injects
    USER="-f root" via the Telnet NEW-ENVIRON option to bypass authentication
    in GNU InetUtils telnetd.
references:
    - https://github.com/franckferman/CVE_2026_24061
    - https://datatracker.ietf.org/doc/html/rfc1572
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-24061
author: franckferman
date: {TODAY}
tags:
    - attack.initial_access
    - attack.t1190
    - attack.privilege_escalation
    - attack.t1548
    - cve.2026.24061
logsource:
    category: network_connection
    product: any
detection:
    selection_port:
        dst_port: 23
    selection_payload:
        payload|contains:
            - 'USER'
            - '-f root'
    selection_ids:
        alert.signature|contains: 'CVE-2026-24061'
    condition: selection_port and (selection_payload or selection_ids)
falsepositives:
    - Legitimate use of Telnet NEW-ENVIRON with USER variable (very rare)
level: critical
"""


def main():
    os.makedirs(SIG_DIR, exist_ok=True)

    snort_path = os.path.join(SIG_DIR, "snort.rules")
    sigma_path = os.path.join(SIG_DIR, "sigma.yml")

    snort_content = generate_snort()
    sigma_content = generate_sigma()

    with open(snort_path, 'w', encoding='utf-8') as f:
        f.write(snort_content)

    with open(sigma_path, 'w', encoding='utf-8') as f:
        f.write(sigma_content)

    print(f"[+] Snort/Suricata rules -> {snort_path}")
    print(f"[+] Sigma rule           -> {sigma_path}")
    print(f"[+] Payload hex: {PAYLOAD_HEX}")
    print(f"[+] Payload size: {len(PAYLOAD)} bytes")


if __name__ == "__main__":
    main()
