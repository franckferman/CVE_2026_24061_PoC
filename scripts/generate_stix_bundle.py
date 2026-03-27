#!/usr/bin/env python3
"""
Generate a STIX 2.1 bundle for CVE-2026-24061.

Produces a self-contained STIX bundle containing:
    - Vulnerability SDO (CVE metadata, CVSS)
    - Indicator SDO (network traffic pattern matching the exploit)
    - Attack Pattern SDOs (MITRE ATT&CK techniques)
    - Course of Action SDO (remediation steps)
    - Relationships linking all objects

The bundle is valid STIX 2.1 JSON and can be consumed by:
    - MISP (via STIX import)
    - OpenCTI
    - TAXII servers
    - Any STIX 2.1 compatible platform

Output:
    indicators/stix_bundle.json

Usage:
    python3 scripts/generate_stix_bundle.py

No external dependencies - builds the JSON structure directly.
"""

import json
import os
import uuid
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
IND_DIR = os.path.join(ROOT, "indicators")

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_id(stype: str) -> str:
    """Generate a deterministic-ish STIX ID."""
    return f"{stype}--{uuid.uuid5(uuid.NAMESPACE_URL, f'CVE-2026-24061-{stype}')}"


def generate_bundle() -> dict:
    """Build a STIX 2.1 bundle."""

    vuln_id = stix_id("vulnerability")
    indicator_id = stix_id("indicator")
    ap_t1190_id = stix_id("attack-pattern-t1190")
    ap_t1548_id = stix_id("attack-pattern-t1548")
    ap_t1059_id = stix_id("attack-pattern-t1059")
    coa_id = stix_id("course-of-action")
    identity_id = stix_id("identity")

    objects = []

    # Identity (author)
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": NOW,
        "modified": NOW,
        "name": "franckferman",
        "identity_class": "individual",
        "description": "Security researcher - CVE-2026-24061 analysis and PoC author",
    })

    # Vulnerability
    objects.append({
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": vuln_id,
        "created": NOW,
        "modified": NOW,
        "created_by_ref": identity_id,
        "name": "CVE-2026-24061",
        "description": (
            "GNU InetUtils telnetd fails to sanitize client-supplied environment variables "
            "received via the Telnet NEW-ENVIRON option (RFC 1572). By injecting USER=\"-f root\" "
            "during the protocol handshake, an unauthenticated attacker causes telnetd to invoke "
            "\"login -f root\", granting a root shell without credential verification. "
            "CVSS 3.1: 9.8 Critical (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)."
        ),
        "external_references": [
            {"source_name": "cve", "external_id": "CVE-2026-24061", "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-24061"},
            {"source_name": "RFC 1572", "url": "https://datatracker.ietf.org/doc/html/rfc1572", "description": "Telnet Environment Option (NEW-ENVIRON)"},
            {"source_name": "PoC", "url": "https://github.com/franckferman/CVE_2026_24061"},
            {"source_name": "cve", "external_id": "CVE-2001-0797", "description": "Historical precedent: SysV telnetd -f bypass"},
        ],
    })

    # Indicator (network signature)
    objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": NOW,
        "modified": NOW,
        "created_by_ref": identity_id,
        "name": "CVE-2026-24061 Exploit Payload",
        "description": (
            "Detects the Telnet NEW-ENVIRON sub-negotiation payload containing "
            "VAR USER VALUE \"-f root\" used to exploit CVE-2026-24061. "
            "Hex: FF FA 27 00 00 55 53 45 52 01 2D 66 20 72 6F 6F 74 FF F0"
        ),
        "indicator_types": ["malicious-activity"],
        "pattern": "[network-traffic:dst_port = 23 AND network-traffic:extensions.'tcp-ext'.src_payload_ref.payload_bin = 'v/onAABVU0VSAS1mIHJvb3T/8A==']",
        "pattern_type": "stix",
        "valid_from": NOW,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
        ],
    })

    # Attack Patterns (MITRE ATT&CK)
    for ap_id, tid, name, tactic in [
        (ap_t1190_id, "T1190", "Exploit Public-Facing Application", "initial-access"),
        (ap_t1548_id, "T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
        (ap_t1059_id, "T1059", "Command and Scripting Interpreter", "execution"),
    ]:
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": NOW,
            "modified": NOW,
            "name": name,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid, "url": f"https://attack.mitre.org/techniques/{tid}/"},
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": tactic},
            ],
        })

    # Course of Action (remediation)
    objects.append({
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": coa_id,
        "created": NOW,
        "modified": NOW,
        "created_by_ref": identity_id,
        "name": "Mitigate CVE-2026-24061",
        "description": (
            "1. Disable telnetd immediately (systemctl disable telnet.socket --now). "
            "2. Replace Telnet with SSH for all remote administration. "
            "3. Apply vendor patch for GNU InetUtils when available. "
            "4. Block TCP/23 at perimeter firewalls. "
            "5. Deploy IDS signatures to detect NEW-ENVIRON USER=\"-f\" injection patterns. "
            "6. Monitor auth.log for unexpected root logins via login(1)."
        ),
    })

    # Relationships
    relationships = [
        ("indicates", indicator_id, vuln_id, "Indicator detects exploitation of CVE-2026-24061"),
        ("uses", ap_t1190_id, vuln_id, "T1190 exploits the telnetd vulnerability"),
        ("uses", ap_t1548_id, vuln_id, "T1548 abuses login -f to escalate privileges"),
        ("mitigates", coa_id, vuln_id, "Remediation steps for CVE-2026-24061"),
    ]

    for rel_type, source, target, desc in relationships:
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_URL, f'{source}-{rel_type}-{target}')}",
            "created": NOW,
            "modified": NOW,
            "relationship_type": rel_type,
            "source_ref": source,
            "target_ref": target,
            "description": desc,
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, 'CVE-2026-24061-bundle')}",
        "objects": objects,
    }


def main():
    os.makedirs(IND_DIR, exist_ok=True)

    bundle = generate_bundle()
    output_path = os.path.join(IND_DIR, "stix_bundle.json")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    print(f"[+] STIX 2.1 bundle -> {output_path}")
    print(f"[+] Objects: {len(bundle['objects'])}")
    print(f"[+] Types: {', '.join(set(o['type'] for o in bundle['objects']))}")
    print(f"[+] Compatible with: MISP, OpenCTI, TAXII, any STIX 2.1 consumer")


if __name__ == "__main__":
    main()
