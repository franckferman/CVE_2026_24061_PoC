# CVE-2026-24061 Telnet Root Exploit & Scanner

A robust, multithreaded Python scanner for the **CVE-2026-24061** vulnerability in GNU InetUtils (telnetd).  
This vulnerability allows an unauthenticated attacker to gain a root shell by injecting the `USER` environment variable with the value `-f root` during the Telnet protocol handshake.

## Features
- **Single Script**: All-in-one standalone script for easy deployment.
- **Native Implementation**: Fully implements the RFC 1572 `NEW-ENVIRON` negotiation in Python (no external dependencies beyond `netaddr`).
- **Multithreading**: High-performance scanning using `ThreadPoolExecutor`.
- **Target Flexibility**: Supports single IP, CIDR notation (e.g., `10.0.0.0/24`), or file input.
- **Reporting**: Colored console output and optional CSV file logging.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python cve_2026_24061_scanner.py -t 192.168.1.1
```

### Mass Scan (CIDR)
```bash
python cve_2026_24061_scanner.py -t 192.168.1.0/24 -T 50
```

### File Input
```bash
python cve_2026_24061_scanner.py -f targets.txt -o results.csv
```

## Disclaimer
This tool is intended for **authorized security auditing** and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The authors accept no liability for misuse.
