#!/usr/bin/env python3
"""
HoneyTrap - Nagios Plugin: check_honeypot.py
Checks HoneyTrap SSH Honeypot port (127.0.0.1:2222) availability and SSH banner.

Nagios Exit Codes:
  0 = OK       (Port accepting connections and returned SSH banner)
  1 = WARNING  (Port open but unexpected banner)
  2 = CRITICAL (Port closed, connection refused, or timeout)
  3 = UNKNOWN  (Invalid arguments or unexpected exception)
"""

import sys
import socket
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2222
EXPECTED_BANNER_SUBSTRING = "SSH"

def check_honeypot(host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=3.0):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        
        # Read SSH banner
        banner = ""
        try:
            raw_banner = s.recv(1024)
            banner = raw_banner.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        finally:
            s.close()

        perf_data = f"| time={elapsed_ms}ms;1500;3000;0;"

        if EXPECTED_BANNER_SUBSTRING in banner:
            print(f"OK - HoneyTrap SSH Honeypot listening on {host}:{port} ({banner}) {perf_data}")
            sys.exit(0)
        elif banner:
            print(f"WARNING - HoneyTrap port {port} open but unexpected banner: '{banner}' {perf_data}")
            sys.exit(1)
        else:
            print(f"OK - HoneyTrap port {port} accepting TCP connections (No banner sent) {perf_data}")
            sys.exit(0)

    except socket.timeout:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        print(f"CRITICAL - Connection Timeout ({timeout}s) to {host}:{port} | time={elapsed_ms}ms")
        sys.exit(2)
    except ConnectionRefusedError:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        print(f"CRITICAL - Connection Refused on {host}:{port} (Honeypot Service is DOWN) | time={elapsed_ms}ms")
        sys.exit(2)
    except Exception as e:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        print(f"CRITICAL - Cannot reach {host}:{port} ({e}) | time={elapsed_ms}ms")
        sys.exit(2)

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    p = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    check_honeypot(h, p)
