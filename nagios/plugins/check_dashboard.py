#!/usr/bin/env python3
"""
HoneyTrap - Nagios Plugin: check_dashboard.py
Checks HoneyTrap Flask Dashboard availability, response time, and security state.

Nagios Exit Codes:
  0 = OK
  1 = WARNING (Service responding but reported UNDER_ATTACK or degraded)
  2 = CRITICAL (Service offline, connection refused, or HTTP 5xx error)
  3 = UNKNOWN  (Invalid arguments or unexpected exception)
"""

import sys
import time
import json
import urllib.request
import urllib.error

DEFAULT_URL = "http://127.0.0.1:5000/api/status"

def check_dashboard(url=DEFAULT_URL, timeout=4.0):
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Nagios-check_dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = round((time.time() - t0) * 1000, 2)
            status_code = resp.status
            if status_code != 200:
                print(f"CRITICAL - HTTP {status_code} returned by {url} | time={elapsed_ms}ms")
                sys.exit(2)

            data = json.loads(resp.read().decode("utf-8"))
            state = data.get("state", "UNKNOWN")
            status_text = data.get("status_text", "")
            perf_data = f"| time={elapsed_ms}ms;2000;4000;0;"

            if state == "ACTIVE":
                print(f"OK - HoneyTrap Dashboard online (State: ACTIVE, Response: {elapsed_ms}ms) - {status_text} {perf_data}")
                sys.exit(0)
            elif state == "UNDER_ATTACK":
                print(f"WARNING - HoneyTrap under active attack (State: UNDER_ATTACK, Response: {elapsed_ms}ms) - {status_text} {perf_data}")
                sys.exit(1)
            elif state in ["SERVICE_STOPPED", "HEALING_FAILED"]:
                print(f"CRITICAL - HoneyTrap Dashboard reports state: {state} - {status_text} {perf_data}")
                sys.exit(2)
            else:
                print(f"OK - HoneyTrap Dashboard running (State: {state}) {perf_data}")
                sys.exit(0)

    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        print(f"CRITICAL - HTTP Error {e.code}: {e.reason} | time={elapsed_ms}ms")
        sys.exit(2)
    except urllib.error.URLError as e:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        print(f"CRITICAL - Connection Refused / Unreachable ({e.reason}) | time={elapsed_ms}ms")
        sys.exit(2)
    except Exception as e:
        print(f"UNKNOWN - Check failed with exception: {e}")
        sys.exit(3)

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    check_dashboard(target_url)
