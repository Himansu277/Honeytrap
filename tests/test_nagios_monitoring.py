#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Nagios Active Monitoring Test Suite (test_nagios_monitoring.py)
# Verifies plugins, monitor engine, status.dat, nagios.log, and event handlers.
# ==============================================================================

import os
import sys
import time
import json
import socket
import subprocess

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
NAGIOS_DIR = os.path.join(PROJECT_ROOT, "nagios")
PLUGINS_DIR = os.path.join(NAGIOS_DIR, "plugins")
STATUS_FILE = os.path.join(NAGIOS_DIR, "status.dat")
LOG_FILE = os.path.join(NAGIOS_DIR, "nagios.log")
EVENT_LOG_FILE = os.path.join(NAGIOS_DIR, "nagios-eventhandler.log")

def is_port_listening(host="127.0.0.1", port=2222, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def ensure_services():
    """Ensures dashboard (5000) and honeypot (2222) are running and active for the test."""
    if not is_port_listening("127.0.0.1", 2222):
        print("  [Setup] Starting scripts/honeypot_service.py on port 2222...")
        subprocess.Popen([sys.executable, os.path.join(PROJECT_ROOT, "scripts", "honeypot_service.py")], cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            time.sleep(0.5)
            if is_port_listening("127.0.0.1", 2222):
                break

    if not is_port_listening("127.0.0.1", 5000):
        print("  [Setup] Starting dashboard/app.py on port 5000...")
        subprocess.Popen([sys.executable, os.path.join(PROJECT_ROOT, "dashboard", "app.py")], cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            time.sleep(0.5)
            if is_port_listening("127.0.0.1", 5000):
                break

    # Reset dashboard status to active if needed
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:5000/api/trigger-healing", data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception:
        pass

def test_nagios_system():
    print("==================================================================")
    print("        HONEYTRAP NAGIOS ACTIVE MONITORING TEST SUITE             ")
    print("==================================================================")

    ensure_services()

    # 1. Test check_dashboard.py directly
    print("\n[TEST 1] Testing check_dashboard.py plugin directly...")
    res = subprocess.run(
        [sys.executable, os.path.join(PLUGINS_DIR, "check_dashboard.py"), "http://127.0.0.1:5000/api/status"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=PROJECT_ROOT
    )
    print(f"  Exit code: {res.returncode}")
    print(f"  Output   : {res.stdout.strip()}")
    assert res.returncode == 0, f"Expected 0 (OK), got {res.returncode}"
    print("  -> PASS: check_dashboard.py returns OK (code 0)")

    # 2. Test check_honeypot.py directly
    print("\n[TEST 2] Testing check_honeypot.py plugin directly...")
    res = subprocess.run(
        [sys.executable, os.path.join(PLUGINS_DIR, "check_honeypot.py"), "127.0.0.1", "2222"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=PROJECT_ROOT
    )
    print(f"  Exit code: {res.returncode}")
    print(f"  Output   : {res.stdout.strip()}")
    assert res.returncode == 0, f"Expected 0 (OK), got {res.returncode}"
    print("  -> PASS: check_honeypot.py returns OK (code 0) with valid SSH banner")

    # 3. Test check_cowrie_activity.sh via monitor
    print("\n[TEST 3] Running full Nagios cycle via scripts/nagios_monitor.py --once...")
    res = subprocess.run(
        [sys.executable, os.path.join(PROJECT_ROOT, "scripts", "nagios_monitor.py"), "--once"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=PROJECT_ROOT
    )
    print(res.stdout)
    assert res.returncode == 0, "nagios_monitor.py returned non-zero exit code"
    print("  -> PASS: Nagios monitor cycle executed cleanly")

    # 4. Verify nagios/status.dat
    print("\n[TEST 4] Verifying nagios/status.dat structure and contents...")
    assert os.path.exists(STATUS_FILE), "status.dat does not exist"
    with open(STATUS_FILE, "r", encoding="utf-8") as f:
        status_content = f.read()
    assert "HoneyTrap_Dashboard_Health" in status_content
    assert "HoneyTrap_Honeypot_Health" in status_content
    assert "HoneyTrap_Intrusion_Activity" in status_content
    print("  -> PASS: nagios/status.dat correctly updated with all monitored services")

    # 5. Verify nagios/nagios.log
    print("\n[TEST 5] Verifying nagios/nagios.log alerts...")
    assert os.path.exists(LOG_FILE), "nagios.log does not exist"
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        log_content = f.read()
    assert "SERVICE ALERT: localhost;HoneyTrap_Dashboard_Health" in log_content
    assert "SERVICE ALERT: localhost;HoneyTrap_Honeypot_Health" in log_content
    assert "SERVICE ALERT: localhost;HoneyTrap_Intrusion_Activity" in log_content
    print("  -> PASS: nagios/nagios.log records valid standard Nagios Core alerts")

    # 6. Verify Event Handler execution log
    print("\n[TEST 6] Verifying nagios-eventhandler.log...")
    assert os.path.exists(EVENT_LOG_FILE), "nagios-eventhandler.log does not exist"
    with open(EVENT_LOG_FILE, "r", encoding="utf-8") as f:
        ev_content = f.read()
    assert "[Nagios-EventHandler] Triggered" in ev_content
    print("  -> PASS: Event handler execution logged and verified")

    print("\n==================================================================")
    print("     ALL NAGIOS ACTIVE MONITORING CHECKS PASSED (6/6)             ")
    print("==================================================================")

if __name__ == "__main__":
    test_nagios_system()
