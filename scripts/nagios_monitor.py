#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Active Nagios Monitoring Engine (nagios_monitor.py)
# Executes configured Nagios plugins, maintains nagios.log and status.dat,
# and triggers event handlers on service failure or intrusion detection.
# ==============================================================================

import os
import sys
import time
import subprocess
import shutil
import argparse
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
NAGIOS_DIR = os.path.join(PROJECT_ROOT, "nagios")
PLUGINS_DIR = os.path.join(NAGIOS_DIR, "plugins")
EVENTHANDLERS_DIR = os.path.join(NAGIOS_DIR, "eventhandlers")
LOG_FILE = os.path.join(NAGIOS_DIR, "nagios.log")
STATUS_FILE = os.path.join(NAGIOS_DIR, "status.dat")
EVENT_LOG_FILE = os.path.join(NAGIOS_DIR, "nagios-eventhandler.log")

# Exit Code Constants (Standard Nagios Plugin API)
STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

STATE_NAMES = {
    STATE_OK: "OK",
    STATE_WARNING: "WARNING",
    STATE_CRITICAL: "CRITICAL",
    STATE_UNKNOWN: "UNKNOWN"
}

def find_bash_executable():
    """Locates bash on Windows (Git Bash) or Linux standard path."""
    for candidate in [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Git\bin\bash.exe",
        "/bin/bash",
        "/usr/bin/bash",
        shutil.which("bash")
    ]:
        if candidate and os.path.isfile(candidate) and "System32" not in candidate:
            return candidate
    return None

def get_services_definition():
    """Returns active monitored services configuration matching nagios/conf.d/services.cfg."""
    bash_bin = find_bash_executable()
    cowrie_log_path = os.path.join(PROJECT_ROOT, "dashboard", "data", "cowrie.json")
    
    # Define execution commands for services
    services = [
        {
            "name": "HoneyTrap_Dashboard_Health",
            "host": "localhost",
            "host_address": "127.0.0.1",
            "description": "Monitors HoneyTrap Flask Threat Intelligence Dashboard on port 5000",
            "cmd": [sys.executable, os.path.join(PLUGINS_DIR, "check_dashboard.py"), "http://127.0.0.1:5000/api/status"],
            "event_handler": None,
            "event_handler_enabled": False
        },
        {
            "name": "HoneyTrap_Honeypot_Health",
            "host": "localhost",
            "host_address": "127.0.0.1",
            "description": "Monitors Paramiko SSH Honeypot port 2222 availability and SSH banner",
            "cmd": [sys.executable, os.path.join(PLUGINS_DIR, "check_honeypot.py"), "127.0.0.1", "2222"],
            "event_handler": os.path.join(EVENTHANDLERS_DIR, "handle_honeypot_attack.sh"),
            "event_handler_enabled": True
        },
        {
            "name": "HoneyTrap_Intrusion_Activity",
            "host": "localhost",
            "host_address": "127.0.0.1",
            "description": "Monitors cowrie.json for real-time intrusion attempts",
            "cmd": [bash_bin, os.path.join(PLUGINS_DIR, "check_cowrie_activity.sh"), cowrie_log_path] if bash_bin else None,
            "event_handler": os.path.join(EVENTHANDLERS_DIR, "handle_honeypot_attack.sh"),
            "event_handler_enabled": True
        }
    ]
    return services

def run_service_check(service):
    """Executes a single Nagios plugin check and returns (state_code, output, duration_ms)."""
    cmd = service.get("cmd")
    if not cmd:
        return STATE_UNKNOWN, "UNKNOWN - Check command or interpreter not configured", 0.0

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            cwd=PROJECT_ROOT
        )
        duration_ms = (time.time() - t0) * 1000.0
        output = (proc.stdout or proc.stderr or "").strip()
        state = proc.returncode
        if state not in STATE_NAMES:
            state = STATE_UNKNOWN
        return state, output, duration_ms
    except subprocess.TimeoutExpired:
        duration_ms = (time.time() - t0) * 1000.0
        return STATE_CRITICAL, f"CRITICAL - Plugin check timed out after 15s", duration_ms
    except Exception as e:
        duration_ms = (time.time() - t0) * 1000.0
        return STATE_UNKNOWN, f"UNKNOWN - Execution error: {e}", duration_ms

def trigger_event_handler(service, state_code, state_type="HARD", attempt=1):
    """Executes the service event handler when configured."""
    handler_script = service.get("event_handler")
    if not handler_script or not service.get("event_handler_enabled"):
        return None

    state_name = STATE_NAMES.get(state_code, "UNKNOWN")
    host_addr = service.get("host_address", "127.0.0.1")
    bash_bin = find_bash_executable()

    if not bash_bin or not os.path.exists(handler_script):
        return f"Event handler script or bash not found: {handler_script}"

    cmd = [bash_bin, handler_script, state_name, state_type, str(attempt), host_addr]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            cwd=PROJECT_ROOT
        )
        out = (proc.stdout or proc.stderr or "").strip()
        return f"EventHandler ({state_name}) exited with {proc.returncode}: {out}"
    except Exception as e:
        return f"EventHandler execution error: {e}"

def append_nagios_log(service, state_code, output, state_type="HARD", attempt=1):
    """Appends alert in standard Nagios Core log format to nagios/nagios.log."""
    ts = int(time.time())
    state_str = STATE_NAMES.get(state_code, "UNKNOWN")
    log_line = f"[{ts}] SERVICE ALERT: {service['host']};{service['name']};{state_str};{state_type};{attempt};{output}\n"
    
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def write_nagios_status(results):
    """Writes service states to nagios/status.dat matching Nagios Core status file schema."""
    ts = int(time.time())
    lines = [
        "########################################",
        "# NAGIOS STATUS FILE - HoneyTrap Core",
        f"# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "########################################\n",
        "info {",
        f"    created={ts}",
        "    version=4.4.6",
        "}\n"
    ]
    
    for r in results:
        svc = r["service"]
        code = r["state"]
        output = r["output"]
        lines.append("servicestatus {")
        lines.append(f"    host_name={svc['host']}")
        lines.append(f"    service_description={svc['name']}")
        lines.append(f"    current_state={code}")
        lines.append(f"    plugin_output={output}")
        lines.append(f"    last_check={ts}")
        lines.append(f"    has_been_checked=1")
        lines.append(f"    check_type=0")
        lines.append(f"    is_flapping=0")
        lines.append("}\n")

    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def display_results_table(results):
    """Formats check results into a clear Nagios operational report."""
    print("=" * 80)
    print("           HONEYTRAP - NAGIOS ACTIVE MONITORING REPORT")
    print(f" Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Node: localhost (127.0.0.1)")
    print("=" * 80)
    print(f"{'SERVICE':<30} {'STATUS':<10} {'TIME (ms)':<12} {'PLUGIN OUTPUT'}")
    print("-" * 80)
    
    for r in results:
        svc_name = r["service"]["name"]
        st_name = STATE_NAMES.get(r["state"], "UNKNOWN")
        st_badge = f"[{st_name}]"
        dur = f"{r['duration_ms']:.1f}ms"
        out_summary = r["output"].split("|")[0].strip()
        print(f"{svc_name:<30} {st_badge:<10} {dur:<12} {out_summary}")
        if r.get("event_handler_result"):
            print(f"  └─> [EVENT HANDLER]: {r['event_handler_result']}")

    print("=" * 80)
    print(f"Status file updated: {os.path.relpath(STATUS_FILE, PROJECT_ROOT)}")
    print(f"Nagios log updated  : {os.path.relpath(LOG_FILE, PROJECT_ROOT)}")
    print("=" * 80)

def run_monitoring_cycle(verbose=True):
    """Runs a single complete pass of all configured Nagios checks."""
    services = get_services_definition()
    results = []

    for svc in services:
        state, output, dur = run_service_check(svc)
        event_res = None
        
        # Trigger event handler if in CRITICAL state and configured
        if state == STATE_CRITICAL and svc.get("event_handler_enabled"):
            event_res = trigger_event_handler(svc, state)

        append_nagios_log(svc, state, output)
        results.append({
            "service": svc,
            "state": state,
            "output": output,
            "duration_ms": dur,
            "event_handler_result": event_res
        })

    write_nagios_status(results)
    if verbose:
        display_results_table(results)
    return results

def main():
    parser = argparse.ArgumentParser(description="HoneyTrap Active Nagios Monitoring Daemon")
    parser.add_argument("--once", action="store_true", help="Run a single audit check and exit")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in the background")
    parser.add_argument("--interval", type=int, default=10, help="Check interval in seconds (default: 10)")
    args = parser.parse_args()

    if args.daemon:
        print(f"[+] Starting Nagios Monitoring Daemon (Interval: {args.interval}s)...")
        try:
            while True:
                run_monitoring_cycle(verbose=True)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[-] Nagios Monitoring Daemon stopped.")
    else:
        # Default single pass
        run_monitoring_cycle(verbose=True)

if __name__ == "__main__":
    main()
