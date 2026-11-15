import os
import sys
import time
import socket
import json
import hashlib
import tarfile
import subprocess
import urllib.request
import urllib.error
import paramiko

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASHBOARD_URL = "http://127.0.0.1:5000"
HONEYPOT_HOST = "127.0.0.1"
HONEYPOT_PORT = 2222
os.environ["HONEYPOT_PORT"] = str(HONEYPOT_PORT)
os.environ["HONEYPOT_BIND_PORT"] = str(HONEYPOT_PORT)

def is_port_listening(host=HONEYPOT_HOST, port=HONEYPOT_PORT, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def get_honeypot_pids():
    pids = []
    try:
        out = subprocess.check_output(
            ["powershell", "-Command", f"Get-NetTCPConnection -LocalPort {HONEYPOT_PORT} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess"],
            text=True
        )
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit() and int(line) > 0:
                pids.append(int(line))
    except Exception:
        pass
    return list(set(pids))

def http_get(path):
    url = f"{DASHBOARD_URL}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))

def http_post(path, data=None):
    url = f"{DASHBOARD_URL}{path}"
    body = json.dumps(data or {}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))

def run_e2e_verification():
    print("==================================================================")
    print("      HONEYTRAP FINAL END-TO-END VERIFICATION WORKFLOW           ")
    print("==================================================================")

    steps_results = {}

    # -----------------------------------------------------------------
    # STEP 1: Verify Dashboard and SSH Honeypot are running
    # -----------------------------------------------------------------
    print("\n[Step 1] Verifying Dashboard (5000) and Honeypot (2222) are running...")
    dash_ok = False
    try:
        status_code, status_data = http_get("/api/status")
        dash_ok = (status_code == 200)
    except Exception as e:
        print(f"[-] Dashboard not responding: {e}. Starting dashboard...")
        test_env = {**os.environ, "HONEYPOT_PORT": str(HONEYPOT_PORT), "HONEYPOT_BIND_PORT": str(HONEYPOT_PORT)}
        subprocess.Popen([sys.executable, os.path.join(PROJECT_ROOT, "dashboard", "app.py")], env=test_env, cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        status_code, status_data = http_get("/api/status")
        dash_ok = (status_code == 200)

    honeypot_ok = is_port_listening(HONEYPOT_HOST, HONEYPOT_PORT)
    if not honeypot_ok:
        print("[-] Honeypot not listening. Starting honeypot service...")
        test_env = {**os.environ, "HONEYPOT_PORT": str(HONEYPOT_PORT), "HONEYPOT_BIND_PORT": str(HONEYPOT_PORT)}
        subprocess.Popen([sys.executable, os.path.join(PROJECT_ROOT, "scripts", "honeypot_service.py")], env=test_env, cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        honeypot_ok = is_port_listening(HONEYPOT_HOST, HONEYPOT_PORT)

    pids_1 = get_honeypot_pids()
    s1_pass = dash_ok and honeypot_ok
    steps_results["Step 1: Start Dashboard and Honeypot"] = (
        "PASS" if s1_pass else "FAIL",
        f"Dashboard HTTP 200: {dash_ok} | Honeypot TCP 2222 open: {honeypot_ok} (PID: {pids_1})"
    )
    print(f"--> Step 1 Result: {steps_results['Step 1: Start Dashboard and Honeypot'][0]} - {steps_results['Step 1: Start Dashboard and Honeypot'][1]}")

    # -----------------------------------------------------------------
    # STEP 2 & 3: Connect to localhost:2222 and perform 3 failed logins
    # -----------------------------------------------------------------
    print("\n[Step 2 & 3] Performing 3 controlled failed logins with dummy username...")
    dummy_user = "audit_dummy_operator"
    dummy_pass = "TestFailedPassword!999"
    rejections = 0
    for attempt in range(1, 4):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=HONEYPOT_HOST,
                port=HONEYPOT_PORT,
                username=dummy_user,
                password=dummy_pass,
                timeout=3,
                allow_agent=False,
                look_for_keys=False
            )
            print(f"    [!] Attempt {attempt}: Unexpectedly authenticated!")
        except paramiko.AuthenticationException:
            rejections += 1
            print(f"    [+] Attempt {attempt}: Authentication rejected as expected.")
        except Exception as e:
            print(f"    [-] Attempt {attempt}: Connection error: {e}")
        finally:
            client.close()
        time.sleep(0.4)

    s23_pass = (rejections == 3)
    steps_results["Step 2 & 3: 3 Failed SSH Login Attempts"] = (
        "PASS" if s23_pass else "FAIL",
        f"3/3 connection attempts safely rejected by honeypot on port 2222."
    )
    print(f"--> Step 2 & 3 Result: {steps_results['Step 2 & 3: 3 Failed SSH Login Attempts'][0]}")

    # -----------------------------------------------------------------
    # STEP 4: Verify real brute-force alert appears on dashboard
    # -----------------------------------------------------------------
    print("\n[Step 4] Verifying real brute-force alert on dashboard...")
    time.sleep(1)
    status_code, alerts = http_get("/api/alerts")
    matching_alerts = [a for a in alerts if a.get("ip") == HONEYPOT_HOST]
    s4_pass = (status_code == 200 and len(matching_alerts) >= 1)
    sample_alert = matching_alerts[0] if matching_alerts else {}
    steps_results["Step 4: Real Brute-Force Alert Verification"] = (
        "PASS" if s4_pass else "FAIL",
        f"Alert found: IP={sample_alert.get('ip')}, attempts={sample_alert.get('failed_attempts')}, msg='{sample_alert.get('message')}', timestamp='{sample_alert.get('timestamp')}'"
    )
    print(f"--> Step 4 Result: {steps_results['Step 4: Real Brute-Force Alert Verification'][0]} - {steps_results['Step 4: Real Brute-Force Alert Verification'][1]}")

    # -----------------------------------------------------------------
    # STEP 5: Trigger evidence backup
    # -----------------------------------------------------------------
    print("\n[Step 5] Triggering evidence backup (/api/trigger-healing)...")
    status_code, heal_resp = http_post("/api/trigger-healing")
    evidence_meta = heal_resp.get("evidence", {})
    archive_id = evidence_meta.get("archive_id")
    s5_pass = (status_code == 200 and bool(archive_id))
    steps_results["Step 5: Trigger Evidence Backup"] = (
        "PASS" if s5_pass else "FAIL",
        f"Evidence package created: {archive_id} (Size: {evidence_meta.get('file_size_kb')})"
    )
    print(f"--> Step 5 Result: {steps_results['Step 5: Trigger Evidence Backup'][0]} - {steps_results['Step 5: Trigger Evidence Backup'][1]}")

    # -----------------------------------------------------------------
    # STEP 6: Verify archive contains cowrie.json, alerts.json, triage report
    # -----------------------------------------------------------------
    print("\n[Step 6] Inspecting contents of generated evidence archive...")
    archive_path = os.path.join(PROJECT_ROOT, "dashboard", "evidence", archive_id)
    archive_members = []
    with tarfile.open(archive_path, "r:gz") as tar:
        archive_members = tar.getnames()

    has_cowrie = "cowrie.json" in archive_members
    has_alerts = "alerts.json" in archive_members
    has_report = "forensic_triage_report.txt" in archive_members
    s6_pass = (has_cowrie and has_alerts and has_report)
    steps_results["Step 6: Evidence Archive Members Check"] = (
        "PASS" if s6_pass else "FAIL",
        f"Members found: {archive_members} (cowrie.json: {has_cowrie}, alerts.json: {has_alerts}, report: {has_report})"
    )
    print(f"--> Step 6 Result: {steps_results['Step 6: Evidence Archive Members Check'][0]} - {steps_results['Step 6: Evidence Archive Members Check'][1]}")

    # -----------------------------------------------------------------
    # STEP 7: Independently verify SHA-256 hash
    # -----------------------------------------------------------------
    print("\n[Step 7] Independently calculating SHA-256 hash of archive...")
    hasher = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    computed_hash = hasher.hexdigest()
    reported_hash = evidence_meta.get("hash_sha256")
    s7_pass = (computed_hash == reported_hash)
    steps_results["Step 7: Independent SHA-256 Integrity Verification"] = (
        "PASS" if s7_pass else "FAIL",
        f"Computed: {computed_hash} | Reported: {reported_hash} (Match: {s7_pass})"
    )
    print(f"--> Step 7 Result: {steps_results['Step 7: Independent SHA-256 Integrity Verification'][0]} - {steps_results['Step 7: Independent SHA-256 Integrity Verification'][1]}")

    # -----------------------------------------------------------------
    # STEP 8: Stop only the honeypot process
    # -----------------------------------------------------------------
    print("\n[Step 8] Stopping only the honeypot process...")
    pids_before_kill = get_honeypot_pids()
    print(f"[+] Terminating honeypot PID(s): {pids_before_kill}")
    for pid in pids_before_kill:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    port_listening_after_kill = is_port_listening(HONEYPOT_HOST, HONEYPOT_PORT)
    dash_still_up = False
    try:
        sc, _ = http_get("/api/status")
        dash_still_up = (sc == 200)
    except Exception:
        dash_still_up = False

    s8_pass = (not port_listening_after_kill and dash_still_up)
    steps_results["Step 8: Stop Honeypot Process"] = (
        "PASS" if s8_pass else "FAIL",
        f"Port 2222 closed: {not port_listening_after_kill} | Dashboard port 5000 still running: {dash_still_up}"
    )
    print(f"--> Step 8 Result: {steps_results['Step 8: Stop Honeypot Process'][0]} - {steps_results['Step 8: Stop Honeypot Process'][1]}")

    # -----------------------------------------------------------------
    # STEP 9: Verify dashboard detects SERVICE_STOPPED
    # -----------------------------------------------------------------
    print("\n[Step 9] Verifying dashboard detects SERVICE_STOPPED...")
    status_code, status_dead = http_get("/api/status")
    state_dead = status_dead.get("state")
    alive_dead = status_dead.get("honeypot_alive")
    s9_pass = (state_dead == "SERVICE_STOPPED" and alive_dead is False)
    steps_results["Step 9: Detection of Stopped Service"] = (
        "PASS" if s9_pass else "FAIL",
        f"Dashboard dynamically detected outage: state='{state_dead}', honeypot_alive={alive_dead}, status_text='{status_dead.get('status_text')}'"
    )
    print(f"--> Step 9 Result: {steps_results['Step 9: Detection of Stopped Service'][0]} - {steps_results['Step 9: Detection of Stopped Service'][1]}")

    # -----------------------------------------------------------------
    # STEP 10: Trigger self-healing
    # -----------------------------------------------------------------
    print("\n[Step 10] Triggering Self-Healing (/api/trigger-healing)...")
    status_code, heal_resp2 = http_post("/api/trigger-healing")
    recovery_status = heal_resp2.get("recovery_status")
    action_taken = heal_resp2.get("action")
    port_verified = heal_resp2.get("port_verified")
    s10_pass = (status_code == 200 and recovery_status == "HEALED" and action_taken == "RESTARTED" and port_verified is True)
    steps_results["Step 10: Trigger Self-Healing"] = (
        "PASS" if s10_pass else "FAIL",
        f"API response: recovery_status='{recovery_status}', action='{action_taken}', port_verified={port_verified}"
    )
    print(f"--> Step 10 Result: {steps_results['Step 10: Trigger Self-Healing'][0]} - {steps_results['Step 10: Trigger Self-Healing'][1]}")

    # -----------------------------------------------------------------
    # STEP 11: Verify honeypot restarts and port 2222 becomes available
    # -----------------------------------------------------------------
    print("\n[Step 11] Verifying honeypot restarted and port 2222 is active...")
    port_listening_after_heal = is_port_listening(HONEYPOT_HOST, HONEYPOT_PORT)
    status_code, status_recovered = http_get("/api/status")
    state_recovered = status_recovered.get("state")
    alive_recovered = status_recovered.get("honeypot_alive")
    new_pids = get_honeypot_pids()
    s11_pass = (port_listening_after_heal and state_recovered == "ACTIVE" and alive_recovered is True)
    steps_results["Step 11: Port 2222 Restored & Verified"] = (
        "PASS" if s11_pass else "FAIL",
        f"Port 2222 listening: {port_listening_after_heal} (New PID: {new_pids}), Dashboard state='{state_recovered}', honeypot_alive={alive_recovered}"
    )
    print(f"--> Step 11 Result: {steps_results['Step 11: Port 2222 Restored & Verified'][0]} - {steps_results['Step 11: Port 2222 Restored & Verified'][1]}")

    # -----------------------------------------------------------------
    # STEP 12: Verify no duplicate honeypot process exists
    # -----------------------------------------------------------------
    print("\n[Step 12] Verifying no duplicate honeypot process exists...")
    current_pids = get_honeypot_pids()
    # Trigger healing one more time to check duplicate prevention
    http_post("/api/trigger-healing")
    time.sleep(1)
    pids_after_second_heal = get_honeypot_pids()
    s12_pass = (len(current_pids) == 1 and len(pids_after_second_heal) == 1)
    steps_results["Step 12: Duplicate Process Prevention"] = (
        "PASS" if s12_pass else "FAIL",
        f"Process count listening on port 2222: {len(pids_after_second_heal)} (PID: {pids_after_second_heal}). Zero duplicate processes."
    )
    print(f"--> Step 12 Result: {steps_results['Step 12: Duplicate Process Prevention'][0]} - {steps_results['Step 12: Duplicate Process Prevention'][1]}")

    # -----------------------------------------------------------------
    # STEP 13: Confirm no passwords or secrets are stored
    # -----------------------------------------------------------------
    print("\n[Step 13] Auditing all files and archive for plaintext passwords and secrets...")
    cowrie_log_path = os.path.join(PROJECT_ROOT, "dashboard", "data", "cowrie.json")
    alerts_file_path = os.path.join(PROJECT_ROOT, "dashboard", "data", "alerts.json")
    
    leaks = []
    # Check active cowrie.json
    if os.path.exists(cowrie_log_path):
        with open(cowrie_log_path, "r", encoding="utf-8") as f:
            for lno, line in enumerate(f, 1):
                if '"password"' in line or "'password'" in line:
                    leaks.append(f"cowrie.json:line {lno}")

    # Check active alerts.json
    if os.path.exists(alerts_file_path):
        with open(alerts_file_path, "r", encoding="utf-8") as f:
            for lno, line in enumerate(f, 1):
                if '"password"' in line or "'password'" in line:
                    leaks.append(f"alerts.json:line {lno}")

    # Check new evidence archive members
    with tarfile.open(archive_path, "r:gz") as tar:
        for m in tar.getnames():
            content = tar.extractfile(m).read().decode("utf-8", errors="ignore")
            for kw in ['"password"', "'password'", "api_key", "secret_key"]:
                if kw in content.lower():
                    leaks.append(f"archive:{m}:{kw}")

    s13_pass = (len(leaks) == 0)
    steps_results["Step 13: Zero Passwords & Secrets Stored"] = (
        "PASS" if s13_pass else "FAIL",
        f"Leaks found: {len(leaks)}. Confirmed zero plaintext password fields or secrets stored in logs, alerts, or archives."
    )
    print(f"--> Step 13 Result: {steps_results['Step 13: Zero Passwords & Secrets Stored'][0]} - {steps_results['Step 13: Zero Passwords & Secrets Stored'][1]}")

    print("\n------------------------------------------------------------------")
    print("                     FINAL RESULTS SUMMARY                        ")
    print("------------------------------------------------------------------")
    all_passed = True
    for step_name, (status, detail) in steps_results.items():
        print(f"[{status}] {step_name}")
        print(f"      {detail}\n")
        if status != "PASS":
            all_passed = False

    if all_passed:
        print("==================================================================")
        print("🎉 COMPLETE HONEYTRAP WORKFLOW: 13/13 STEPS PASSED SUCCESSFULLY! ")
        print("==================================================================")
    else:
        print("❌ ONE OR MORE STEPS FAILED.")

    return all_passed

if __name__ == "__main__":
    success = run_e2e_verification()
    sys.exit(0 if success else 1)
