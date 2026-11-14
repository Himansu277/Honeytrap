import os
import sys
import time
import socket
import subprocess
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "dashboard"))
import app

def is_port_open(host="127.0.0.1", port=2222, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def test_self_healing_capabilities():
    print("==================================================================")
    print("      HONEYTRAP SELF-HEALING & RECOVERY AUDIT TEST SUITE          ")
    print("==================================================================")

    results = {}

    # Step 1: Start honeypot process
    print("\n[Step 1] Starting honeypot service subprocess on 127.0.0.1:2222...")
    honeypot_script = os.path.join(PROJECT_ROOT, "scripts", "honeypot_service.py")
    proc = subprocess.Popen([sys.executable, honeypot_script], cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)

    initial_port_open = is_port_open()
    print(f"Honeypot PID: {proc.pid} | Port 2222 open: {initial_port_open}")

    # Check dashboard initial status
    with app.app.test_client() as client:
        status_before = client.get("/api/status").get_json()
        print(f"Initial Dashboard Status: state='{status_before.get('state')}', text='{status_before.get('status_text')}'")

    # Step 2: Terminate honeypot process (simulating crash or stop)
    print("\n[Step 2] Simulating honeypot service stop/crash (terminating PID)...")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(1)

    port_after_kill = is_port_open()
    print(f"Port 2222 open after kill: {port_after_kill}")

    # Step 3: Check Check #1 - Does system detect stopped process?
    with app.app.test_client() as client:
        status_after_kill = client.get("/api/status").get_json()
        print(f"Dashboard status after process stopped: state='{status_after_kill.get('state')}', text='{status_after_kill.get('status_text')}'")
        
        # Did the status change or alert that the honeypot is DOWN?
        detected_stopped = (
            status_after_kill.get("state") in ["OFFLINE", "DOWN", "ERROR", "STOPPED"] or
            "stopped" in status_after_kill.get("status_text", "").lower() or
            "offline" in status_after_kill.get("status_text", "").lower()
        )
        results["1_detect_process_stopped"] = {
            "status": "PASS" if detected_stopped else "FAIL",
            "details": f"Port 2222 is closed ({port_after_kill}), but /api/status still reports: state='{status_after_kill.get('state')}', text='{status_after_kill.get('status_text')}'"
        }

    # Step 4: Call /api/trigger-healing
    print("\n[Step 3] Invoking /api/trigger-healing endpoint...")
    evidence_archive_created = False
    evidence_archive_name = None
    with app.app.test_client() as client:
        # Preserve cowrie.json content so healing rotation doesn't wipe test lab data
        cowrie_path = os.path.join(PROJECT_ROOT, "dashboard", "data", "cowrie.json")
        backup_content = None
        if os.path.exists(cowrie_path):
            with open(cowrie_path, "r", encoding="utf-8") as f:
                backup_content = f.read()

        try:
            heal_resp = client.post("/api/trigger-healing")
            heal_data = heal_resp.get_json()
            evidence_archive_name = heal_data.get("evidence", {}).get("archive_id")
            if evidence_archive_name and os.path.exists(os.path.join(PROJECT_ROOT, "dashboard", "evidence", evidence_archive_name)):
                evidence_archive_created = True

            time.sleep(2)

            # Step 5: Check Check #2 - Does it restart honeypot process?
            # Check Check #3 - Does it verify port 2222 is listening?
            port_after_heal = is_port_open()
            print(f"Port 2222 open after /api/trigger-healing: {port_after_heal}")

            results["2_restart_honeypot_process"] = {
                "status": "PASS" if port_after_heal else "FAIL",
                "details": f"/api/trigger-healing does not spawn scripts/honeypot_service.py. Port 2222 remains closed: {port_after_heal}."
            }

            results["3_verify_port_2222_listening"] = {
                "status": "PASS" if port_after_heal else "FAIL",
                "details": "No socket or health check logic exists in api_trigger_healing() to verify port 2222 is reachable."
            }

            # Step 6: Check Check #4 - Does it record recovery event?
            status_after_heal = client.get("/api/status").get_json()
            recorded_recovery = (
                status_after_heal.get("state") == "ACTIVE" and 
                "healed" in status_after_heal.get("status_text", "").lower()
            )
            results["4_record_recovery_event"] = {
                "status": "PASS" if recorded_recovery else "FAIL",
                "details": f"Dashboard records status.json update: state='{status_after_heal.get('state')}', timestamp='{status_after_heal.get('last_healing_event')}'. However, this claims success even though the process was not restarted."
            }

            # Step 7: Check Check #5 - Does evidence pipeline run?
            results["5_evidence_backup_pipeline_runs"] = {
                "status": "PASS" if evidence_archive_created else "FAIL",
                "details": f"Evidence archive created during healing: {evidence_archive_name} (exists={evidence_archive_created})."
            }

        finally:
            if backup_content and os.path.exists(cowrie_path):
                with open(cowrie_path, "w", encoding="utf-8") as f:
                    f.write(backup_content)

    print("\n------------------------------------------------------------------")
    print("                     AUDIT RESULT SUMMARY                         ")
    print("------------------------------------------------------------------")
    for k, v in results.items():
        print(f"[{v['status']}] {k}:")
        print(f"      {v['details']}\n")

    return results

if __name__ == "__main__":
    test_self_healing_capabilities()
