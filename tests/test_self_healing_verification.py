import os
import sys
import time
import socket
import subprocess
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "dashboard"))
import app

def get_honeypot_pids():
    """Finds PIDs listening on port 2222 on Windows."""
    pids = []
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Get-NetTCPConnection -LocalPort 2222 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess"],
            text=True
        )
        for line in output.splitlines():
            line = line.strip()
            if line.isdigit() and int(line) > 0:
                pids.append(int(line))
    except Exception:
        pass
    return list(set(pids))

def kill_honeypot_processes():
    """Safely terminates only processes listening on port 2222."""
    pids = get_honeypot_pids()
    for pid in pids:
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    time.sleep(1)

def run_self_healing_tests():
    print("==================================================================")
    print("      HONEYTRAP GENUINE SELF-HEALING TEST & BENCHMARK SUITE       ")
    print("==================================================================")

    cowrie_log = os.path.join(PROJECT_ROOT, "dashboard", "data", "cowrie.json")
    cowrie_backup = os.path.join(PROJECT_ROOT, "dashboard", "data", "cowrie_test_guard.json")
    if os.path.exists(cowrie_log):
        with open(cowrie_log, "r", encoding="utf-8") as f:
            saved_cowrie = f.read()

    try:
        # -----------------------------------------------------------------
        # TEST 1: Health check function detects active honeypot
        # -----------------------------------------------------------------
        print("\n--- TEST 1: Health-check while honeypot is running ---")
        if not app.is_honeypot_alive():
            print("[*] Starting honeypot for initial test...")
            app.start_honeypot_service()
            time.sleep(1)

        assert app.is_honeypot_alive(), "Honeypot should be alive on 127.0.0.1:2222!"
        initial_pids = get_honeypot_pids()
        print(f"[+] Honeypot verified online on 127.0.0.1:2222 (PID: {initial_pids})")

        with app.app.test_client() as client:
            status = client.get("/api/status").get_json()
            assert status.get("honeypot_alive") is True
            assert status.get("state") == "ACTIVE"
            print(f"✓ TEST 1 PASSED: Health-check reports port 2222 alive, state='ACTIVE'.")

        # -----------------------------------------------------------------
        # TEST 2: Self-healing when already running (no duplicate process)
        # -----------------------------------------------------------------
        print("\n--- TEST 2: Trigger healing while already running (duplicate prevention) ---")
        with app.app.test_client() as client:
            heal_resp = client.post("/api/trigger-healing")
            assert heal_resp.status_code == 200
            heal_data = heal_resp.get_json()
            assert heal_data.get("recovery_status") == "HEALED"
            assert heal_data.get("action") == "ALREADY_ACTIVE"
            assert heal_data.get("port_verified") is True

            pids_after_heal = get_honeypot_pids()
            assert len(pids_after_heal) == 1, f"Expected exactly 1 process, found: {pids_after_heal}"
            print(f"✓ TEST 2 PASSED: Reported HEALED (action='ALREADY_ACTIVE'), no duplicate process spawned.")

        # -----------------------------------------------------------------
        # TEST 3: Stop honeypot -> Detection -> Recovery -> Port verification
        # -----------------------------------------------------------------
        print("\n--- TEST 3: Honeypot stopped -> Detection -> Automatic Recovery ---")
        print("[*] Stopping honeypot process...")
        kill_honeypot_processes()
        assert not app.is_honeypot_alive(), "Port 2222 should be closed after kill!"
        print("[+] Verified port 2222 is closed.")

        with app.app.test_client() as client:
            # 3a. Check detection of stopped service
            status_stopped = client.get("/api/status").get_json()
            assert status_stopped.get("honeypot_alive") is False
            assert status_stopped.get("state") == "SERVICE_STOPPED"
            print(f"[+] System detected stopped honeypot: state='{status_stopped.get('state')}'")

            # 3b. Trigger recovery
            print("[*] Calling /api/trigger-healing to recover...")
            recovery_resp = client.post("/api/trigger-healing")
            recovery_data = recovery_resp.get_json()
            
            assert recovery_resp.status_code == 200
            assert recovery_data.get("recovery_status") == "HEALED"
            assert recovery_data.get("action") == "RESTARTED"
            assert recovery_data.get("port_verified") is True
            print(f"[+] Recovery response: status='{recovery_data.get('recovery_status')}', action='{recovery_data.get('action')}'")

            # 3c. Verify port is alive again
            assert app.is_honeypot_alive(), "Port 2222 should be active after recovery!"
            new_pids = get_honeypot_pids()
            print(f"[+] Port 2222 verified listening again with new PID: {new_pids}")

            # 3d. Check status.json updated with recovery info
            status_healed = client.get("/api/status").get_json()
            assert status_healed.get("state") == "ACTIVE"
            assert status_healed.get("recovery_status") == "HEALED"
            assert status_healed.get("honeypot_alive") is True
            print(f"✓ TEST 3 PASSED: Stopped service detected, restarted, port 2222 verified, status recorded.")

        # -----------------------------------------------------------------
        # TEST 4: Trigger healing again to re-verify duplicate prevention
        # -----------------------------------------------------------------
        print("\n--- TEST 4: Trigger healing again (re-check duplicate prevention) ---")
        with app.app.test_client() as client:
            heal_resp2 = client.post("/api/trigger-healing")
            heal_data2 = heal_resp2.get_json()
            assert heal_data2.get("recovery_status") == "HEALED"
            assert heal_data2.get("action") == "ALREADY_ACTIVE"
            pids_now = get_honeypot_pids()
            assert len(pids_now) == 1, f"Expected 1 process, found {pids_now}"
            print(f"✓ TEST 4 PASSED: Honeypot remains single process ({pids_now}), no duplicates.")

        # -----------------------------------------------------------------
        # TEST 5: Failure handling (Never report fictional success)
        # -----------------------------------------------------------------
        print("\n--- TEST 5: Failure handling when recovery cannot start ---")
        # Temporarily point HONEYPOT_SCRIPT to an invalid path to simulate recovery failure
        original_script = app.HONEYPOT_SCRIPT
        app.HONEYPOT_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "non_existent_service.py")

        kill_honeypot_processes()
        assert not app.is_honeypot_alive(), "Port 2222 should be closed!"

        with app.app.test_client() as client:
            fail_resp = client.post("/api/trigger-healing")
            fail_data = fail_resp.get_json()
            assert fail_data.get("recovery_status") == "HEALING_FAILED"
            assert fail_data.get("port_verified") is False
            print(f"[+] Failed recovery response: recovery_status='{fail_data.get('recovery_status')}'")

            # Check status reflects failure truthfully
            status_failed = client.get("/api/status").get_json()
            assert status_failed.get("state") == "HEALING_FAILED"
            assert status_failed.get("recovery_status") == "HEALING_FAILED"
            assert "FAILED" in status_failed.get("status_text")
            print(f"✓ TEST 5 PASSED: Truthful failure handling verified. Never reported fictional success.")

        # Restore original script and recover service
        app.HONEYPOT_SCRIPT = original_script
        print("\n[*] Restoring honeypot service...")
        app.start_honeypot_service()
        time.sleep(1)
        assert app.is_honeypot_alive(), "Honeypot should be running again."
        print(f"[+] Restored honeypot on port 2222 (PID: {get_honeypot_pids()})")

        print("\n==================================================================")
        print("🎉 ALL 5 SELF-HEALING & RECOVERY TESTS PASSED SUCCESSFULLY!")
        print("==================================================================")

    finally:
        # Restore cowrie log content
        if saved_cowrie and os.path.exists(cowrie_log):
            with open(cowrie_log, "w", encoding="utf-8") as f:
                f.write(saved_cowrie)

if __name__ == "__main__":
    run_self_healing_tests()
