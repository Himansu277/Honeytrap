import sys
import os
import time
import json
import subprocess
import socket
import paramiko

# Add paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "dashboard"))

import app

def test_live_detection():
    print("[*] Starting end-to-end live SSH detection test...")

    # 1. Start honeypot service as a subprocess (main thread of new process)
    honeypot_script = os.path.join(PROJECT_ROOT, "scripts", "honeypot_service.py")
    proc = subprocess.Popen(
        [sys.executable, honeypot_script],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print(f"[*] Honeypot service started as PID {proc.pid}")
    
    # Wait for port 2222 to be open
    time.sleep(2)

    try:
        # 2. Perform 3 controlled failed SSH login attempts
        print("[*] Performing 3 controlled failed login attempts against honeypot on 127.0.0.1:2222...")
        for attempt in range(1, 4):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname="127.0.0.1",
                    port=2222,
                    username=f"audit_user_{attempt}",
                    password="ControlledTestPassword123!",
                    timeout=3,
                    allow_agent=False,
                    look_for_keys=False
                )
            except paramiko.AuthenticationException:
                print(f"    -> Attempt {attempt}: Authentication rejected as expected.")
            except Exception as e:
                print(f"    -> Attempt {attempt}: Connection exception ({e})")
            finally:
                client.close()
            time.sleep(0.5)

    finally:
        # 3. Stop honeypot service cleanly
        print("[*] Terminating honeypot process...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[*] Honeypot process stopped.")

    # 4. Check cowrie.json for genuine records
    events = app.parse_cowrie_logs()
    real_failed = [
        e for e in events 
        if e.get("eventid") == "cowrie.login.failed" and not e.get("simulation") and e.get("src_ip") == "127.0.0.1"
    ]
    print(f"[+] Total genuine 127.0.0.1 failed logins in cowrie.json: {len(real_failed)}")
    assert len(real_failed) >= 3, f"Expected at least 3 failed login attempts recorded, found {len(real_failed)}!"

    # 5. Run detection via Flask test client
    with app.app.test_client() as c:
        resp = c.get("/api/alerts")
        assert resp.status_code == 200
        alerts = resp.get_json()
        print(f"\n[+] /api/alerts returned {len(alerts)} alert(s):")
        for a in alerts:
            print(f"    - Alert ID: {a.get('alert_id')}")
            print(f"      IP: {a.get('ip')}")
            print(f"      Failed Attempts: {a.get('failed_attempts')}")
            print(f"      Timestamp: {a.get('timestamp')}")
            print(f"      Message: {a.get('message')}")
            assert a.get("ip") == "127.0.0.1"
            assert a.get("failed_attempts") >= 3
            assert "password" not in a

        # 6. Test deduplication - call /api/alerts again
        resp2 = c.get("/api/alerts")
        alerts2 = resp2.get_json()
        assert len(alerts2) == len(alerts), f"Deduplication failed: {len(alerts2)} != {len(alerts)}"
        print("[+] Deduplication verified: subsequent calls do not produce duplicate alerts.")

        # 7. Test simulation attack does not trigger alert
        initial_alert_count = len(alerts)
        sim_resp = c.post("/api/simulate-attack", json={"type": "brute_force"})
        assert sim_resp.status_code == 200
        print("[+] Triggered /api/simulate-attack (simulated attack injection).")

        resp3 = c.get("/api/alerts")
        alerts3 = resp3.get_json()
        assert len(alerts3) == initial_alert_count, "Simulation events generated an alert! They must be ignored."
        print("[+] Simulation isolation verified: simulation records correctly ignored.")

    print("\n=======================================================")
    print("🎉 ALL END-TO-END HONEYTRAP DETECTION CHECKS PASSED!")
    print("=======================================================")

if __name__ == "__main__":
    test_live_detection()
