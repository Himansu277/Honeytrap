import sys
import os
import json
import tempfile
import shutil
from datetime import datetime, timedelta

# Import detection from dashboard.app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard")))
import app

def run_tests():
    print("[+] Testing HoneyTrap SSH attack detection...")

    # Test 1: Verify current cowrie.json parsing
    events = app.parse_cowrie_logs()
    print(f"Total events in cowrie.json: {len(events)}")
    sim_count = sum(1 for e in events if e.get("simulation") is True)
    real_count = sum(1 for e in events if not e.get("simulation"))
    print(f"Simulated events: {sim_count}, Real events: {real_count}")

    # Temporary directory for alerts file
    temp_dir = tempfile.mkdtemp()
    temp_alert_file = os.path.join(temp_dir, "alerts.json")
    app.ALERT_FILE = temp_alert_file

    try:
        # Test 2: Check simulation filtering (3 failed logins marked simulation: True)
        test_sim_events = [
            {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "timestamp": "2026-11-13T10:00:00Z", "simulation": True},
            {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "timestamp": "2026-11-13T10:01:00Z", "simulation": True},
            {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "timestamp": "2026-11-13T10:02:00Z", "simulation": True},
        ]
        alerts = app.detect_brute_force_alerts(test_sim_events)
        assert len(alerts) == 0, f"Expected 0 alerts for simulation events, got {len(alerts)}"
        print("✓ Test 2 PASSED: Simulation records ignored.")

        # Test 3: Less than 3 failed attempts (e.g. 2 attempts) -> 0 alerts
        test_2_attempts = [
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.5", "timestamp": "2026-11-13T10:00:00Z", "simulation": False},
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.5", "timestamp": "2026-11-13T10:02:00Z", "simulation": False},
        ]
        alerts = app.detect_brute_force_alerts(test_2_attempts)
        assert len(alerts) == 0, f"Expected 0 alerts for 2 attempts, got {len(alerts)}"
        print("✓ Test 3 PASSED: Under 3 attempts generates 0 alerts.")

        # Test 4: Exactly 3 failed attempts within 5 minutes -> 1 alert
        test_3_attempts = [
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.5", "timestamp": "2026-11-13T10:00:00Z", "simulation": False},
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.5", "timestamp": "2026-11-13T10:02:00Z", "simulation": False},
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.5", "timestamp": "2026-11-13T10:04:00Z", "simulation": False},
        ]
        alerts = app.detect_brute_force_alerts(test_3_attempts)
        assert len(alerts) == 1, f"Expected 1 alert for 3 attempts, got {len(alerts)}"
        alert = alerts[0]
        assert alert["ip"] == "10.0.0.5", f"Expected ip 10.0.0.5, got {alert['ip']}"
        assert alert["failed_attempts"] == 3, f"Expected 3 attempts, got {alert['failed_attempts']}"
        assert "timestamp" in alert, "Expected timestamp in alert"
        assert "password" not in alert, "Password found in alert!"
        print(f"✓ Test 4 PASSED: 3 failed logins detected with alert: {alert['message']}")

        # Test 5: Deduplication check - calling again with same events should produce 0 new alerts
        alerts_again = app.detect_brute_force_alerts(test_3_attempts)
        assert len(alerts_again) == 0, f"Expected 0 new alerts on duplicate check, got {len(alerts_again)}"
        print("✓ Test 5 PASSED: Duplicate alerts prevented for same detection window.")

        # Test 6: Verify alerts file contains 1 alert and no passwords
        with open(temp_alert_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 1, f"Expected 1 line in alert file, got {len(lines)}"
        saved_alert = json.loads(lines[0])
        assert "password" not in saved_alert, "Password leaked in alerts file!"
        print("✓ Test 6 PASSED: Alert saved cleanly without passwords.")

        # Test 7: Attempts spread beyond 5 minutes (e.g. 0m, 3m, 6m) -> 0 alerts
        app.ALERT_FILE = os.path.join(temp_dir, "alerts_time.json")
        test_spread_attempts = [
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.9", "timestamp": "2026-11-13T10:00:00Z", "simulation": False},
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.9", "timestamp": "2026-11-13T10:03:00Z", "simulation": False},
            {"eventid": "cowrie.login.failed", "src_ip": "10.0.0.9", "timestamp": "2026-11-13T10:06:00Z", "simulation": False},
        ]
        # Notice: 10:00 to 10:06 is 6 minutes (>5 min). Sub-windows: [10:00, 10:03] is 2 attempts, [10:03, 10:06] is 2 attempts.
        alerts_spread = app.detect_brute_force_alerts(test_spread_attempts)
        assert len(alerts_spread) == 0, f"Expected 0 alerts for spread attempts, got {len(alerts_spread)}"
        print("✓ Test 7 PASSED: Attempts spread across >5 minutes do not trigger alert.")

        # Test 8: Test Flask Test Client for /api/alerts and /api/stats
        with app.app.test_client() as client:
            resp_stats = client.get("/api/stats")
            assert resp_stats.status_code == 200, f"/api/stats failed with status {resp_stats.status_code}"
            stats_json = resp_stats.get_json()
            assert "total_events" in stats_json
            print("✓ Test 8a PASSED: /api/stats returns 200 OK.")

            resp_alerts = client.get("/api/alerts")
            assert resp_alerts.status_code == 200, f"/api/alerts failed with status {resp_alerts.status_code}"
            alerts_json = resp_alerts.get_json()
            assert isinstance(alerts_json, list)
            print(f"✓ Test 8b PASSED: /api/alerts returns 200 OK (count={len(alerts_json)}).")

        print("\n==========================================")
        print("🎉 ALL 8 DETECTION TESTS COMPLETED SUCCESSFULLY!")
        print("==========================================")
    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    run_tests()
