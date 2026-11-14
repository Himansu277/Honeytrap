import os
import sys
import json
import shutil
import hashlib
import tarfile
import io

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "dashboard"))
import app

def test_evidence_backup():
    print("==================================================================")
    print("      HONEYTRAP EVIDENCE BACKUP INSPECTION & VERIFICATION         ")
    print("==================================================================")

    data_dir = os.path.join(PROJECT_ROOT, "dashboard", "data")
    evidence_dir = os.path.join(PROJECT_ROOT, "dashboard", "evidence")
    cowrie_log = os.path.join(data_dir, "cowrie.json")
    alerts_file = os.path.join(data_dir, "alerts.json")

    # Safety: backup cowrie.json so log rotation during test doesn't wipe it
    cowrie_backup = os.path.join(data_dir, "cowrie_temp_backup.json")
    shutil.copyfile(cowrie_log, cowrie_backup)

    results = {}

    try:
        # Trigger real healing/evidence generation via Flask test client
        with app.app.test_client() as client:
            resp = client.post("/api/trigger-healing")
            assert resp.status_code == 200, f"Trigger healing failed with {resp.status_code}"
            data = resp.get_json()
            evidence_meta = data.get("evidence", {})
            archive_name = evidence_meta.get("archive_id")
            archive_path = os.path.join(evidence_dir, archive_name)
            meta_json_path = os.path.join(evidence_dir, archive_name.replace("incident_evidence_", "evidence_").replace(".tar.gz", ".json"))

            print(f"\n[+] Generated evidence archive: {archive_name}")
            print(f"[+] Reported SHA-256: {evidence_meta.get('hash_sha256')}")

            # -------------------------------------------------------------
            # Verification 1: Does it create a real .tar.gz archive?
            # -------------------------------------------------------------
            is_real_tar_gz = False
            if os.path.exists(archive_path) and os.path.getsize(archive_path) > 0:
                with open(archive_path, "rb") as f:
                    magic_bytes = f.read(2)
                # GZIP magic bytes: 0x1F, 0x8B
                if magic_bytes == b"\x1f\x8b":
                    try:
                        with tarfile.open(archive_path, "r:gz") as tar:
                            members = tar.getnames()
                            is_real_tar_gz = True
                    except Exception as e:
                        print(f"[-] Tarfile error: {e}")
            
            results["1_real_tar_gz"] = {
                "status": "PASS" if is_real_tar_gz else "FAIL",
                "details": f"Archive exists ({os.path.getsize(archive_path)} bytes), GZIP magic bytes verified, valid tar structure."
            }

            # -------------------------------------------------------------
            # Verification 2: Does it contain cowrie.json and alerts.json?
            # -------------------------------------------------------------
            with tarfile.open(archive_path, "r:gz") as tar:
                members = tar.getnames()
            
            has_cowrie = "cowrie.json" in members
            has_alerts = "alerts.json" in members
            
            if has_cowrie and has_alerts:
                v2_status = "PASS"
                v2_details = f"Both files found in archive: {members}"
            elif has_cowrie and not has_alerts:
                v2_status = "FAIL"
                v2_details = f"Partial: 'cowrie.json' is present, but 'alerts.json' is MISSING. Archive members: {members}"
            else:
                v2_status = "FAIL"
                v2_details = f"Neither file found. Archive members: {members}"

            results["2_contains_cowrie_and_alerts"] = {
                "status": v2_status,
                "details": v2_details
            }

            # -------------------------------------------------------------
            # Verification 3: Is SHA-256 calculated from actual archive?
            # -------------------------------------------------------------
            hasher = hashlib.sha256()
            with open(archive_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            actual_sha256 = hasher.hexdigest()
            reported_sha256 = evidence_meta.get("hash_sha256")
            
            # Also verify meta JSON file on disk has same hash
            disk_sha256 = None
            if os.path.exists(meta_json_path):
                with open(meta_json_path, "r", encoding="utf-8") as mf:
                    disk_meta = json.load(mf)
                    disk_sha256 = disk_meta.get("hash_sha256")

            matches = (actual_sha256 == reported_sha256 == disk_sha256)
            results["3_sha256_integrity"] = {
                "status": "PASS" if matches else "FAIL",
                "details": f"Actual computed: {actual_sha256} | API reported: {reported_sha256} | Meta file on disk: {disk_sha256}"
            }

            # -------------------------------------------------------------
            # Verification 4: Can archive be downloaded and opened?
            # -------------------------------------------------------------
            download_url = f"/api/evidence/download/{archive_name}"
            dl_resp = client.get(download_url)
            can_download = (dl_resp.status_code == 200)
            
            can_open_downloaded = False
            if can_download:
                try:
                    downloaded_bytes = io.BytesIO(dl_resp.data)
                    with tarfile.open(fileobj=downloaded_bytes, mode="r:gz") as tar:
                        names = tar.getnames()
                        if len(names) > 0:
                            can_open_downloaded = True
                except Exception as e:
                    print(f"[-] Could not open downloaded archive: {e}")

            results["4_download_and_open"] = {
                "status": "PASS" if (can_download and can_open_downloaded) else "FAIL",
                "details": f"HTTP {dl_resp.status_code} from {download_url}. Content-Length: {len(dl_resp.data)} bytes. Opened in-memory with tarfile: {names}."
            }

            # -------------------------------------------------------------
            # Verification 5: Does the archive contain plaintext password fields?
            # -------------------------------------------------------------
            passwords_found_in_new = []
            with tarfile.open(archive_path, "r:gz") as tar:
                for member_name in tar.getnames():
                    member_file = tar.extractfile(member_name)
                    content = member_file.read().decode("utf-8", errors="ignore")
                    for line_no, line in enumerate(content.splitlines(), 1):
                        if '"password"' in line or "'password'" in line:
                            passwords_found_in_new.append((member_name, line_no, line))

            # Also check old historical archives in the folder
            historical_leaks = {}
            for fname in os.listdir(evidence_dir):
                if fname.endswith(".tar.gz") and fname != archive_name:
                    fpath = os.path.join(evidence_dir, fname)
                    try:
                        with tarfile.open(fpath, "r:gz") as htar:
                            for hname in htar.getnames():
                                hfile = htar.extractfile(hname)
                                hcontent = hfile.read().decode("utf-8", errors="ignore")
                                for line in hcontent.splitlines():
                                    if '"password"' in line or "'password'" in line:
                                        historical_leaks.setdefault(fname, 0)
                                        historical_leaks[fname] += 1
                    except Exception:
                        pass

            if len(passwords_found_in_new) == 0:
                v5_status = "PASS"
                v5_details = f"0 password fields in newly created archive. (Note: {len(historical_leaks)} old historical archives from pre-cleanup dates contain old passwords: {historical_leaks})"
            else:
                v5_status = "FAIL"
                v5_details = f"Found {len(passwords_found_in_new)} password field(s) in new archive: {passwords_found_in_new}"

            results["5_no_plaintext_passwords"] = {
                "status": v5_status,
                "details": v5_details
            }

    finally:
        # Restore cowrie.json to preserve pre-test state
        shutil.copyfile(cowrie_backup, cowrie_log)
        if os.path.exists(cowrie_backup):
            os.remove(cowrie_backup)

    print("\n------------------------------------------------------------------")
    print("                     VERIFICATION SUMMARY                         ")
    print("------------------------------------------------------------------")
    for key, val in results.items():
        print(f"[{val['status']}] {key}:")
        print(f"      {val['details']}\n")

    return results

if __name__ == "__main__":
    test_evidence_backup()
