import os
import sys
import json

target_files = [
    'dashboard/evidence/evidence_2026-10-25_151649.json',
    'dashboard/evidence/evidence_2026-10-25_152022.json',
    'dashboard/evidence/evidence_2026-10-25_163149.json'
]

print("=== PERFORMING DELETION ===")
for tf in target_files:
    if os.path.exists(tf):
        os.remove(tf)
        print(f"[-] Deleted: {tf}")
    else:
        print(f"[!] Already gone: {tf}")

print("\n=== POST-DELETION VERIFICATION 1: All 3 files are gone ===")
for tf in target_files:
    exists = os.path.exists(tf)
    print(f"Check {tf}: Exists = {exists}")
    assert not exists, f"File still exists: {tf}"
print("Confirmed: All 3 target files deleted.")

print("\n=== POST-DELETION VERIFICATION 2: Nov 13 archives remain ===")
nov13_files = [
    'dashboard/evidence/incident_evidence_2026-11-13_150617.tar.gz',
    'dashboard/evidence/evidence_2026-11-13_150617.json',
    'dashboard/evidence/incident_evidence_2026-11-13_150808.tar.gz',
    'dashboard/evidence/evidence_2026-11-13_150808.json'
]
for nf in nov13_files:
    exists = os.path.exists(nf)
    size = os.path.getsize(nf) if exists else 0
    print(f"Nov 13 file: {nf} | Exists: {exists} | Size: {size} bytes")
    assert exists, f"Nov 13 file unexpectedly missing: {nf}"

print("\n=== POST-DELETION VERIFICATION 3 & 4: API & Download Checks ===")
sys.path.insert(0, os.path.abspath('dashboard'))
import app

with app.app.test_client() as client:
    # 3. Downloads still work
    for archive_name in ['incident_evidence_2026-11-13_150617.tar.gz', 'incident_evidence_2026-11-13_150808.tar.gz']:
        dl_resp = client.get(f'/api/evidence/download/{archive_name}')
        print(f"Download {archive_name}: HTTP {dl_resp.status_code} ({len(dl_resp.data)} bytes)")
        assert dl_resp.status_code == 200, f"Download failed for {archive_name}"

    # 4. Forensic vault listing check
    ev_resp = client.get('/api/evidence')
    assert ev_resp.status_code == 200
    evidence_records = ev_resp.get_json()
    listed_archives = [r.get('archive_id') for r in evidence_records]
    print(f"\nForensic Vault contains {len(evidence_records)} verified packages:")
    for r in evidence_records:
        aid = r.get('archive_id')
        size_kb = r.get('file_size_kb')
        h = r.get('hash_sha256', '')[:16]
        print(f" - {aid} | Size: {size_kb} | SHA-256: {h}...")

    # Assert none of the Oct 25 entries exist
    for aid in ['incident_evidence_2026-10-25_151649.tar.gz', 'incident_evidence_2026-10-25_152022.tar.gz', 'incident_evidence_2026-10-25_163149.tar.gz']:
        assert aid not in listed_archives, f"Invalid Oct 25 archive still listed: {aid}"
    print("\n[+] Confirmed: 0 invalid October 25 entries remain in the Forensic Vault!")

print("\n🎉 CLEANUP & ALL VERIFICATIONS PASSED!")
