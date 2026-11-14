#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Ansible Playbook Syntax & Schema Validator (test_ansible_playbooks.py)
# Validates YAML structure, task definitions, inventory, and variables.
# ==============================================================================

import os
import sys
import yaml
import configparser

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ANSIBLE_DIR = os.path.join(PROJECT_ROOT, "ansible")
PLAYBOOKS_DIR = os.path.join(ANSIBLE_DIR, "playbooks")
INVENTORY_DIR = os.path.join(ANSIBLE_DIR, "inventory")

def validate_yaml_file(filepath):
    print(f"  Validating YAML: {os.path.relpath(filepath, PROJECT_ROOT)} ...", end=" ")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        assert data is not None, "File is empty"
        print("OK")
        return data
    except Exception as e:
        print(f"FAILED: {e}")
        return None

def test_ansible():
    print("==================================================================")
    print("        HONEYTRAP ANSIBLE PLAYBOOK & INVENTORY VALIDATION         ")
    print("==================================================================")

    # 1. Check ansible.cfg
    print("\n[CHECK 1] Validating ansible.cfg...")
    cfg_path = os.path.join(ANSIBLE_DIR, "ansible.cfg")
    assert os.path.exists(cfg_path), "ansible.cfg missing"
    cp = configparser.ConfigParser()
    cp.read(cfg_path)
    assert "defaults" in cp, "[defaults] section missing in ansible.cfg"
    assert "privilege_escalation" in cp, "[privilege_escalation] missing"
    print("  -> PASS: ansible.cfg is valid and configured")

    # 2. Check Inventory
    print("\n[CHECK 2] Validating inventory/hosts.ini...")
    inv_path = os.path.join(INVENTORY_DIR, "hosts.ini")
    assert os.path.exists(inv_path), "hosts.ini missing"
    with open(inv_path, "r", encoding="utf-8") as f:
        inv_text = f.read()
    assert "[management]" in inv_text
    assert "[honeypot]" in inv_text
    assert "[production]" in inv_text
    print("  -> PASS: hosts.ini contains management, honeypot, and production host groups")

    # 3. Check Group Vars
    print("\n[CHECK 3] Validating inventory/group_vars/all.yml...")
    vars_path = os.path.join(INVENTORY_DIR, "group_vars", "all.yml")
    all_vars = validate_yaml_file(vars_path)
    assert all_vars is not None
    assert "aws_region" in all_vars
    assert "s3_evidence_bucket" in all_vars
    assert "cowrie_log_dir" in all_vars
    assert "dashboard_sync_path" in all_vars
    print("  -> PASS: group_vars/all.yml loaded successfully with required parameters")

    # 4. Check Playbooks
    print("\n[CHECK 4] Validating Ansible Playbooks...")
    playbooks = [
        "incident_response.yml",
        "rebuild_honeypot.yml",
        "patch_prod.yml"
    ]
    
    total_tasks = 0
    for pb_name in playbooks:
        pb_path = os.path.join(PLAYBOOKS_DIR, pb_name)
        pb_data = validate_yaml_file(pb_path)
        assert pb_data is not None, f"Failed to load {pb_name}"
        assert isinstance(pb_data, list), f"{pb_name} root must be a list of plays"
        for play in pb_data:
            assert "name" in play, f"Play missing name in {pb_name}"
            assert "hosts" in play, f"Play missing hosts in {pb_name}"
            assert "tasks" in play, f"Play missing tasks in {pb_name}"
            tasks = play["tasks"]
            total_tasks += len(tasks)
            print(f"     └─ Play '{play['name']}' targets '{play['hosts']}' ({len(tasks)} tasks)")

    print(f"\n  -> Total validated Ansible tasks: {total_tasks}")
    print("\n==================================================================")
    print("         ALL ANSIBLE VALIDATION CHECKS PASSED                     ")
    print("==================================================================")

if __name__ == "__main__":
    test_ansible()
