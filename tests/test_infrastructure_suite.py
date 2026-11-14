#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Complete Infrastructure Test Suite (test_infrastructure_suite.py)
# Executes validation for Nagios, Terraform, Ansible, and Puppet.
# ==============================================================================

import os
import sys
import subprocess

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TERRAFORM_DIR = os.path.join(PROJECT_ROOT, "terraform")

def run_test(name, cmd, cwd=PROJECT_ROOT):
    print(f"\n>> RUNNING: {name}")
    print("-" * 70)
    proc = subprocess.run(cmd, cwd=cwd, text=True)
    if proc.returncode == 0:
        print(f"PASS: {name}")
        return True
    else:
        print(f"FAILED: {name} (Exit code {proc.returncode})")
        return False

def main():
    print("==================================================================")
    print("       HONEYTRAP COMPLETE INFRASTRUCTURE VERIFICATION SUITE       ")
    print("   [Nagios Core Monitor | Terraform IaC | Ansible | Puppet]       ")
    print("==================================================================")

    results = {}

    # 1. Nagios Active Monitoring
    results["Nagios Monitoring"] = run_test(
        "Nagios Active Monitoring Checks",
        [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_nagios_monitoring.py")]
    )

    # 2. Terraform IaC Validation
    results["Terraform IaC Validation"] = run_test(
        "Terraform Infrastructure Validation",
        ["terraform", "validate"],
        cwd=TERRAFORM_DIR
    )

    # 3. Ansible Playbook Validation
    results["Ansible Playbook Validation"] = run_test(
        "Ansible Playbook & Inventory Validation",
        [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_ansible_playbooks.py")]
    )

    # 4. Puppet Manifests Validation
    results["Puppet Manifests Validation"] = run_test(
        "Puppet Manifest & ERB Validation",
        [sys.executable, os.path.join(PROJECT_ROOT, "tests", "test_puppet_manifests.py")]
    )

    print("\n==================================================================")
    print("                   FINAL INFRASTRUCTURE SUMMARY                   ")
    print("==================================================================")
    all_passed = True
    for component, status in results.items():
        st_text = "[ PASS ]" if status else "[ FAIL ]"
        print(f"  {component:<35} {st_text}")
        if not status:
            all_passed = False

    print("==================================================================")
    if all_passed:
        print(" ALL INFRASTRUCTURE BLUEPRINTS & MONITORS VALIDATED SUCCESSFULLY! ")
    else:
        print(" ONE OR MORE INFRASTRUCTURE VALIDATION CHECKS FAILED! ")
    print("==================================================================")
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
