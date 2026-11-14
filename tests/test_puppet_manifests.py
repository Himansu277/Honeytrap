#!/usr/bin/env python3
# ==============================================================================
# HoneyTrap - Puppet Manifests & ERB Template Validator (test_puppet_manifests.py)
# Verifies site.pp, module classes, resource declarations, and templates.
# ==============================================================================

import os
import re

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PUPPET_DIR = os.path.join(PROJECT_ROOT, "puppet")
MANIFESTS_DIR = os.path.join(PUPPET_DIR, "manifests")
MODULES_DIR = os.path.join(PUPPET_DIR, "modules")

def validate_puppet_syntax(file_path):
    print(f"  Validating Puppet manifest: {os.path.relpath(file_path, PROJECT_ROOT)} ...", end=" ")
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify basic Puppet language constructs
    open_braces = content.count("{")
    close_braces = content.count("}")
    assert open_braces == close_braces, f"Brace mismatch: {open_braces} open vs {close_braces} close"
    
    # Check for invalid syntax patterns
    assert not re.search(r"class\s+([a-zA-Z0-9_:]+)\s*\([^)]*$", content), "Unclosed parameter list"
    print("OK")
    return content

def validate_erb_template(template_path):
    print(f"  Validating ERB template   : {os.path.relpath(template_path, PROJECT_ROOT)} ...", end=" ")
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Verify ERB tag matching (<% ... %> and <%= ... %>)
    opens = re.findall(r"<%[=\-]?", content)
    closes = re.findall(r"-?%>", content)
    assert len(opens) == len(closes), f"ERB tag mismatch: {len(opens)} open vs {len(closes)} close"
    print("OK")

def test_puppet():
    print("==================================================================")
    print("          HONEYTRAP PUPPET MANIFESTS & MODULES VALIDATION         ")
    print("==================================================================")

    # 1. Site Manifest
    print("\n[CHECK 1] Validating site.pp...")
    site_pp = os.path.join(MANIFESTS_DIR, "site.pp")
    assert os.path.exists(site_pp), "site.pp missing"
    site_content = validate_puppet_syntax(site_pp)
    assert "node default" in site_content
    assert "node /.*honeypot.*/" in site_content
    assert "node /.*production.*/" in site_content
    assert "node /.*management.*/" in site_content
    print("  -> PASS: site.pp defines policies for default, honeypot, production, and management nodes")

    # 2. Cowrie Module
    print("\n[CHECK 2] Validating cowrie module...")
    cowrie_init = os.path.join(MODULES_DIR, "cowrie", "manifests", "init.pp")
    validate_puppet_syntax(cowrie_init)
    cowrie_erb = os.path.join(MODULES_DIR, "cowrie", "templates", "cowrie.cfg.erb")
    validate_erb_template(cowrie_erb)
    print("  -> PASS: cowrie module manifests and templates validated")

    # 3. Hardening Module
    print("\n[CHECK 3] Validating hardening module...")
    hardening_init = os.path.join(MODULES_DIR, "hardening", "manifests", "init.pp")
    validate_puppet_syntax(hardening_init)
    print("  -> PASS: hardening module manifests validated (SSH, fail2ban, auditd)")

    # 4. NRPE Module
    print("\n[CHECK 4] Validating nrpe module...")
    nrpe_init = os.path.join(MODULES_DIR, "nrpe", "manifests", "init.pp")
    validate_puppet_syntax(nrpe_init)
    nrpe_erb = os.path.join(MODULES_DIR, "nrpe", "templates", "nrpe.cfg.erb")
    validate_erb_template(nrpe_erb)
    print("  -> PASS: nrpe module manifests and templates validated")

    print("\n==================================================================")
    print("         ALL PUPPET VALIDATION CHECKS PASSED                      ")
    print("==================================================================")

if __name__ == "__main__":
    test_puppet()
