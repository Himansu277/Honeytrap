# HoneyTrap: End-to-End System Workflow

This document illustrates the complete end-to-end operational lifecycle of HoneyTrap from initial threat reconnaissance to automated forensic recovery and re-arming.

---

## The 8-Step Autonomous Healing Sequence

```
[Phase 1: Reconnaissance]
         |
         v
1. Attacker or internet scanner scans port 22 and discovers the Cowrie trap.
         |
         v
[Phase 2: Intrusion]
         |
         v
2. Attacker initiates dictionary brute-force. Cowrie grants fake shell access,
   recording credentials, TTY sessions, and commands in `cowrie.json`.
         |
         v
[Phase 3: Detection]
         |
         v
3. Nagios NRPE agent runs `check_cowrie_activity.sh`.
   New intrusion events are detected; service changes status to CRITICAL.
         |
         v
[Phase 4: Notification]
         |
         v
4. Nagios broadcasts an alert through Amazon SNS to administrator email / Slack.
         |
         v
[Phase 5: Event Handler Trigger]
         |
         v
5. Nagios Event Handler (`handle_honeypot_attack.sh`) activates Ansible controller.
         |
         v
[Phase 6: Forensic Capture]
         |
         v
6. Ansible executes `incident_response.yml`:
   - Gathers volatile memory, processes (`ps auxf`), and sockets (`ss -antup`).
   - Compresses logs into `incident_evidence_<timestamp>.tar.gz`.
   - Uploads archive to AWS S3 immutable bucket.
   - Triggers an Amazon EBS volume snapshot for disk forensics.
         |
         v
[Phase 7: Self-Healing & Purge]
         |
         v
7. Ansible executes `rebuild_honeypot.yml`:
   - Kills compromised processes and child shells.
   - Purges contaminated workspaces.
   - Re-applies Puppet configuration (`site.pp`) to eliminate drift.
   - Restarts Cowrie in pristine state and resets Nagios check pointer.
         |
         v
[Phase 8: Telemetry Refresh]
         |
         v
8. The HoneyTrap Threat Intelligence Dashboard auto-refreshes, updating attack stats,
   geolocations, and confirming the clean trap is ARMED.
```
