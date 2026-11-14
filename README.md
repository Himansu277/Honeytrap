# 🍯 HoneyTrap – A Self-Healing Honeypot Security Trap

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Dashboard-Flask%203.1-black?logo=flask)](https://flask.palletsprojects.com/)
[![Paramiko](https://img.shields.io/badge/Honeypot-Paramiko%20SSH-yellow)](https://www.paramiko.org/)
[![Integrity](https://img.shields.io/badge/Forensics-SHA--256-emerald)](https://en.wikipedia.org/wiki/SHA-2)
[![Platform](https://img.shields.io/badge/Tested%20On-Windows%2011-0078D6?logo=windows)](https://www.microsoft.com/)

> **Academic Project:** Bachelor of Technology (B.Tech) – Computer Science & Engineering  
> **Student:** Himansu | **Registration No.:** 12304038 | **Roll No.:** 4  
> **Project Guide:** Er. Manpreet Kaur  
> **Department:** Department of Computer Science and Engineering, Lovely Professional University  
> **Academic Session:** 2026–2027  

---

## 1. Project Overview & Problem Statement

### The Problem
Modern internet-facing servers encounter automated brute-force attacks within minutes of going online. Traditional cybersecurity operations face three fundamental challenges:
1. **Slow Detection:** Automated brute-force attacks often go unnoticed until accounts are breached.
2. **Volatile Evidence Loss:** In the panic of an incident, logs are overwritten, corrupted, or deleted, destroying the forensic chain of custody.
3. **Manual, Error-Prone Recovery:** System administrators manually restart services without preserving evidence or verifying service recovery.

### The Solution: HoneyTrap
**HoneyTrap** is an autonomous cybersecurity deception and incident response trap. Instead of exposing real systems to attacks, HoneyTrap runs a dedicated, isolated SSH honeypot that:
- Attracts and lures malicious actors to a safe trap on `127.0.0.1:2222`.
- Strictly rejects 100% of authentication attempts and never grants a real shell or command execution.
- Never collects or stores submitted passwords.
- Records structured security events in Cowrie-compatible JSON format.
- Correlates connection logs in real time to detect brute-force attacks ($\ge 3$ failed logins within 5 minutes).
- Packages digital evidence into real gzip-compressed archives (`.tar.gz`) and verifies forensic integrity with cryptographic **SHA-256** checksums.
- Actively detects service crashes or port closures and executes **autonomous self-healing** to restart the honeypot without manual human intervention.

---

## 2. Project Objectives

1. **Deception & Containment:** Provide a safe SSH decoy service bound strictly to `127.0.0.1:2222` to isolate attack traffic completely from the host operating system.
2. **Strict Credential Privacy:** Enforce a zero-password storage policy where passwords are never recorded in logs, alerts, or forensic archives.
3. **Automated Threat Detection:** Implement sliding-window intrusion detection that identifies brute-force patterns from genuine log telemetry while ignoring simulated records.
4. **Forensic Integrity:** Generate immutable, downloadable forensic archives (`.tar.gz`) containing logs, alerts, and triage reports, sealed with SHA-256 hashes.
5. **Genuine Autonomous Self-Healing:** Implement dynamic socket health checks that automatically detect service crashes, restart the honeypot process, verify port availability within 5 seconds, prevent duplicate processes, and report truthful status.
6. **Real-Time Threat Intelligence:** Provide a beginner-friendly web dashboard (Flask + TailwindCSS) displaying live telemetry, attack feeds, alert panels, and recovery controls.

---

## 3. System Architecture & Workflow

```
+-----------------------------------------------------------------------------------+
|                              LOCAL LAB / OPERATOR                                 |
+-----------------------------------------------------------------------------------+
                                         |
                       SSH Login Attempt | (Port 2222)
                                         v
+-----------------------------------------------------------------------------------+
| 1. SSH HONEYPOT SERVICE (scripts/honeypot_service.py)                              |
|    - Listens on 127.0.0.1:2222 (Loopback Safe)                                    |
|    - 2048-bit RSA Host Key Authentication                                         |
|    - REJECTS ALL LOGINS (check_auth_password -> AUTH_FAILED)                      |
|    - ZERO Passwords Saved (Password field omitted entirely)                       |
|    - REJECTS ALL Channels (No TTY, No Shell, No Exec)                             |
|    - Appends JSON events to: dashboard/data/cowrie.json                           |
+-----------------------------------------------------------------------------------+
                                         |
                                         | Cowrie-format Event Telemetry
                                         v
+-----------------------------------------------------------------------------------+
| 2. THREAT DETECTION ENGINE (dashboard/app.py)                                     |
|    - Parses active events from cowrie.json                                        |
|    - Filter: Ignores records tagged "simulation": true                            |
|    - Algorithm: Groups failed logins per IP within a sliding 5-minute window      |
|    - Threshold: >= 3 failed logins triggers SSH Brute-Force Alert                 |
|    - Deduplication: Unique alert ID prevents repeated alerts for same window      |
|    - Persists alerts to: dashboard/data/alerts.json                               |
+-----------------------------------------------------------------------------------+
                                         |
                                         | Incident Triggered / Healing Invoked
                                         v
+-----------------------------------------------------------------------------------+
| 3. EVIDENCE VAULT PIPELINE (api_trigger_healing)                                  |
|    - Generates forensic triage manifest report (forensic_triage_<ts>.txt)         |
|    - Bundles: cowrie.json + alerts.json + manifest into incident_evidence_<ts>.tar.gz
|    - Computes cryptographic SHA-256 checksum over raw binary chunks               |
|    - Writes evidence descriptor to: dashboard/evidence/evidence_<ts>.json         |
|    - Rotates active log to: dashboard/data/cowrie_archive_<ts>.json               |
|    - Re-arms clean honeypot log file                                              |
+-----------------------------------------------------------------------------------+
                                         |
                                         | Health Probing & Process Remediation
                                         v
+-----------------------------------------------------------------------------------+
| 4. AUTONOMOUS SELF-HEALING ENGINE (is_honeypot_alive / start_honeypot_service)    |
|    - Probes TCP port 2222 with socket handshake (127.0.0.1:2222)                  |
|    - If down: Spawns scripts/honeypot_service.py using sys.executable             |
|    - Duplicate Prevention: Keeps existing process if port is already active       |
|    - Verification: Polls up to 5 seconds to confirm port is listening             |
|    - Truthful Reporting: Sets HEALED if port is active; HEALING_FAILED if down    |
|    - Updates status in: dashboard/data/status.json                                |
+-----------------------------------------------------------------------------------+
                                         |
                                         | REST API Telemetry
                                         v
+-----------------------------------------------------------------------------------+
| 5. THREAT INTELLIGENCE DASHBOARD (Flask + TailwindCSS at http://127.0.0.1:5000)   |
|    - Live Stat Cards: Events, Unique IPs, Credentials Trapped, Command Breaches   |
|    - Real-Time Alerts Panel: Displays IP, failed attempts, timestamp, alert status|
|    - Live Status Banner: ARMED & READY, UNDER_ATTACK, or SERVICE_STOPPED          |
|    - Forensic Vault (/evidence): One-click download of .tar.gz packages + SHA-256|
+-----------------------------------------------------------------------------------+
```

---

## 4. Technologies Used

| Technology | Role in HoneyTrap | Why Chosen |
|---|---|---|
| **Python 3.11** | Core Language | Standard for cybersecurity scripting, socket networking, and forensic data processing. |
| **Paramiko 5.1** | SSH Honeypot Server | Native Python SSH implementation; allows full control over authentication hooks without external daemons. |
| **Flask 3.1** | Web Dashboard & REST API | Lightweight, fast Python web framework ideal for serving real-time forensic APIs and web UI. |
| **TailwindCSS & Chart.js** | Frontend Presentation | Clean, responsive UI with real-time charts and dark-mode security aesthetic. |
| **Standard Library (`hashlib`)** | Evidence Integrity | Computes NIST-compliant SHA-256 cryptographic hashes for forensic chain-of-custody. |
| **Standard Library (`tarfile`)** | Evidence Packaging | Standard gzip-compressed tar archive generation (`.tar.gz`) for digital forensics. |
| **Standard Library (`socket`)** | Health Verification | Native TCP socket probing to test service availability on `127.0.0.1:2222`. |
| **Standard Library (`subprocess`)** | Process Orchestration | Cross-platform process management for restarting the honeypot service cleanly. |
| **JSON Lines (`.json`)** | Log & Alert Telemetry | Industry-standard Cowrie-compatible log format for simple, schema-less event parsing. |
| **Terraform, Ansible, Puppet, Nagios** | Cloud Blueprints | Included in the repository as architectural Infrastructure-as-Code (IaC) blueprints for future AWS production deployment. |

> **Note on Cowrie:** In the local Windows 11 lab, HoneyTrap uses a native **Python/Paramiko-based SSH honeypot** (`scripts/honeypot_service.py`) that implements the exact event schema, fields, and behavior of Cowrie (`cowrie.login.failed`, `cowrie.session.connect`, etc.). This avoids heavy Docker or Linux dependencies while remaining 100% genuine and fully functional on Windows.

---

## 5. Project Folder Structure

```
c:\Users\HP\OneDrive\Desktop\dev pro\
├── dashboard/                      # Threat Intelligence Dashboard Web Application
│   ├── app.py                      # Flask server, REST APIs, detection engine & self-healing
│   ├── requirements.txt            # Python dependencies (flask, paramiko, boto3, etc.)
│   ├── data/                       # Active telemetry and logs storage
│   │   ├── cowrie.json             # Live Cowrie-compatible JSON event stream
│   │   ├── alerts.json             # Persisted SSH brute-force alert records
│   │   └── status.json             # System operational state, health & healing history
│   ├── evidence/                   # Forensic Evidence Vault
│   │   ├── incident_evidence_*.tar.gz # Real gzip-compressed forensic packages
│   │   └── evidence_*.json         # Metadata descriptors containing verified SHA-256 hashes
│   ├── static/
│   │   └── js/dashboard.js         # Frontend telemetry polling (every 3s) & DOM updates
│   └── templates/                  # Frontend HTML Views
│       ├── index.html              # Main Threat Overview & live Alerts panel
│       ├── attacks.html            # Deep Threat Telemetry event log table
│       ├── evidence.html           # Forensic Vault with 1-click download buttons
│       └── architecture.html       # Visual system architecture diagram
├── scripts/                        # Operational Scripts
│   ├── honeypot_service.py         # Native Paramiko SSH Honeypot (Port 2222)
│   ├── honeypot_host_key           # 2048-bit RSA SSH private host key
│   ├── deploy_aws.ps1 / .sh        # Cloud deployment automation scripts
│   └── start_dashboard.ps1 / .bat  # Convenience launch scripts
├── tests/                          # Automated Verification & Benchmark Suites
│   ├── test_detection.py           # Unit tests for sliding-window detection & deduplication
│   ├── test_evidence_verification.py # Tests archive members, SHA-256 match & download
│   ├── test_self_healing_verification.py # Tests crash detection, restart & duplicate prevention
│   └── final_e2e_verification.py   # Full 13-step end-to-end integration test
├── simulation/                     # Attack Simulation Scripts (for controlled testing)
│   ├── attack_simulator.py         # Standalone simulation injector
│   └── test_self_healing_cycle.py  # Self-healing loop verification suite
├── terraform/                      # AWS IaC Blueprints (VPC, Subnets, EC2, S3, NACLs)
├── ansible/                        # Configuration Playbooks (rebuild, incident response)
├── puppet/                         # System Hardening & Drift Correction Manifests
├── nagios/                         # Monitoring Configurations & Event Handlers
├── docs/                           # Project Documentation & Viva Preparation
└── README.md                       # Complete Project Documentation (this file)
```

---

## 6. Installation Requirements for Windows 11

### Prerequisites
1. **Operating System:** Windows 11 (64-bit).
2. **Python:** Python 3.10 or 3.11 installed and added to your system `PATH`.
3. **OpenSSH Client:** Standard OpenSSH client (installed by default in Windows 11 PowerShell).

### Setup Instructions
Open PowerShell or Command Prompt in the project root directory:

```powershell
# 1. Navigate to project root
cd "c:\Users\HP\OneDrive\Desktop\dev pro"

# 2. Install required Python packages
python -m pip install flask paramiko
```

---

## 7. How to Run the Project Locally

Running HoneyTrap requires **two terminal windows**:

### Terminal 1: Start the SSH Honeypot Service
```powershell
python scripts/honeypot_service.py
```
**Expected Output:**
```text
==================================================================
      HoneyTrap - Native Python SSH Honeypot Service (Paramiko)    
==================================================================
 [+] Listening Host : 127.0.0.1 (Loopback only - Safe)
 [+] Listening Port : 2222
 [+] Host Key File  : ...\scripts\honeypot_host_key
 [+] Log Destination: ...\dashboard\data\cowrie.json
 [+] Security Rules : ALL logins rejected. Zero shell/exec access.
 [+] Password Policy: Passwords are NEVER logged or saved.
 [+] Status         : ARMED & RUNNING. Waiting for connections...
 [!] Press Ctrl+C at any time to stop the service cleanly.
==================================================================
```

### Terminal 2: Start the Threat Intelligence Dashboard
```powershell
python dashboard/app.py
```
**Expected Output:**
```text
[+] HoneyTrap Threat Intelligence & Self-Healing Dashboard starting on port 5000...
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

### Accessing the Web Dashboard
Open your browser and navigate to:  
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

You will see:
- Top banner: `ARMED & READY` (monitoring perimeter on Port 2222).
- **SSH Brute-Force Alerts** panel with `REAL DETECTION` badge.
- Live attack telemetry cards and graphs.

---

## 8. How to Test SSH Login Rejection

Open a third terminal window and attempt to connect to the honeypot:

```powershell
ssh -p 2222 testuser@127.0.0.1
```

1. Enter any test password when prompted (e.g., `Password123!`).
2. **What Happens:**
   - The honeypot immediately rejects the authentication (`Permission denied, please try again`).
   - The honeypot console displays:
     ```text
     [!] Unauthorized login attempt - User: 'testuser' | IP: 127.0.0.1:58432 (AUTH REJECTED)
     ```
   - A genuine JSON record is written to `dashboard/data/cowrie.json`.
   - **Crucial Security Check:** The password you typed is **never** saved or logged anywhere.

---

## 9. How Brute-Force Detection Works

The detection engine resides in `detect_brute_force_alerts()` inside `dashboard/app.py`:

1. **Log Ingestion:** Reads all events from `dashboard/data/cowrie.json`.
2. **Simulation Isolation:** Any event containing `"simulation": true` is ignored. Only genuine events (`simulation != True`) are processed.
3. **Sliding Time Window:**
   - Filters events for `eventid == "cowrie.login.failed"`.
   - Groups failed login timestamps per IP address.
   - Slides a 300-second (5-minute) window across the timestamps.
4. **Threshold:** If $\ge 3$ failed logins occur within the 5-minute window, an alert is triggered.
5. **Deduplication:**
   - Each alert is given a deterministic ID based on the IP and the start timestamp:
     ```python
     alert_id = f"alert_{ip}_{int(window_start.timestamp())}"
     ```
   - Before saving, the engine checks existing IDs in `dashboard/data/alerts.json`.
   - Re-evaluating logs never creates duplicate alerts for the same attack window.
6. **Dashboard Display:**
   - The dashboard polls `/api/alerts` every 3 seconds.
   - The alert appears dynamically in the **SSH Brute-Force Alerts** card with the source IP, failed count, timestamp, and alert message.

---

## 10. How Evidence Backup & SHA-256 Verification Work

When an incident occurs or the user clicks **"Trigger Self-Healing"** (or calls `POST /api/trigger-healing`):

1. **Manifest Generation:** Creates a forensic incident report (`forensic_triage_<ts>.txt`) containing timestamp, target host, event count, and chain-of-custody status.
2. **Archive Packaging:** Uses Python's `tarfile` module to package three essential files into a genuine gzip archive (`incident_evidence_<ts>.tar.gz`):
   - `cowrie.json` (Sanitized raw honeypot events)
   - `alerts.json` (Actual correlated threat detections)
   - `forensic_triage_report.txt` (Forensic chain-of-custody manifest)
3. **Cryptographic SHA-256 Hash:**
   - Reads the newly written archive in binary chunks (`hashlib.sha256()`).
   - Computes the exact 64-character hexadecimal checksum.
   - Stores the metadata in `dashboard/evidence/evidence_<ts>.json`.
4. **Log Rotation:** Rotates the active log into `dashboard/data/cowrie_archive_<ts>.json` and re-arms a clean log file.
5. **Independent Verification:**
   You can verify the SHA-256 hash yourself in PowerShell:
   ```powershell
   Get-FileHash -Path "dashboard\evidence\incident_evidence_<timestamp>.tar.gz" -Algorithm SHA256
   ```
   The output will match the hash displayed on the **Forensic Vault** page (`/evidence`).
6. **One-Click Download:** Users can download the archive directly from the dashboard via `/api/evidence/download/<filename>`.

---

## 11. How Service Failure Detection & Self-Healing Work

HoneyTrap includes a real-time health-check and autonomous remediation engine:

### Failure Detection
1. The helper function `is_honeypot_alive()` attempts a TCP connection to `127.0.0.1:2222`.
2. Every time `/api/status` is called, it performs this health check.
3. If port 2222 is closed (e.g., process killed or crashed), the dashboard banner immediately turns red and changes state to:
   ```text
   State: SERVICE_STOPPED
   Headline: WARNING: Honeypot service is STOPPED on Port 2222. Trigger Self-Healing to recover.
   Badge: SERVICE OFFLINE
   ```

### Autonomous Self-Healing
When `POST /api/trigger-healing` is called:
1. **Evidence First:** Forensic evidence is backed up and hashed before touching any services.
2. **Process Restart:**
   - If port 2222 is closed, HoneyTrap launches `scripts/honeypot_service.py` using `sys.executable` and the project root working directory.
   - If port 2222 is already open, it skips spawning to **prevent duplicate processes**.
3. **Port Verification:**
   - The engine polls `127.0.0.1:2222` for up to 5 seconds.
   - It performs a final socket handshake to confirm the port is accepting connections.
4. **Truthful Reporting:**
   - **HEALED:** Reported *only* if the socket handshake succeeds (`port_verified: True`). State returns to `ACTIVE`.
   - **HEALING_FAILED:** If the port cannot be reached after 5 seconds, the system reports `HEALING_FAILED` and records the error. It **never** displays fictional success.

---

## 12. Implemented REST API Endpoints

All endpoints are live and return standard JSON:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Main threat overview dashboard. |
| `GET` | `/attacks` | Deep threat telemetry page (table of all events). |
| `GET` | `/evidence` | Forensic evidence vault page with download buttons. |
| `GET` | `/architecture` | Visual system architecture and workflow view. |
| `GET` | `/api/status` | Returns live system state, honeypot health (`honeypot_alive`), and recovery timestamps. |
| `GET` | `/api/stats` | Aggregated statistics: total events, unique IPs, login counts, top usernames. |
| `GET` | `/api/attacks` | Returns the 50 most recent attack records. |
| `GET` | `/api/commands` | Returns the 30 most recent typed command records. |
| `GET` | `/api/alerts` | Returns all detected SSH brute-force alerts (runs live detection). |
| `GET` | `/api/evidence` | Returns list of all archived evidence packages with sizes and SHA-256 hashes. |
| `GET` | `/api/evidence/download/<file>` | Downloads the actual `.tar.gz` evidence archive. |
| `POST` | `/api/trigger-healing` | Executes evidence archiving, log rotation, and honeypot service recovery. |
| `POST` | `/api/simulate-attack` | Injects simulated attack events tagged with `"simulation": true`. |
| `POST` | `/api/reset` | Resets dashboard status back to default armed baseline. |

---

## 13. Security Limitations & Future Scope

### Current Local Lab Limitations
1. **Loopback Binding (`127.0.0.1`):** In local Windows testing, the honeypot binds to port 2222 on localhost to avoid exposing the host machine to real external network attacks.
2. **Standard Port 22:** On Windows, binding privileged port 22 requires administrator privileges or native Linux daemons; port 2222 is used as the safe local testing port.
3. **Simulated Shell Commands:** Because all authentication is strictly rejected, command execution is emulated through controlled test logs rather than granting an interactive shell.

### Infrastructure Automation & Validation
The project includes fully implemented, structured, and validated configurations for all four DevOps/DevSecOps tools:
- **Nagios (`nagios/` & `scripts/nagios_monitor.py`):** Active health checks for Dashboard (`check_dashboard.py`), Honeypot (`check_honeypot.py`), and Cowrie intrusion logs (`check_cowrie_activity.sh`) with automated incident response via `handle_honeypot_attack.sh`.
- **Terraform (`terraform/`):** Low-cost, Free-Tier-optimized AWS architecture featuring a dedicated VPC, public honeypot subnet, S3 forensic evidence vault, single-server EC2 deployment, and strict security groups isolating decoy bait (port 22) from administrative access (ports 2222, 5000, 80). Fully initialized with HashiCorp AWS & Random providers and verified via `terraform validate`.
- **Ansible (`ansible/`):** Complete playbooks for incident response (`incident_response.yml`), honeypot purging & rebuilding (`rebuild_honeypot.yml`), and production patching (`patch_prod.yml`). Validated via `tests/test_ansible_playbooks.py`.
- **Puppet (`puppet/`):** Declarative state manifests (`site.pp`), Cowrie configuration templates, SSH baseline hardening, `fail2ban`, and NRPE agent enforcement. Validated via `tests/test_puppet_manifests.py`.

To run the complete automated infrastructure validation across all 4 components in a single command:
```powershell
python tests/test_infrastructure_suite.py
```

---

## 14. Viva Questions & Quick Answers

**Q1: What is a honeypot?**  
> *A:* A honeypot is a deliberately vulnerable decoy system designed to attract, detect, and deflect attackers from real production systems while studying their tactics.

**Q2: What is the core difference between a regular honeypot and HoneyTrap?**  
> *A:* Traditional honeypots only log attacks passively. HoneyTrap actively correlates attacks in real time, locks down evidence with cryptographic hashes (SHA-256), and automatically self-heals by restarting compromised or crashed trap services.

**Q3: How do you prevent attackers from using HoneyTrap to pivot into your computer?**  
> *A:* The honeypot binds strictly to `127.0.0.1` (loopback). It unconditionally rejects all authentication attempts, disables shell/exec channels, and never executes commands on the host OS.

**Q4: How does your brute-force detection algorithm work?**  
> *A:* It uses a sliding 5-minute time window across failed login timestamps (`cowrie.login.failed`) grouped by IP address. If 3 or more attempts occur within 5 minutes, an alert is triggered. Deduplication keys prevent repeat alerts for the same window.

**Q5: How do you ensure digital evidence is admissible in forensics?**  
> *A:* HoneyTrap packages raw logs, alert feeds, and an incident triage manifest into a `.tar.gz` archive and immediately calculates its cryptographic SHA-256 checksum. Any modification to the archive changes the hash, proving tamper resistance.

**Q6: What happens if the honeypot service crashes?**  
> *A:* The dashboard's health-check function probes TCP port 2222. When it fails, the dashboard flags `SERVICE_STOPPED`. Triggering self-healing preserves evidence first, restarts `honeypot_service.py` via Python `subprocess`, verifies port 2222 within 5 seconds, and truthfully reports recovery.
