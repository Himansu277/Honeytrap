# 🍯 HoneyTrap: A Self-Healing Honeypot Security Trap on AWS

[![AWS](https://img.shields.io/badge/Cloud-AWS-orange?logo=amazon-aws)](https://aws.amazon.com/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-blueviolet?logo=terraform)](https://www.terraform.io/)
[![Puppet](https://img.shields.io/badge/Config-Puppet-FFAE1A?logo=puppet)](https://puppet.com/)
[![Nagios](https://img.shields.io/badge/Monitoring-Nagios%20Core-green?logo=nagios)](https://www.nagios.org/)
[![Ansible](https://img.shields.io/badge/Orchestration-Ansible-EE0000?logo=ansible)](https://www.ansible.com/)
[![Honeypot](https://img.shields.io/badge/Deception-Cowrie%20SSH-yellow)](https://github.com/cowrie/cowrie)
[![Dashboard](https://img.shields.io/badge/UI-Flask%20%2B%20TailwindCSS-000000?logo=flask)](https://flask.palletsprojects.com/)

> **Bachelor of Technology (B.Tech) - Computer Science & Engineering**  
> **Student:** Himansu | **Registration No.:** 12304038 | **Roll No.:** 4  
> **Project Guide:** Manpreet Kaur  
> **Department of Computer Science and Engineering**, Lovely Professional University, Punjab  
> **Academic Session:** 2026–2027  

---

## 📖 Project Overview

Cyber attacks against cloud infrastructure occur within minutes of instances going online. Traditional security operations suffer from three fatal flaws:
1. **Late detection** (breaches often remain undetected for weeks).
2. **Loss of evidence** (manual triage destroys volatile memory and forensic trails).
3. **Slow, manual recovery** (cleaning infected machines by hand takes hours).

**HoneyTrap** solves this by turning the paradigm inside out: it places a fake, deliberately vulnerable server (Cowrie honeypot) on AWS to lure attackers. The honeypot watches and records everything they do in an isolated DMZ. When an attack is detected, a fully automated DevOps feedback loop kicks in:
- **Nagios Core** detects the intrusion and triggers alerts.
- **Ansible** immediately freezes volatile memory, bundles logs, uploads them to **Amazon S3**, and captures an **Amazon EBS disk snapshot**.
- **Ansible & Puppet** purge the contaminated environment, re-apply hardened configurations, and rebuild a pristine honeypot in minutes.
- Real production systems remain 100% safe in an isolated private subnet.

---

## 🏛️ System Architecture

```
                 +------------------------------------------------+
                 |            INTERNET (Threat Scanners)          |
                 +------------------------------------------------+
                                         |
                                         | Inbound SSH (Port 22)
                                         v
+-----------------------------------------------------------------------------------+
| AWS VIRTUAL PRIVATE CLOUD (VPC: 10.0.0.0/16)                                      |
|                                                                                   |
|  +----------------------------------+     +------------------------------------+  |
|  |  HONEYPOT DMZ (10.0.2.0/24)      |     |  PUBLIC MANAGEMENT (10.0.1.0/24)   |  |
|  |  - Cowrie Honeypot (Port 22/2223)|     |  - Bastion Host                    |  |
|  |  - Nagios NRPE Agent (Port 5666) |<----+  - Nagios Core (Monitor & Alerter) |  |
|  |  - Maint. SSH (Port 2222)        |     |  - Puppet Master (State Enforcer)  |  |
|  |  - Strict One-Way Egress         |     |  - Ansible Controller (Orchestrator|  |
|  +-----------------+----------------+     |  - Web Threat Dashboard (Port 5000)|  |
|                    |                      +------------------------------------+  |
|          NACL Rule | 50 (DENY ALL)                           |                    |
|                    X                                         |                    |
|  +-----------------+----------------+                        |                    |
|  |  PRIVATE PRODUCTION (10.0.3.0/24)|                        | Managed via        |
|  |  - Enterprise Internal Web Portal|<-----------------------+ Port 2222          |
|  |  - Hardened: fail2ban + auditd   |                                             |
|  |  - ZERO Direct Internet Ingress  |                                             |
|  +----------------------------------+                                             |
+-----------------------------------------------------------------------------------+
                     |                                         |
                     | (Forensic Sync)                         | (Attack Alert)
                     v                                         v
         +------------------------+               +------------------------+
         | AWS S3 EVIDENCE BUCKET |               |  AWS SNS ALERT TOPIC   |
         | & EBS ROOT SNAPSHOTS   |               |   (Email & Dashboard)  |
         +------------------------+               +------------------------+
```

---

## 🛠️ Tools & Technologies Used

| Tool | Category | Job in HoneyTrap |
|:---|:---|:---|
| **AWS** | Cloud Platform | Cloud hosting: VPC, 3 Subnets, EC2 (`t3.micro`), S3 (Evidence Vault), SNS (Alerts), VPC Flow Logs. |
| **Terraform** | Infrastructure-as-Code | Declaratively provisions the entire cloud topology in a single `terraform apply`. |
| **Puppet** | Configuration Management | Enforces baseline security state, disables password authentication, installs `fail2ban` and `auditd`, and configures Cowrie and NRPE agents. |
| **Nagios Core** | Continuous Monitoring | Actively polls honeypot with custom `check_cowrie_activity.sh`; triggers alerts and the self-healing event handler on `CRITICAL`. |
| **Ansible** | Automated Orchestration | Executes incident response (volatile memory dump, S3 log sync, EBS snapshot) and self-healing rebuild playbooks. |
| **Cowrie** | Deception / Honeypot | Emulates an authentic SSH server; records attacker passwords, usernames, and keystrokes to JSON. |
| **Flask + Tailwind**| Threat Intelligence UI | Real-time web dashboard displaying attack metrics, geolocation, harvested credentials, and live self-healing controls. |

---

## 🚀 Quick Start Guide

### Option A: Local Interactive Demonstration (For Viva / Evaluation)
You can run the Threat Intelligence Dashboard and simulate the entire self-healing loop locally on your computer without incurring cloud costs:

1. **Install dependencies & launch dashboard:**
   - On Windows: Double-click `scripts\start_dashboard.bat` (or run `powershell -File scripts\start_dashboard.ps1`)
   - Or manually:
     ```bash
     pip install -r dashboard/requirements.txt
     python dashboard/app.py
     ```
2. **Open Dashboard:** Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000)
3. **Simulate Attacks & Verify Self-Healing:**
   - Click **"Simulate SSH Brute Force"** or **"Simulate Terminal Breach"** on the dashboard.
   - Click **"Trigger Self-Healing"** to observe forensic packaging and recovery.
4. **Run the Automated Test Suite:**
   ```bash
   python simulation/test_self_healing_cycle.py
   ```

---

### Option B: Full AWS Cloud Deployment
To deploy the live multi-subnet infrastructure on AWS:

1. **Configure credentials:**
   ```bash
   aws configure
   ```
2. **Setup configuration variables:**
   ```bash
   cd terraform
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your IP and AWS Key Pair name
   ```
3. **Deploy with Terraform:**
   ```bash
   terraform init
   terraform plan -out=tfplan
   terraform apply tfplan
   ```
4. **Access Endpoints:**
   - HoneyTrap Dashboard: `http://<management_node_ip>:5000`
   - Nagios Core Console: `http://<management_node_ip>/nagios`
   - Attack Bait (Cowrie Port 22): `ssh -p 22 root@<honeypot_node_ip>`
   - Real Admin SSH: `ssh -i <key.pem> -p 2222 ubuntu@<management_node_ip>`

---

## 🧪 Testing & Verification Results Matrix

The table below reflects the expected and validated test cases (from Section 12 of the Project Synopsis):

| Test Case | Expected Result | Observation | Status |
|:---|:---|:---|:---|
| **Failed SSH logins recorded** | Pass | Every attempt appeared in `cowrie.json` with IP, user, and password | ✅ PASS |
| **Nagios alert on attack** | Pass | Custom plugin changed status to `CRITICAL` on next polling check | ✅ PASS |
| **Evidence saved to S3** | Pass | Forensic triage archive and EBS disk snapshot stored securely | ✅ PASS |
| **Honeypot rebuilt** | Pass | Contaminated trap purged; clean instance re-armed via Ansible & Puppet | ✅ PASS |
| **Access from honeypot to prod** | Blocked | NACL Rule 50 strictly dropped all packets destined for `10.0.3.0/24` | 🛡️ BLOCKED |

---

## 📁 Repository Structure

```
HoneyTrap/
├── terraform/                  # Infrastructure as Code (AWS VPC, Subnets, EC2, S3, SNS, IAM)
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── vpc.tf
│   ├── security_groups.tf
│   ├── nacl.tf
│   ├── ec2.tf
│   ├── s3_iam.tf
│   ├── sns.tf
│   ├── user_data/              # Cloud-init bootstrap scripts
│   └── terraform.tfvars.example
├── puppet/                     # Configuration Management & Drift Correction
│   ├── manifests/site.pp
│   └── modules/
│       ├── hardening/          # SSH hardening, fail2ban, auditd
│       ├── cowrie/             # Fake SSH server & system banners
│       └── nrpe/               # Nagios monitoring agent & check plugins
├── nagios/                     # Continuous Monitoring & Event Handling
│   ├── nagios.cfg
│   ├── conf.d/                 # Hosts, services, commands, contacts
│   ├── plugins/                # check_cowrie_activity.sh plugin
│   └── eventhandlers/          # handle_honeypot_attack.sh (Self-healing trigger)
├── ansible/                    # Automated Incident Response & Orchestration
│   ├── ansible.cfg
│   ├── inventory/hosts.ini
│   └── playbooks/
│       ├── incident_response.yml # S3 log preservation & EBS snapshotting
│       ├── rebuild_honeypot.yml  # Autonomous honeypot purge & rebuild
│       └── patch_prod.yml        # Production server security patching
├── dashboard/                  # Real-Time Cyber Threat Intelligence Web App
│   ├── app.py                  # Flask backend with REST APIs
│   ├── requirements.txt
│   ├── data/                   # Real-time and sample Cowrie attack logs
│   ├── static/js/dashboard.js
│   └── templates/              # Modern Tailwind UI templates
├── simulation/                 # Penetration & Evaluation Tools
│   ├── attack_simulator.py     # SSH brute-force & command injector
│   └── test_self_healing_cycle.py # Table 12 automated benchmark suite
├── scripts/                    # Helper scripts for deployment & execution
│   ├── deploy_aws.sh / .ps1
│   ├── start_dashboard.bat / .ps1
│   └── run_simulation.bat
└── docs/                       # Technical & Academic Documentation
    ├── ARCHITECTURE.md
    ├── DEPLOYMENT_GUIDE.md
    ├── VIVA_DEFENSE_QUESTIONS.md
    └── SYSTEM_WORKFLOW.md
```

---

## 📚 References & Academic Citations

1. HashiCorp Terraform Documentation: [developer.hashicorp.com/terraform](https://developer.hashicorp.com/terraform)
2. Perforce Puppet Documentation: [puppet.com/docs](https://puppet.com/docs)
3. Red Hat Ansible Documentation: [docs.ansible.com](https://docs.ansible.com)
4. Nagios Core Documentation: [nagios.org](https://www.nagios.org)
5. Cowrie SSH/Telnet Honeypot: [github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)
6. Amazon Web Services Documentation: [docs.aws.amazon.com](https://docs.aws.amazon.com)
