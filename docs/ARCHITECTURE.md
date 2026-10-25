# HoneyTrap: System Architecture & Technical Specifications

**HoneyTrap** is an autonomous, self-healing cybersecurity architecture designed for cloud workloads on Amazon Web Services (AWS). It combines low-interaction deception technology with an Infrastructure-as-Code (IaC) and Configuration Management (CM) feedback loop to lure, detect, isolate, preserve forensic evidence, and automatically recover from intrusions with zero human intervention.

---

## 1. High-Level Architecture Diagram

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

## 2. The 3-Subnet Network Topology

The AWS Virtual Private Cloud is partitioned into 3 isolated subnets:

| Subnet Name | CIDR Block | Route Table Target | Accessibility & Roles |
|:---|:---|:---|:---|
| **Public Management Subnet** | `10.0.1.0/24` | Internet Gateway (`0.0.0.0/0 -> igw`) | Hosts Bastion Host, Nagios Core, Puppet, Ansible, and the Threat Intelligence Dashboard. Accessible only via administrator IP on port 2222. |
| **Honeypot DMZ Subnet** | `10.0.2.0/24` | Internet Gateway (`0.0.0.0/0 -> igw`) | Contains the Cowrie honeypot instance. Port 22 is open to `0.0.0.0/0` to act as bait. **Completely isolated from the production subnet.** |
| **Private Production Subnet** | `10.0.3.0/24` | Internal Only (No default gateway route) | Houses real enterprise business workloads. Has zero public IPs and zero inbound internet access. Managed solely through the Bastion. |

---

## 3. Network Isolation and Safety Mechanisms

Honeypots invite malicious traffic; therefore, stringent containment is non-negotiable:

1. **Subnet-Level Packet Filtering (NACL Rule 50):**
   - An explicit Network Access Control List rule (`Rule 50 DENY 10.0.3.0/24`) guarantees that even if an attacker attempts network lateral movement or port scanning from the honeypot, the AWS hypervisor drops the packets before they reach the production subnet.
2. **Outbound Restriction (AWS Policy Compliance):**
   - The honeypot's security group limits outbound traffic exclusively to DNS (UDP 53) and HTTPS (TCP 443 for AWS S3 log upload). Attackers cannot weaponize the honeypot for outbound DDoS attacks or network scanning.
3. **Port Relocation (Admin SSH vs. Cowrie Trap):**
   - True administrative SSH is relocated to port `2222` and restricted to the admin's CIDR IP.
   - Standard port `22` is forwarded via `iptables` to Cowrie's unprivileged fake shell daemon on port `2223`.
4. **Immutable Forensic Chain of Custody:**
   - Logs flow strictly one-way: from the honeypot to an S3 bucket configured with S3 Object Versioning and public access block.
   - At the instant of intrusion, an Amazon EBS snapshot captures the raw disk state.

---

## 4. Multi-Tool DevOps Coordination

| Tool | Primary Function | Technical Workflow |
|:---|:---|:---|
| **AWS** | Cloud Hosting | Provides compute (EC2), virtual networking (VPC, Subnets, Route Tables, NACLs), and storage (S3, EBS). |
| **Terraform** | Infrastructure-as-Code | Declaratively provisions the entire AWS environment in a single `terraform apply`. |
| **Puppet** | Configuration Management | Enforces baseline state (disabling password authentication, installing `fail2ban` and `auditd`, maintaining Cowrie configuration). Corrects configuration drift. |
| **Nagios Core** | Active Continuous Monitoring | NRPE agent runs `check_cowrie_activity.sh` every 60 seconds. On detecting login brute-force or command input, status transitions to `CRITICAL` and executes an event handler. |
| **Ansible** | Automated Orchestration | Triggered by the Nagios event handler. Runs playbooks to extract volatile system state, upload evidence to S3, trigger an EBS snapshot, purge contaminated workspaces, and restore a pristine honeypot trap. |
| **Cowrie** | Low-Interaction Deception | Emulates Ubuntu 20.04/22.04 SSH server. Records passwords, usernames, terminal session keystrokes, and downloaded payloads in structured JSON. |
