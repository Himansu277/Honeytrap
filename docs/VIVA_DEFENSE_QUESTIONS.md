# HoneyTrap: University Capstone Viva & Defense Questions

Comprehensive reference Q&A guide for the HoneyTrap project presentation and examination.

---

### Q1: What is the core problem statement of HoneyTrap?
**Answer:** Real-world servers connected to the public internet are probed by automated attack bots within minutes of coming online. Security teams struggle with three major bottlenecks:
1. **Late detection** (breaches often go unnoticed for weeks or months).
2. **Loss of evidence** (in the rush to clean an attacked machine manually, volatile memory, process lists, and attacker keystrokes are destroyed).
3. **Slow, manual recovery** (cleaning and rebuilding servers manually takes hours and introduces human configuration errors).

HoneyTrap solves this by deploying a deceptive honeypot on AWS that lures attackers away from real systems, captures evidence immutably to AWS S3 and EBS snapshots, and automatically self-heals in minutes using DevOps automation (Terraform, Puppet, Nagios, and Ansible).

---

### Q2: What is the difference between Low-Interaction and High-Interaction honeypots? Why did you select Cowrie?
**Answer:**
- **Low-Interaction Honeypot:** Emulates services and provides fake shells/responses without giving the attacker access to a real operating system kernel. (e.g., Cowrie).
- **High-Interaction Honeypot:** Exposes a genuine operating system with real software. It captures authentic malware behavior but poses severe containment risks if the attacker uses the machine as a pivot to attack other servers or the host network.
- **Why Cowrie?** Cowrie emulates an SSH/Telnet server. It accepts passwords, emulates a believable Linux Debian/Ubuntu shell (`ls`, `uname`, `cat /proc/cpuinfo`, `wget`), and logs all credentials, keystrokes, and downloaded files in structured JSON while guaranteeing containment and zero kernel exploitation.

---

### Q3: Why use both Puppet and Ansible? Isn't there an overlap?
**Answer:** While both are configuration tools, they serve fundamentally different paradigms in HoneyTrap:
- **Puppet (Declarative / Pull-based / State Enforcer):** Puppet maintains continuous baseline configuration compliance. It runs in the background to ensure security settings (such as `PasswordAuthentication no`, `fail2ban`, `auditd`, and Cowrie systemd services) remain intact. If an attacker or drift modifies `/etc/ssh/sshd_config`, Puppet automatically corrects it back.
- **Ansible (Imperative / Push-based / Event Orchestration):** Ansible operates on-demand without requiring a daemon. When Nagios detects an attack, its event handler immediately pushes imperative commands: collecting volatile memory, streaming evidence archives to S3, triggering AWS EC2 EBS snapshots, and executing the honeypot rebuild sequence.
- **Summary:** Puppet enforces continuous state; Ansible executes immediate crisis orchestration.

---

### Q4: How is network isolation guaranteed? How do you prevent an attacker from pivoting to the production server?
**Answer:**
1. **3-Subnet Architecture:** The AWS VPC is split into Public Management (`10.0.1.0/24`), Honeypot DMZ (`10.0.2.0/24`), and Private Production (`10.0.3.0/24`).
2. **Network ACL Rule 50 (Stateless Packet Filter):** An explicit rule in the Honeypot subnet's NACL blocks any packet destined for `10.0.3.0/24`. This is enforced at the AWS hypervisor level before traffic can even enter the router.
3. **Security Groups (Stateful Inspection):** The production server's security group only accepts inbound connections from the Public Management security group on port 2222; it denies all traffic originating from the honeypot security group.
4. **Outbound Egress Restrictions:** The honeypot cannot initiate arbitrary outbound connections to external internet IPs, preventing it from being utilized in DDoS botnets or port scanning.

---

### Q5: How do you handle administrative SSH access when Cowrie is listening on standard port 22?
**Answer:** The real administrative OpenSSH daemon is reconfigured to listen on custom port `2222`. Furthermore, port 2222 is protected by security group ingress rules restricted to the administrator's CIDR IP address. Standard port `22` is exposed publicly and redirected via `iptables` NAT PREROUTING rules to Cowrie's unprivileged listening port (`2223`).

---

### Q6: How does Nagios detect attacks in real-time?
**Answer:** Nagios Core uses the NRPE (Nagios Remote Plugin Executor) agent. We authored a custom monitoring plugin named `check_cowrie_activity.sh`. Every 60 seconds, it reads `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`. It tracks byte pointers; when new lines contain `cowrie.login.failed`, `cowrie.login.success`, or `cowrie.command.input`, the plugin outputs an alert string with the attacker's IP and exits with status code `2` (`CRITICAL`).

---

### Q7: What is a Nagios Event Handler and how does it drive self-healing?
**Answer:** A Nagios event handler is an optional command executed whenever a host or service changes state. In HoneyTrap, we attached `handle_honeypot_attack.sh` to the `Cowrie_Intrusion_Detection` service. When the service enters `CRITICAL` state, Nagios passes the state arguments to the handler script, which immediately launches the Ansible `incident_response.yml` and `rebuild_honeypot.yml` playbooks.

---

### Q8: How is forensic chain of custody maintained?
**Answer:**
1. Volatile evidence (process tree `ps auxf`, socket connections `ss -antup`, login records `last -a`) is written immediately to a staging directory.
2. Cowrie logs and raw TTY session recordings are bundled and compressed into `incident_evidence_<timestamp>.tar.gz`.
3. The archive is streamed directly to an Amazon S3 bucket with **S3 Object Versioning** and **Public Access Block** enabled.
4. An Amazon EBS snapshot of the honeypot instance root block device is captured simultaneously via the AWS EC2 API, locking in the disk bitstream for deep forensic analysis.

---

### Q9: What are the measurable performance benchmarks of the system?
**Answer:**
- **Attack Detection Time:** 5 to 60 seconds (determined by the Nagios polling interval).
- **Forensic Capture & S3 Sync Time:** ~8 to 15 seconds.
- **EBS Snapshot Dispatch:** ~3 seconds.
- **Honeypot Rebuild & Re-Arming:** ~45 to 90 seconds.
- **Total Recovery Window:** Under 2.5 minutes, with zero human intervention.

---

### Q10: How does HoneyTrap adhere to AWS Acceptable Use Policy?
**Answer:** Running honeypots on public cloud providers requires strict safety precautions to prevent your instances from attacking third parties. HoneyTrap enforces outbound egress filtering in security groups so that even if an attacker successfully uploads and executes an automated scanning tool or botnet payload, all outbound SYN packets to outside networks are dropped.
