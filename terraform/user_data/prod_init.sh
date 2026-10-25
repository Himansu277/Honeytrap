#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Private Production Server Bootstrap Script (Ubuntu 22.04 LTS)
# Hardened, Protected internal corporate web/app server
# ==============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# 1. Update OS packages
apt-get update -y
apt-get install -y nginx fail2ban auditd nagios-nrpe-server nagios-plugins curl ufw

# 2. Relocate SSH to port 2222 and disable password logins
echo "[*] Hardening SSH configuration..."
sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# 3. Configure Internal Enterprise Intranet App on Nginx
cat <<'EOF' > /var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HoneyTrap Protected Internal Enterprise Portal</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; max-width: 600px; margin: auto; }
        .status { color: #10b981; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🔒 Corporate Secure Internal Production Node</h2>
        <p>Status: <span class="status">OPERATIONAL (Isolated Subnet)</span></p>
        <p>This node is isolated from the HoneyTrap DMZ network and accepts administrative traffic only via the Bastion Control Node.</p>
        <p>Hardening: <strong>fail2ban</strong>, <strong>auditd</strong>, <strong>key-only SSH (port 2222)</strong> enabled.</p>
    </div>
</body>
</html>
EOF
systemctl restart nginx

# 4. Enable fail2ban & auditd
systemctl enable fail2ban
systemctl start fail2ban
systemctl enable auditd
systemctl start auditd

# 5. Configure Nagios NRPE
cat <<'EOF' >> /etc/nagios/nrpe.cfg
allowed_hosts=127.0.0.1,10.0.1.0/24
command[check_users]=/usr/lib/nagios/plugins/check_users -w 5 -c 10
command[check_load]=/usr/lib/nagios/plugins/check_load -r -w .15,.10,.05 -c .30,.25,.20
command[check_disk]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /
command[check_nginx]=/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -p 80
EOF

systemctl enable nagios-nrpe-server
systemctl restart nagios-nrpe-server

echo "[+] HoneyTrap Production Server hardening & bootstrap complete."
