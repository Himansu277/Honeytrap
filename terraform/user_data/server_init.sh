#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Single-Server Bootstrap Script (Ubuntu 22.04 LTS)
# Configures: SSH relocation (port 2222), Nagios Core, Apache, Systemd Units
# Log file: /var/log/honeytrap_bootstrap.log
# ==============================================================================
set -euo pipefail

LOG_FILE="/var/log/honeytrap_bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================================="
echo "   HONEYTRAP SINGLE-SERVER BOOTSTRAP INITIALIZATION STARTED       "
echo "   Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')                  "
echo "=================================================================="

export DEBIAN_FRONTEND=noninteractive

# 1. Configure 2 GB Swap File (Essential for 1 GiB t3.micro memory buffer)
echo "[*] Configuring swap space for t3.micro..."
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "[+] 2 GB swapfile activated successfully."
else
    echo "[+] Swapfile already exists."
fi

# 2. Update OS Packages
echo "[*] Updating system package index..."
apt-get update -y
apt-get install -y build-essential libgd-dev openssl libssl-dev unzip apache2 \
  apache2-utils autoconf gcc libc6 make wget libmcrypt-dev bc gawk dc \
  python3 python3-pip python3-venv git curl awscli jq nagios-plugins nagios-nrpe-plugin \
  iptables iptables-persistent

# 2. Relocate Real Administrative SSH to Port 2222 (Idempotent)
echo "[*] Configuring administrative SSH daemon on port 2222..."
if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
    sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config
    if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
        echo "Port 2222" >> /etc/ssh/sshd_config
    fi
    systemctl restart ssh || systemctl restart sshd
    echo "[+] Administrative SSH relocated to port 2222."
else
    echo "[+] Administrative SSH already listening on port 2222."
fi

# 3. Build & Install Genuine Nagios Core (Idempotent)
echo "[*] Checking Nagios Core installation..."
if [ ! -f "/usr/local/nagios/bin/nagios" ]; then
    echo "[*] Compiling Nagios Core 4.4.14 from source..."
    cd /tmp
    wget -q -O nagioscore.tar.gz https://github.com/NagiosEnterprises/nagioscore/archive/nagios-4.4.14.tar.gz
    tar xzf nagioscore.tar.gz
    cd nagioscore-nagios-4.4.14
    ./configure --with-httpd-conf=/etc/apache2/sites-enabled
    make all
    make install-groups-users
    usermod -a -G nagios www-data || true
    make install
    make install-daemoninit
    make install-commandmode
    make install-config
    make install-webconf

    a2enmod rewrite cgi || true
    # Set web credentials (nagiosadmin / honeytrap2026!)
    htpasswd -b -c /usr/local/nagios/etc/htpasswd.users nagiosadmin honeytrap2026!
    systemctl enable nagios
    systemctl restart apache2
    systemctl restart nagios
    echo "[+] Genuine Nagios Core installed and enabled."
else
    echo "[+] Nagios Core binary already present at /usr/local/nagios/bin/nagios."
fi

# 4. Create Project Application Directories
echo "[*] Setting up HoneyTrap application directories..."
mkdir -p /opt/honeytrap/ansible
mkdir -p /opt/honeytrap/nagios/conf.d
mkdir -p /opt/honeytrap/nagios/plugins
mkdir -p /opt/honeytrap/nagios/eventhandlers
mkdir -p /opt/honeytrap/dashboard/data
mkdir -p /opt/honeytrap/dashboard/evidence
mkdir -p /opt/honeytrap/scripts
mkdir -p /opt/honeytrap/puppet

# 5. Setup Python Virtual Environment (Idempotent)
echo "[*] Configuring Python virtual environment..."
if [ ! -d "/opt/honeytrap/venv" ]; then
    python3 -m venv /opt/honeytrap/venv
    /opt/honeytrap/venv/bin/pip install --upgrade pip
    /opt/honeytrap/venv/bin/pip install flask requests boto3 paramiko
    echo "[+] Python virtual environment configured."
else
    echo "[+] Python virtual environment already exists."
fi

# 6. Setup Systemd Service Units for Persistence & Boot Survivability
echo "[*] Configuring Systemd service units..."

# Honeypot Service Unit (Binds to decoy Port 22)
cat << 'EOF' > /etc/systemd/system/honeytrap-honeypot.service
[Unit]
Description=HoneyTrap Python Paramiko SSH Honeypot
After=network.target ssh.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeytrap
Environment=HONEYPOT_BIND_HOST=0.0.0.0
Environment=HONEYPOT_BIND_PORT=22
ExecStart=/opt/honeytrap/venv/bin/python3 /opt/honeytrap/scripts/honeypot_service.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Dashboard Service Unit (Binds to Port 5000)
cat << 'EOF' > /etc/systemd/system/honeytrap-dashboard.service
[Unit]
Description=HoneyTrap Threat Intelligence & Self-Healing Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeytrap
Environment=HONEYPOT_HOST=127.0.0.1
Environment=HONEYPOT_PORT=22
ExecStart=/opt/honeytrap/venv/bin/python3 /opt/honeytrap/dashboard/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable apache2
systemctl enable nagios || true
systemctl enable honeytrap-honeypot.service || true
systemctl enable honeytrap-dashboard.service || true

echo "=================================================================="
echo "   HONEYTRAP SINGLE-SERVER BOOTSTRAP COMPLETED SUCCESSFULLY       "
echo "   Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')                  "
echo "=================================================================="
