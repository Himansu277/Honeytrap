#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Single-Server Bootstrap Script for Amazon Linux 2023 (AL2023)
# Configures: 2GB Swap, DNF packages, SSH port 2222, Apache (httpd),
# Nagios Core 4.4.14, Puppet 8 Agent, and HoneyTrap Systemd services.
# Log file: /var/log/honeytrap_bootstrap.log
# ==============================================================================
set -euo pipefail

LOG_FILE="/var/log/honeytrap_bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================================="
echo "   HONEYTRAP AMAZON LINUX 2023 BOOTSTRAP INITIALIZATION STARTED   "
echo "   Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')                 "
echo "   Target OS: Amazon Linux 2023 (RPM / DNF)                       "
echo "=================================================================="

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

# 2. Update System Packages via DNF
echo "[*] Updating system package index via DNF..."
dnf check-update || true
dnf update -y

# 3. Install Required System Dependencies and Build Tools
echo "[*] Installing build tools, libraries, Python, and Apache (httpd)..."
dnf install -y \
  gcc \
  make \
  glibc-devel \
  openssl-devel \
  gd \
  gd-devel \
  unzip \
  wget \
  tar \
  gzip \
  which \
  python3 \
  python3-pip \
  python3-devel \
  git \
  curl \
  jq \
  iptables \
  iptables-services \
  httpd \
  httpd-tools

# 4. Relocate Real Administrative SSH to Port 2222 (Idempotent)
echo "[*] Relocating real administrative SSH to custom port 2222..."
mkdir -p /etc/ssh/sshd_config.d
cat << 'EOF' > /etc/ssh/sshd_config.d/00-custom-port.conf
# HoneyTrap: Administrative SSH moved to port 2222 to free port 22 for honeypot decoy
Port 2222
EOF

if ! grep -q "^Port 2222" /etc/ssh/sshd_config; then
    sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config
fi
systemctl restart sshd
echo "[+] Administrative SSH active on port 2222 (service: sshd)."

# 5. Build and Install Genuine Nagios Core 4.4.14 for Amazon Linux 2023
echo "[*] Checking Nagios Core installation..."
if [ ! -f "/usr/local/nagios/bin/nagios" ]; then
    echo "[*] Building genuine Nagios Core 4.4.14 from source for AL2023..."
    useradd -r nagios || true
    groupadd -r nagcmd || true
    usermod -a -G nagcmd nagios || true
    usermod -a -G nagcmd apache || true
    usermod -a -G nagios apache || true

    cd /tmp
    wget -q -O nagioscore.tar.gz https://github.com/NagiosEnterprises/nagioscore/archive/nagios-4.4.14.tar.gz
    tar xzf nagioscore.tar.gz
    cd nagioscore-nagios-4.4.14

    # Configure specifically for AL2023 Apache path (/etc/httpd/conf.d)
    ./configure \
      --with-command-group=nagcmd \
      --with-httpd-conf=/etc/httpd/conf.d \
      --with-nagios-user=nagios \
      --with-nagios-group=nagios

    make all
    make install-groups-users
    make install
    make install-daemoninit
    make install-commandmode
    make install-config
    make install-webconf

    # Set web console credentials for operator (nagiosadmin / honeytrap2026!)
    htpasswd -b -c /usr/local/nagios/etc/htpasswd.users nagiosadmin honeytrap2026!
    chown apache:apache /usr/local/nagios/etc/htpasswd.users
    chmod 640 /usr/local/nagios/etc/htpasswd.users

    # Install Nagios Plugins
    echo "[*] Compiling Nagios official plugins..."
    cd /tmp
    wget -q -O nagios-plugins.tar.gz https://github.com/nagios-plugins/nagios-plugins/releases/download/release-2.4.6/nagios-plugins-2.4.6.tar.gz
    tar xzf nagios-plugins.tar.gz
    cd nagios-plugins-2.4.6
    ./configure --with-nagios-user=nagios --with-nagios-group=nagios
    make
    make install

    systemctl enable httpd
    systemctl restart httpd
    systemctl enable nagios
    systemctl restart nagios || true
    echo "[+] Genuine Nagios Core compiled, configured, and running under httpd."
else
    echo "[+] Nagios Core already installed at /usr/local/nagios/bin/nagios."
fi

# 6. Install Official Puppet 8 Agent for Amazon Linux 2023
echo "[*] Checking Puppet Agent installation for AL2023..."
if [ ! -f "/opt/puppetlabs/bin/puppet" ]; then
    echo "[*] Installing official Puppet 8 repository for Amazon Linux 2023..."
    rpm -Uvh https://yum.puppet.com/puppet8-release-amazon-2023.noarch.rpm || true
    dnf install -y puppet-agent || true
    if [ -f "/opt/puppetlabs/bin/puppet" ]; then
        ln -sf /opt/puppetlabs/bin/puppet /usr/local/bin/puppet || true
        echo "[+] Puppet 8 Agent installed successfully on AL2023."
    fi
else
    echo "[+] Puppet Agent already present at /opt/puppetlabs/bin/puppet."
fi

# 7. Setup Application Directories
echo "[*] Setting up HoneyTrap application directories..."
mkdir -p /opt/honeytrap/ansible
mkdir -p /opt/honeytrap/nagios/conf.d
mkdir -p /opt/honeytrap/nagios/plugins
mkdir -p /opt/honeytrap/nagios/eventhandlers
mkdir -p /opt/honeytrap/dashboard/data
mkdir -p /opt/honeytrap/dashboard/evidence
mkdir -p /opt/honeytrap/scripts
mkdir -p /opt/honeytrap/puppet

# 8. Setup Python Virtual Environment
echo "[*] Setting up Python virtual environment..."
if [ ! -d "/opt/honeytrap/venv" ]; then
    python3 -m venv /opt/honeytrap/venv
    /opt/honeytrap/venv/bin/pip install --upgrade pip
    /opt/honeytrap/venv/bin/pip install flask requests boto3 paramiko
    echo "[+] Python venv ready."
else
    echo "[+] Python venv already configured."
fi

# 9. Configure Systemd Units for Honeypot & Dashboard
echo "[*] Deploying Systemd service units..."

# A. Honeypot Service (Listens on Decoy Port 22)
cat << 'EOF' > /etc/systemd/system/honeytrap-honeypot.service
[Unit]
Description=HoneyTrap Python Paramiko SSH Honeypot
After=network.target sshd.service

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

# B. Dashboard Service (Listens on Port 5000)
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
systemctl enable httpd
systemctl enable nagios || true
systemctl enable honeytrap-honeypot.service || true
systemctl enable honeytrap-dashboard.service || true

echo "=================================================================="
echo "   HONEYTRAP AL2023 SINGLE-SERVER BOOTSTRAP COMPLETED             "
echo "   Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')                 "
echo "=================================================================="
