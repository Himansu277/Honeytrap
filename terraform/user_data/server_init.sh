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

    # Generate unique strong password for operator; store in root-only file; never print in logs
    set +x 2>/dev/null || true
    NAGIOS_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 20)
    mkdir -p /etc/nagios
    echo "nagiosadmin:${NAGIOS_PASS}" > /etc/nagios/nagiosadmin.cred
    chmod 600 /etc/nagios/nagiosadmin.cred
    echo "${NAGIOS_PASS}" | htpasswd -i -c /usr/local/nagios/etc/htpasswd.users nagiosadmin >/dev/null 2>&1
    chown apache:apache /usr/local/nagios/etc/htpasswd.users
    chmod 640 /usr/local/nagios/etc/htpasswd.users
    unset NAGIOS_PASS

    # Install Nagios Plugins
    echo "[*] Compiling Nagios official plugins..."
    cd /tmp
    wget -q -O nagios-plugins.tar.gz https://github.com/nagios-plugins/nagios-plugins/releases/download/release-2.4.6/nagios-plugins-2.4.6.tar.gz
    tar xzf nagios-plugins.tar.gz
    cd nagios-plugins-2.4.6
    ./configure --with-nagios-user=nagios --with-nagios-group=nagios
    make
    make install

    # Configure Nagios Core service definitions for HoneyTrap
    cat << 'EOF' > /usr/local/nagios/etc/objects/honeytrap.cfg
# ==============================================================================
# HoneyTrap Single-Server Monitored Services for Genuine Nagios Core
# ==============================================================================

define service {
    use                     generic-service
    host_name               localhost
    service_description     HoneyTrap_Honeypot_Port22
    check_command           check_ssh!-p 22
    notes                   "Monitors Python Paramiko SSH Honeypot listening on port 22"
}

define service {
    use                     generic-service
    host_name               localhost
    service_description     HoneyTrap_Admin_SSH_Port2222
    check_command           check_ssh!-p 2222
    notes                   "Monitors Real Administrative SSH listening on port 2222"
}

define service {
    use                     generic-service
    host_name               localhost
    service_description     HoneyTrap_Dashboard_Port5000
    check_command           check_http!-p 5000 -u /api/status
    notes                   "Monitors HoneyTrap Threat Intelligence Flask Dashboard on port 5000"
}
EOF

    if ! grep -q "objects/honeytrap.cfg" /usr/local/nagios/etc/nagios.cfg; then
        echo "cfg_file=/usr/local/nagios/etc/objects/honeytrap.cfg" >> /usr/local/nagios/etc/nagios.cfg
    fi

    # Validate Nagios Core configuration
    /usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg || true

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
        /opt/puppetlabs/bin/puppet module install puppetlabs-stdlib --target-dir /etc/puppetlabs/code/environments/production/modules || true
        echo "[+] Puppet 8 Agent installed successfully on AL2023."
    fi
else
    echo "[+] Puppet Agent already present at /opt/puppetlabs/bin/puppet."
fi

# 7. Setup Application Directories and Dedicated Unprivileged User
echo "[*] Setting up HoneyTrap user and application directories..."
useradd -r -s /sbin/nologin -d /opt/honeytrap honeytrap || true
mkdir -p /opt/honeytrap/ansible
mkdir -p /opt/honeytrap/nagios/conf.d
mkdir -p /opt/honeytrap/nagios/plugins
mkdir -p /opt/honeytrap/nagios/eventhandlers
mkdir -p /opt/honeytrap/dashboard/data
mkdir -p /opt/honeytrap/dashboard/evidence
mkdir -p /opt/honeytrap/scripts
mkdir -p /opt/honeytrap/puppet
chown -R honeytrap:honeytrap /opt/honeytrap

# 8. Configure Narrowly Scoped Sudoers Rule for Self-Healing
echo "[*] Configuring narrowly scoped sudoers rule for self-healing..."
mkdir -p /etc/sudoers.d
cat << 'EOF' > /etc/sudoers.d/honeytrap-dashboard
# HoneyTrap: scoped permission to restart and check only the honeypot systemd unit
honeytrap ALL=(root) NOPASSWD: /usr/bin/systemctl restart honeytrap-honeypot.service, /usr/bin/systemctl status honeytrap-honeypot.service, /usr/bin/systemctl is-active honeytrap-honeypot.service
EOF
chmod 0440 /etc/sudoers.d/honeytrap-dashboard
visudo -cf /etc/sudoers.d/honeytrap-dashboard || rm -f /etc/sudoers.d/honeytrap-dashboard

# Set permissions on environment config
chown root:honeytrap /etc/honeytrap/env 2>/dev/null || true
chmod 640 /etc/honeytrap/env 2>/dev/null || true

# 9. Setup Python Virtual Environment
echo "[*] Setting up Python virtual environment..."
if [ ! -d "/opt/honeytrap/venv" ]; then
    python3 -m venv /opt/honeytrap/venv
    /opt/honeytrap/venv/bin/pip install --upgrade pip
    /opt/honeytrap/venv/bin/pip install flask requests boto3 paramiko
    chown -R honeytrap:honeytrap /opt/honeytrap/venv
    echo "[+] Python venv ready."
else
    echo "[+] Python venv already configured."
fi

# 10. Configure Systemd Units for Honeypot & Dashboard
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
EnvironmentFile=-/etc/honeytrap/env
Environment=HONEYPOT_BIND_HOST=0.0.0.0
Environment=HONEYPOT_BIND_PORT=22
ExecStart=/opt/honeytrap/venv/bin/python3 /opt/honeytrap/scripts/honeypot_service.py
Restart=always
RestartSec=3
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# B. Dashboard Service (Listens on Port 5000, runs unprivileged as honeytrap user)
cat << 'EOF' > /etc/systemd/system/honeytrap-dashboard.service
[Unit]
Description=HoneyTrap Threat Intelligence & Self-Healing Dashboard
After=network.target

[Service]
Type=simple
User=honeytrap
Group=honeytrap
WorkingDirectory=/opt/honeytrap
EnvironmentFile=-/etc/honeytrap/env
Environment=HONEYPOT_HOST=127.0.0.1
Environment=HONEYPOT_PORT=22
ExecStart=/opt/honeytrap/venv/bin/python3 /opt/honeytrap/dashboard/app.py
Restart=always
RestartSec=3
ProtectSystem=full
ProtectHome=true

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
