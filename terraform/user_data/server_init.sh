#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Single-Server Bootstrap Script (Ubuntu 22.04 LTS)
# Configures: SSH relocation (port 2222), Nagios Core, Apache, Python, Cowrie prereqs
# ==============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[*] Updating system packages..."
apt-get update -y
apt-get install -y build-essential libgd-dev openssl libssl-dev unzip apache2 \
  apache2-utils autoconf gcc libc6 make wget libmcrypt-dev bc gawk dc \
  python3 python3-pip python3-venv git curl awscli jq nagios-plugins nagios-nrpe-plugin \
  iptables iptables-persistent

# 1. Relocate real administrative SSH to custom port 2222 (frees port 22 for honeypot)
echo "[*] Relocating real administrative SSH to port 2222..."
sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# 2. Build and Install genuine Nagios Core
echo "[*] Installing genuine Nagios Core..."
cd /tmp
if [ ! -d "/usr/local/nagios" ]; then
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

    a2enmod rewrite cgi
    # Set default admin credentials for web console (restricted by security group)
    htpasswd -b -c /usr/local/nagios/etc/htpasswd.users nagiosadmin honeytrap2026!
fi

# 3. Setup Project directories
mkdir -p /opt/honeytrap/ansible
mkdir -p /opt/honeytrap/nagios
mkdir -p /opt/honeytrap/dashboard
mkdir -p /opt/honeytrap/evidence
mkdir -p /opt/honeytrap/puppet

# 4. Setup Python Virtual Environment for HoneyTrap & Dashboard
python3 -m venv /opt/honeytrap/venv
/opt/honeytrap/venv/bin/pip install --upgrade pip
/opt/honeytrap/venv/bin/pip install flask requests boto3 paramiko

systemctl restart apache2 || true
systemctl restart nagios || true

echo "[+] HoneyTrap Single Server bootstrap complete."
