#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Management Node Bootstrap Script (Ubuntu 22.04 LTS)
# Installs Nagios Core, Ansible, Puppet, and Flask Dashboard
# ==============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[*] Updating management server packages..."
apt-get update -y
apt-get install -y build-essential libgd-dev openssl libssl-dev unzip apache2 \
  apache2-utils autoconf gcc libc6 make wget libmcrypt-dev bc gawk dc \
  python3 python3-pip python3-venv git curl awscli jq nagios-plugins nagios-nrpe-plugin \
  ansible

# 1. Relocate SSH to port 2222
echo "[*] Setting SSH port to 2222..."
sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# 2. Install Nagios Core
echo "[*] Installing Nagios Core..."
cd /tmp
if [ ! -d "/usr/local/nagios" ]; then
    wget -O nagioscore.tar.gz https://github.com/NagiosEnterprises/nagioscore/archive/nagios-4.4.14.tar.gz
    tar xzf nagioscore.tar.gz
    cd nagioscore-nagios-4.4.14
    ./configure --with-httpd-conf=/etc/apache2/sites-enabled
    make all
    make install-groups-users
    usermod -a -G nagios www-data
    make install
    make install-daemoninit
    make install-commandmode
    make install-config
    make install-webconf

    a2enmod rewrite cgi
    # Set default admin credentials for web console
    htpasswd -b -c /usr/local/nagios/etc/htpasswd.users nagiosadmin honeytrap2026!
fi

# 3. Setup Project directories on Bastion
mkdir -p /opt/honeytrap/ansible
mkdir -p /opt/honeytrap/nagios
mkdir -p /opt/honeytrap/dashboard
mkdir -p /opt/honeytrap/evidence

# 4. Install Dashboard dependencies
python3 -m venv /opt/honeytrap/venv
/opt/honeytrap/venv/bin/pip install --upgrade pip
/opt/honeytrap/venv/bin/pip install flask requests boto3

systemctl restart apache2
systemctl restart nagios || true

echo "[+] HoneyTrap Management Node bootstrap complete."
