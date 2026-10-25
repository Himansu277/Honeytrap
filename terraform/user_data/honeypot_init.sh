#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Honeypot EC2 Bootstrap Script (Ubuntu 22.04 LTS)
# Sets up Real SSH on Port 2222, Cowrie on Port 22, and NRPE Agent
# ==============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# 1. Update OS packages
apt-get update -y
apt-get install -y git python3-pip python3-venv libssl-dev libffi-dev build-essential \
  nagios-nrpe-server nagios-plugins authbind iptables-persistent curl awscli jq

# 2. Relocate Real Admin SSH from Port 22 to Port 2222
echo "[*] Reconfiguring OpenSSH to listen on port 2222..."
sed -i 's/^#*Port 22/Port 2222/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# 3. Create Cowrie unprivileged user
echo "[*] Creating honeypot user..."
if ! id -u cowrie >/dev/null 2>&1; then
    useradd -r -m -s /bin/bash cowrie
fi

# 4. Install and configure Cowrie SSH Honeypot
echo "[*] Installing Cowrie SSH honeypot..."
COWRIE_HOME="/home/cowrie/cowrie"
if [ ! -d "$COWRIE_HOME" ]; then
    sudo -u cowrie git clone https://github.com/cowrie/cowrie.git "$COWRIE_HOME"
    sudo -u cowrie python3 -m venv "$COWRIE_HOME/cowrie-env"
    sudo -u cowrie "$COWRIE_HOME/cowrie-env/bin/pip" install --upgrade pip
    sudo -u cowrie "$COWRIE_HOME/cowrie-env/bin/pip" install -r "$COWRIE_HOME/requirements.txt"
fi

# 5. Cowrie configuration
cat <<'EOF' > /home/cowrie/cowrie/etc/cowrie.cfg
[honeypot]
hostname = srv-prod-db01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog = true
ttylog_path = var/lib/cowrie/tty

[ssh]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json
epoch_timestamp = false
EOF
chown -R cowrie:cowrie /home/cowrie/cowrie/etc/cowrie.cfg

# 6. Port Redirection: Direct incoming Port 22 traffic to Cowrie on Port 2223
echo "[*] Setting up iptables port redirection 22 -> 2223..."
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2223
netfilter-persistent save || true

# 7. Systemd service for Cowrie
cat <<'EOF' > /etc/systemd/system/cowrie.service
[Unit]
Description=Cowrie SSH Honeypot Service
After=network.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start -n
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie

# 8. Configure Nagios NRPE & Custom Check Script
mkdir -p /usr/lib/nagios/plugins/
cat <<'EOF' > /usr/lib/nagios/plugins/check_cowrie_activity.sh
#!/usr/bin/env bash
# Nagios plugin: check for new cowrie login/command activity
LOG_FILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
STATE_FILE="/tmp/cowrie_check_last_lines.txt"

if [ ! -f "$LOG_FILE" ]; then
    echo "OK: Cowrie running, no log entries yet."
    exit 0
fi

TOTAL_LINES=$(wc -l < "$LOG_FILE" | tr -d ' ')
LAST_LINES=0
if [ -f "$STATE_FILE" ]; then
    LAST_LINES=$(cat "$STATE_FILE")
fi

echo "$TOTAL_LINES" > "$STATE_FILE"

# If total lines increased, examine the new events
if [ "$TOTAL_LINES" -gt "$LAST_LINES" ]; then
    DIFF=$((TOTAL_LINES - LAST_LINES))
    RECENT_ATTACKS=$(tail -n "$DIFF" "$LOG_FILE" | grep -E 'cowrie.login.success|cowrie.login.failed|cowrie.command.input' | wc -l)
    if [ "$RECENT_ATTACKS" -gt 0 ]; then
        LAST_EVENT=$(tail -n "$DIFF" "$LOG_FILE" | grep -E 'cowrie.login|cowrie.command' | tail -n 1)
        ATTACKER_IP=$(echo "$LAST_EVENT" | jq -r '.src_ip // "unknown"')
        CMD=$(echo "$LAST_EVENT" | jq -r '.input // .username // "unknown"')
        echo "CRITICAL: Attacker activity detected! IP: $ATTACKER_IP, Activity: $CMD | new_events=$DIFF"
        exit 2
    fi
fi

echo "OK: Cowrie operational. No recent attack activity | total_logs=$TOTAL_LINES"
exit 0
EOF
chmod +x /usr/lib/nagios/plugins/check_cowrie_activity.sh

# Configure NRPE allowed hosts and command
cat <<'EOF' >> /etc/nagios/nrpe.cfg
allowed_hosts=127.0.0.1,10.0.1.0/24
command[check_cowrie]=/usr/lib/nagios/plugins/check_cowrie_activity.sh
command[check_cowrie_proc]=/usr/lib/nagios/plugins/check_procs -c 1:10 -C cowrie
EOF

systemctl enable nagios-nrpe-server
systemctl restart nagios-nrpe-server

echo "[+] HoneyTrap Honeypot initialization complete."
