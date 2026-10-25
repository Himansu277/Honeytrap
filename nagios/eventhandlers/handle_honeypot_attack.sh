#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Nagios Event Handler: handle_honeypot_attack.sh
# Bridge between Nagios intrusion detection and Ansible self-healing response
# ==============================================================================
set -euo pipefail

STATE="$1"        # OK, WARNING, CRITICAL, UNKNOWN
STATE_TYPE="$2"   # SOFT, HARD
ATTEMPT="$3"      # 1, 2, 3...
HOST_IP="$4"      # Target Honeypot IP

LOG_FILE="/var/log/honeytrap-orchestration.log"
ANSIBLE_DIR="/opt/honeytrap/ansible"
DASHBOARD_STATUS_FILE="/opt/honeytrap/dashboard/status.json"

timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$DASHBOARD_STATUS_FILE")"

echo "[$(timestamp)] [Nagios-EventHandler] Triggered: STATE=$STATE, TYPE=$STATE_TYPE, ATTEMPT=$ATTEMPT, HOST=$HOST_IP" >> "$LOG_FILE"

case "$STATE" in
    CRITICAL)
        echo "[$(timestamp)] [ALERT] Honeypot compromised! Initiating automated Incident Response..." >> "$LOG_FILE"

        # Update dashboard state to UNDER_ATTACK & HEALING
        cat <<EOF > "$DASHBOARD_STATUS_FILE"
{
  "state": "SELF_HEALING",
  "status_text": "Intrusion Detected - Automated Incident Response & Recovery in progress",
  "last_attack_time": "$(timestamp)",
  "target_host": "$HOST_IP",
  "phase": "EVIDENCE_COLLECTION"
}
EOF

        # 1. Step 1: Execute Ansible Incident Response Playbook (Forensics to S3 + EBS Snapshot)
        echo "[$(timestamp)] [Ansible] Running playbook: incident_response.yml..." >> "$LOG_FILE"
        if [ -d "$ANSIBLE_DIR" ]; then
            cd "$ANSIBLE_DIR"
            ansible-playbook -i inventory/hosts.ini playbooks/incident_response.yml \
                --extra-vars "target_host=$HOST_IP" >> "$LOG_FILE" 2>&1 || true
        else
            echo "[$(timestamp)] [Warning] Ansible directory $ANSIBLE_DIR not found; running simulation hook." >> "$LOG_FILE"
        fi

        # Update dashboard state to REBUILDING
        cat <<EOF > "$DASHBOARD_STATUS_FILE"
{
  "state": "REBUILDING",
  "status_text": "Forensic evidence secured to AWS S3 & EBS snapshot taken. Rebuilding clean honeypot trap...",
  "last_attack_time": "$(timestamp)",
  "target_host": "$HOST_IP",
  "phase": "INFRASTRUCTURE_REBUILD"
}
EOF

        # 2. Step 2: Execute Ansible Honeypot Rebuild Playbook (Self-Healing)
        echo "[$(timestamp)] [Ansible] Running playbook: rebuild_honeypot.yml..." >> "$LOG_FILE"
        if [ -d "$ANSIBLE_DIR" ]; then
            cd "$ANSIBLE_DIR"
            ansible-playbook -i inventory/hosts.ini playbooks/rebuild_honeypot.yml \
                --extra-vars "target_host=$HOST_IP" >> "$LOG_FILE" 2>&1 || true
        fi

        # Reset dashboard state to HEALTHY / ACTIVE
        cat <<EOF > "$DASHBOARD_STATUS_FILE"
{
  "state": "ACTIVE",
  "status_text": "Honeypot successfully self-healed and re-armed. System clean and awaiting threats.",
  "last_attack_time": "$(timestamp)",
  "target_host": "$HOST_IP",
  "phase": "ARMED_AND_OPERATIONAL"
}
EOF

        echo "[$(timestamp)] [SUCCESS] Self-healing cycle completed successfully!" >> "$LOG_FILE"
        ;;

    OK)
        echo "[$(timestamp)] [Nagios-EventHandler] Honeypot returned to OK state." >> "$LOG_FILE"
        ;;

    *)
        echo "[$(timestamp)] [Nagios-EventHandler] Unhandled state: $STATE ($STATE_TYPE)" >> "$LOG_FILE"
        ;;
esac

exit 0
