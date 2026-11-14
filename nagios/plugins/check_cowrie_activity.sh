#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - Nagios Plugin: check_cowrie_activity.sh
# Monitors Cowrie JSON log for new attacker sessions, brute force, and commands
# ==============================================================================

COWRIE_LOG="${1:-/home/cowrie/cowrie/var/log/cowrie/cowrie.json}"
STATE_FILE="${STATE_FILE:-${TMPDIR:-${TMP:-/tmp}}/nagios_cowrie_pointer.dat}"

# Check if log file exists
if [ ! -f "$COWRIE_LOG" ]; then
    echo "OK: Cowrie active, waiting for initial events. ($COWRIE_LOG)"
    exit 0
fi

# Count total lines
CURRENT_LINES=$(wc -l < "$COWRIE_LOG" | tr -d ' ')

# Read last known line position
LAST_LINES=0
if [ -f "$STATE_FILE" ]; then
    LAST_LINES=$(cat "$STATE_FILE")
    # Verify file wasn't truncated / rotated
    if [ "$LAST_LINES" -gt "$CURRENT_LINES" ]; then
        LAST_LINES=0
    fi
fi

# Save current position for next iteration
echo "$CURRENT_LINES" > "$STATE_FILE"

# Calculate newly appended events
NEW_EVENTS=$((CURRENT_LINES - LAST_LINES))

if [ "$NEW_EVENTS" -le 0 ]; then
    echo "OK: No new honeypot events detected (Total: $CURRENT_LINES)"
    exit 0
fi

# Extract and analyze recent lines
RECENT_LOGS=$(tail -n "$NEW_EVENTS" "$COWRIE_LOG")

# Filter for security-critical events
LOGIN_FAILURES=$(echo "$RECENT_LOGS" | grep -c "cowrie.login.failed" || true)
LOGIN_SUCCESS=$(echo "$RECENT_LOGS" | grep -c "cowrie.login.success" || true)
COMMANDS_TYPED=$(echo "$RECENT_LOGS" | grep -c "cowrie.command.input" || true)

TOTAL_ATTACKS=$((LOGIN_FAILURES + LOGIN_SUCCESS + COMMANDS_TYPED))

if [ "$TOTAL_ATTACKS" -gt 0 ]; then
    # Extract latest attacker IP and detail
    LAST_ATTACK=$(echo "$RECENT_LOGS" | grep -E "cowrie.login|cowrie.command" | tail -n 1)
    SRC_IP=$(echo "$LAST_ATTACK" | grep -o '"src_ip": "[^"]*"' | cut -d'"' -f4)
    [ -z "$SRC_IP" ] && SRC_IP=$(echo "$LAST_ATTACK" | grep -o '"src_ip":"[^"]*"' | cut -d'"' -f4)
    [ -z "$SRC_IP" ] && SRC_IP="Remote Attacker"

    USER_ATTEMPT=$(echo "$LAST_ATTACK" | grep -o '"username": "[^"]*"' | cut -d'"' -f4)
    CMD_ATTEMPT=$(echo "$LAST_ATTACK" | grep -o '"input": "[^"]*"' | cut -d'"' -f4)

    DETAIL="IP: $SRC_IP | Logins: $TOTAL_ATTACKS (Success: $LOGIN_SUCCESS, Failed: $LOGIN_FAILURES, Commands: $COMMANDS_TYPED)"
    if [ -n "$CMD_ATTEMPT" ]; then
        DETAIL="$DETAIL | Last Command: '$CMD_ATTEMPT'"
    elif [ -n "$USER_ATTEMPT" ]; then
        DETAIL="$DETAIL | Target User: '$USER_ATTEMPT'"
    fi

    echo "CRITICAL: Honeypot Intrusion Detected! $DETAIL"
    exit 2
fi

echo "OK: $NEW_EVENTS non-attack events logged (Total: $CURRENT_LINES)"
exit 0
