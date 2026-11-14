#!/usr/bin/env python3
"""
HoneyTrap - Native Python SSH Honeypot Service (Paramiko-based)
===============================================================
A lightweight, low-interaction SSH honeypot tailored for Windows 11 and local testing.

Key Features & Security Controls:
1. Listens on 127.0.0.1:2222 only (Loopback isolation).
2. Generates an RSA SSH host key automatically if not present.
3. Captures connection timestamps, source IPs, usernames, and auth outcomes.
4. REJECTS all authentication attempts. Never grants shell or exec permissions.
5. NEVER logs or saves passwords (strictly adheres to security requirements).
6. Writes authentic JSON events to dashboard/data/cowrie.json in Cowrie format.
7. Safe shutdown handling via Ctrl+C.

Usage:
  Start: python scripts/honeypot_service.py
  Stop : Press Ctrl+C in the terminal
"""

import os
import sys
import json
import time
import uuid
import socket
import signal
import threading
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("[ERROR] Paramiko is not installed. Please run: python -m pip install paramiko")
    sys.exit(1)

# Paths configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "dashboard", "data")
LOG_FILE = os.path.join(DATA_DIR, "cowrie.json")
HOST_KEY_FILE = os.path.join(SCRIPT_DIR, "honeypot_host_key")

# Honeypot network settings
BIND_HOST = "127.0.0.1"
BIND_PORT = 2222
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

# Thread-safe lock for log writing
log_lock = threading.Lock()
running = True


def get_iso_timestamp():
    """Returns current UTC timestamp in ISO 8601 format matching Cowrie."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log_cowrie_event(event_dict):
    """Safely appends a genuine event record to dashboard/data/cowrie.json."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with log_lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_dict) + "\n")
        except Exception as e:
            print(f"[!] Log write error: {e}")


def get_or_create_host_key():
    """Loads existing RSA host key or generates a new 2048-bit key."""
    if os.path.exists(HOST_KEY_FILE):
        try:
            return paramiko.RSAKey.from_private_key_file(HOST_KEY_FILE)
        except Exception as e:
            print(f"[!] Error loading existing host key ({e}). Generating new key...")

    print(f"[*] Generating new 2048-bit RSA host key at: {HOST_KEY_FILE} ...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    print("[+] Host key generated successfully.")
    return key


class HoneypotServerInterface(paramiko.ServerInterface):
    """
    Paramiko ServerInterface for HoneyTrap:
    - Rejects all authentication methods (password, publickey, none).
    - NEVER stores or logs submitted passwords.
    - Rejects all channel requests (no shell, exec, or port forwarding).
    """

    def __init__(self, client_ip, client_port, session_id):
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_id = session_id
        self.auth_attempts = 0

    def get_allowed_auths(self, username):
        """Advertises password and publickey authentication support."""
        return "password,publickey"

    def check_auth_none(self, username):
        """Rejects unauthenticated login attempts."""
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        """
        Handles password authentication attempts.
        SECURITY POLICY:
        - NEVER log or save the submitted password value.
        - ALWAYS reject authentication.
        """
        self.auth_attempts += 1
        timestamp = get_iso_timestamp()

        # Console notification (Password is strictly NOT shown)
        print(f" [!] [{timestamp[:19]}] Unauthorized login attempt - User: '{username}' | IP: {self.client_ip}:{self.client_port} (AUTH REJECTED)")

        # Record Cowrie-compatible JSON event (password is omitted / never stored)
        event = {
            "eventid": "cowrie.login.failed",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "dst_port": BIND_PORT,
            "session": self.session_id,
            "username": username,
            "timestamp": timestamp,
            "country": "Localhost (Test Lab)"
        }
        log_cowrie_event(event)

        # Always reject authentication
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Rejects public key authentication attempts and logs attempt."""
        self.auth_attempts += 1
        timestamp = get_iso_timestamp()

        print(f" [!] [{timestamp[:19]}] Unauthorized public-key attempt - User: '{username}' | IP: {self.client_ip} (AUTH REJECTED)")

        event = {
            "eventid": "cowrie.login.failed",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "dst_port": BIND_PORT,
            "session": self.session_id,
            "username": username,
            "auth_method": "publickey",
            "timestamp": timestamp,
            "country": "Localhost (Test Lab)"
        }
        log_cowrie_event(event)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        """Reject all channel requests - shell, exec, subsystem, port forwarding."""
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return False

    def check_channel_shell_request(self, channel):
        return False

    def check_channel_exec_request(self, channel, command):
        return False


def handle_client_connection(client_socket, client_addr, host_key):
    """Handles an incoming SSH client connection inside an isolated thread."""
    client_ip, client_port = client_addr
    session_id = uuid.uuid4().hex[:8]
    connect_time = get_iso_timestamp()

    print(f"\n[*] [{connect_time[:19]}] Inbound connection from {client_ip}:{client_port} (Session: {session_id})")

    # 1. Log session connection event
    connect_event = {
        "eventid": "cowrie.session.connect",
        "src_ip": client_ip,
        "src_port": client_port,
        "dst_port": BIND_PORT,
        "session": session_id,
        "timestamp": connect_time,
        "country": "Localhost (Test Lab)"
    }
    log_cowrie_event(connect_event)

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)

        server_interface = HoneypotServerInterface(client_ip, client_port, session_id)
        transport.start_server(server=server_interface)

        # Wait for transport negotiation / auth attempts
        channel = transport.accept(timeout=20)
        if channel is not None:
            channel.close()

        # Keep connection open briefly so client receives rejection banners
        while transport.is_active():
            time.sleep(0.5)

    except paramiko.SSHException as e:
        # Handshake / negotiation error or disconnect
        pass
    except (socket.error, EOFError, ConnectionResetError):
        # Client closed connection abruptly
        pass
    except Exception as e:
        print(f" [!] Connection exception ({session_id}): {e}")
    finally:
        # 2. Log session closed event
        close_time = get_iso_timestamp()
        close_event = {
            "eventid": "cowrie.session.closed",
            "src_ip": client_ip,
            "src_port": client_port,
            "session": session_id,
            "timestamp": close_time,
            "country": "Localhost (Test Lab)"
        }
        log_cowrie_event(close_event)

        print(f"[-] [{close_time[:19]}] Session closed: {session_id} ({client_ip}:{client_port})")

        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass


def start_honeypot():
    """Main loop for the HoneyTrap SSH Honeypot Service."""
    global running

    host_key = get_or_create_host_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((BIND_HOST, BIND_PORT))
        server_socket.listen(10)
        server_socket.settimeout(1.0)
    except Exception as e:
        print(f"[FATAL] Failed to bind honeypot to {BIND_HOST}:{BIND_PORT}: {e}")
        print("        Check if another process is using port 2222.")
        sys.exit(1)

    print("\n==================================================================")
    print("      HoneyTrap - Native Python SSH Honeypot Service (Paramiko)    ")
    print("==================================================================")
    print(f" [+] Listening Host : {BIND_HOST} (Loopback only - Safe)")
    print(f" [+] Listening Port : {BIND_PORT}")
    print(f" [+] Host Key File  : {HOST_KEY_FILE}")
    print(f" [+] Log Destination: {LOG_FILE}")
    print(" [+] Security Rules : ALL logins rejected. Zero shell/exec access.")
    print(" [+] Password Policy: Passwords are NEVER logged or saved.")
    print(" [+] Status         : ARMED & RUNNING. Waiting for connections...")
    print(" [!] Press Ctrl+C at any time to stop the service cleanly.")
    print("==================================================================\n")

    def signal_handler(signum, frame):
        global running
        print("\n\n[!] Shutdown signal received. Stopping honeypot service...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    while running:
        try:
            client_socket, client_addr = server_socket.accept()
            worker = threading.Thread(
                target=handle_client_connection,
                args=(client_socket, client_addr, host_key),
                daemon=True
            )
            worker.start()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                print(f"[!] Socket accept error: {e}")
            break

    try:
        server_socket.close()
    except Exception:
        pass

    print("[+] HoneyTrap SSH Honeypot service has stopped cleanly. Goodbye!\n")


if __name__ == "__main__":
    start_honeypot()
