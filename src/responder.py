import os
import platform
from datetime import datetime

LOG_FILE = "data/processed/firewall_log.txt"

def block_ip(ip_address):
    system = platform.system()

    if system == "Windows":
        cmd = f'netsh advfirewall firewall add rule name="BlockIntruder_{ip_address}" dir=in action=block remoteip={ip_address}'
    elif system == "Linux":
        cmd = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
    else:
        print("⚠️ Unsupported OS for blocking.")
        return

    try:
        os.system(cmd)
        print(f"🛡️ Blocked IP: {ip_address}")

        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now()} - Blocked IP: {ip_address}\n")

    except Exception as e:
        print(f"❌ Failed to block IP: {e}")

def respond_to_intrusion(features, prediction, attacker_ip=None):
    if prediction == 1:
        print("🚨 Intrusion detected. Triggering response...")
        if attacker_ip:
            block_ip(attacker_ip)
        else:
            print("⚠️ No attacker IP provided. Skipping block.")
