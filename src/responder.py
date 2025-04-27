# 📄 responder.py

import pandas as pd
import datetime
import os

# === Paths ===
LOG_FILE = 'data/processed/detection_logs.csv'

# === Response Manager ===
class Responder:
    def __init__(self, log_file=LOG_FILE):
        self.log_file = log_file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def handle_intrusion(self, sample, details=""):
        """
        Respond to detected intrusion.
        
        Args:
        - sample: List or array of feature values
        - details: Optional additional details (e.g., 'Detected via XGBoost')
        """
        timestamp = datetime.datetime.now()
        print(f"[🚨 ALERT] Intrusion Detected - {timestamp}")
        print(f"Details: {details}")
        self.log_event(sample, timestamp, details)

    def log_event(self, sample, timestamp, details):
        """
        Logs the intrusion into CSV file.
        """
        df = pd.DataFrame([sample])
        df['timestamp'] = timestamp
        df['details'] = details

        if os.path.exists(self.log_file):
            df.to_csv(self.log_file, mode='a', header=False, index=False)
        else:
            df.to_csv(self.log_file, mode='w', header=True, index=False)

    def block_ip(self, ip_address):
        """
        (Optional Future) Block a given IP address (Linux only).
        """
        print(f"[⚙️ ACTION] Blocking IP: {ip_address}")
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
