# 📄 simulate_attack.py

import csv
import os
import time
import random
from datetime import datetime

LOG_FILE = "data/processed/live_sniffer_log.csv"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

print("🧪 Simulating attack traffic... (Press Ctrl+C to stop)\n")

try:
    while True:
        timestamp = datetime.now().strftime("%H:%M:%S")

        # 🔁 Randomly decide normal or attack
        is_attack = 1 if random.random() < 0.3 else 0

        with open(LOG_FILE, "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, is_attack])

        if is_attack:
            print(f"[🚨 Simulated Attack] at {timestamp}")
        else:
            print(f"[✅ Simulated Normal] at {timestamp}")

        time.sleep(2)  # simulate packet every 2 seconds

except KeyboardInterrupt:
    print("\n🛑 Simulation stopped by user.")
