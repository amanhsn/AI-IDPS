# 📄 simulate_realtime_detection.py

import time
import numpy as np
import random
from src.detector import predict_intrusion, respond_to_intrusion

# === Settings ===
TOTAL_SAMPLES = 50          # Number of simulated network packets
SLEEP_BETWEEN_SAMPLES = 1   # Seconds between incoming packets

# === Start Simulation ===
print("\n🎯 Starting Real-Time Intrusion Detection Simulation...\n")

for i in range(TOTAL_SAMPLES):
    # Generate a fake network packet with the correct number of features
    fake_packet = np.random.rand(predict_intrusion.__globals__['model'].n_features_in_)
    
    # Simulate occasional malicious behavior by amplifying values
    if random.random() < 0.05:  # 5% chance of attack
        fake_packet = fake_packet * np.random.uniform(1.5, 3.0)
    
    # Run prediction and handle response
    prediction = predict_intrusion(fake_packet)
    respond_to_intrusion(fake_packet, prediction)

    # Wait before next "packet" arrives
    time.sleep(SLEEP_BETWEEN_SAMPLES)

print("\n✅ Simulation completed!\n")
