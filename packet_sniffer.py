from scapy.all import sniff, IP, TCP
import numpy as np
import csv
import os
import time
from src.responder import respond_to_intrusion

LOG_FILE = "data/processed/live_sniffer_log.csv"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def extract_features(pkt):
    features = np.zeros(41)
    try:
        if IP in pkt:
            features[0] = pkt[IP].ttl
            features[1] = pkt[IP].len
            features[2] = pkt[IP].proto

        if TCP in pkt:
            flags = pkt[TCP].flags
            features[3] = int(flags)
            features[4] = pkt[TCP].window

            # Artificial boost for SYN flood to help detection
            if flags == 2 and pkt[TCP].dport == 80:
                features[5] = 999

    except Exception as e:
        print(f"Feature extraction error: {e}")
    return features

def predict_intrusion(features):
    # Dummy model - replace with your trained model's predict method
    # Here, for demo, classify as attack if feature[5] > 500
    return 1 if features[5] > 500 else 0

def handle_packet(pkt):
    features = extract_features(pkt)
    prediction = predict_intrusion(features)
    src_ip = pkt[IP].src if IP in pkt else "127.0.0.1"

    # Log to CSV for dashboard
    try:
        with open(LOG_FILE, "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time.strftime("%H:%M:%S"), prediction])
    except Exception as e:
        print(f"Failed to log: {e}")

    if prediction == 1:
        print(f"[🚨 ALERT] Attack detected from {src_ip}")
    else:
        print(f"[✅] Normal from {src_ip}")

    respond_to_intrusion(features, prediction, attacker_ip=src_ip)

def start_sniffing():
    print("🛡️ Starting packet sniffing... (Press Ctrl+C to stop)")
    try:
        sniff(filter="ip", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user.")
    except Exception as e:
        print(f"Sniffer error: {e}")

if __name__ == "__main__":
    start_sniffing()
