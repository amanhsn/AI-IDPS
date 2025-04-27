# 📄 detector.py

import numpy as np
import joblib
import pandas as pd
import datetime
import os

# === Paths ===
MODEL_PATH = 'data/processed/xgb_full_model.joblib'   # or xgb_pca_model.joblib
SCALER_PATH = None  # If you had a separate scaler saved
LOG_FILE = 'data/processed/detection_logs.csv'

# === Load Model ===
model = joblib.load(MODEL_PATH)

# === Detector Function ===
def predict_intrusion(sample):
    """
    Predicts if the given network sample is normal or an intrusion.
    
    Args:
    - sample: List or 1D numpy array of feature values
    
    Returns:
    - prediction: 0 (normal) or 1 (attack)
    """
    sample = np.array(sample).reshape(1, -1)
    pred = model.predict(sample)[0]
    return pred

# === Response Function ===
def respond_to_intrusion(sample, prediction):
    """
    Handle detection response: print alert and log incident.
    """
    if prediction == 1:
        print(f"[ALERT 🚨] Intrusion detected at {datetime.datetime.now()}")
        log_intrusion(sample)
    else:
        print(f"[INFO ✅] Normal traffic at {datetime.datetime.now()}")

# === Logger Function ===
def log_intrusion(sample):
    """
    Log malicious samples to CSV for tracking.
    """
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    df = pd.DataFrame([sample])
    df['timestamp'] = datetime.datetime.now()
    
    if os.path.exists(LOG_FILE):
        df.to_csv(LOG_FILE, mode='a', header=False, index=False)
    else:
        df.to_csv(LOG_FILE, mode='w', header=True, index=False)

# === Example Usage ===
if __name__ == "__main__":
    # Example sample (random numbers matching number of features)
    fake_sample = np.random.rand(model.n_features_in_)
    
    prediction = predict_intrusion(fake_sample)
    respond_to_intrusion(fake_sample, prediction)
