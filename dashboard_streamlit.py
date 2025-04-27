# 📄 dashboard_streamlit.py

import streamlit as st
import pandas as pd
import numpy as np
import time
import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
from src.detector import predict_intrusion, respond_to_intrusion

# === Page Setup ===
st.set_page_config(page_title="AI-IDPS Dashboard", layout="wide")

# === Title ===
st.title("🚨 Real-Time Intrusion Detection Dashboard")
st.subheader("Monitoring NSL-KDD real network traffic...")

# === Initialize State ===
if 'running' not in st.session_state:
    st.session_state.running = False
if 'normal_count' not in st.session_state:
    st.session_state.normal_count = 0
if 'attack_count' not in st.session_state:
    st.session_state.attack_count = 0
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Normal", "Attacks"])
if 'current_index' not in st.session_state:
    st.session_state.current_index = 0
if 'correct_predictions' not in st.session_state:
    st.session_state.correct_predictions = 0
if 'y_true' not in st.session_state:
    st.session_state.y_true = []
if 'y_pred' not in st.session_state:
    st.session_state.y_pred = []

# === Load Real Samples ===
DATA_DIR = 'data/processed/'
X_test = np.load(DATA_DIR + 'X_test.npy')
y_test = np.load(DATA_DIR + 'y_test.npy')

# === User Controls ===
start_button, stop_button, reset_button = st.columns(3)

if start_button.button("▶️ Start Detection"):
    st.session_state.running = True

if stop_button.button("⏹️ Stop Detection"):
    st.session_state.running = False

if reset_button.button("🔄 Reset Detection"):
    st.session_state.running = False
    st.session_state.normal_count = 0
    st.session_state.attack_count = 0
    st.session_state.alerts = []
    st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Normal", "Attacks"])
    st.session_state.current_index = 0
    st.session_state.correct_predictions = 0
    st.session_state.y_true = []
    st.session_state.y_pred = []
    st.rerun()

st.divider()

# === Layout Placeholders ===
col1, col2, col3 = st.columns(3)
col1.metric("✅ Normal Packets", value=st.session_state.normal_count)
col2.metric("🚨 Detected Attacks", value=st.session_state.attack_count)

# === Live Accuracy ===
if st.session_state.current_index > 0:
    live_accuracy = (st.session_state.correct_predictions / st.session_state.current_index) * 100
else:
    live_accuracy = 0.0
col3.metric("📈 Live Accuracy (%)", value=f"{live_accuracy:.2f}%")

st.divider()

# === Live Alerts Section ===
st.subheader("Live Alerts:")
alert_placeholder = st.empty()

st.divider()

# === Traffic Overview ===
st.subheader("Traffic Overview Over Time")
chart_placeholder = st.empty()

st.subheader("Traffic Type Distribution")
pie_placeholder = st.empty()

st.subheader("📊 Live Confusion Matrix")
conf_matrix_placeholder = st.empty()

# === Single Detection Step ===
if st.session_state.running and st.session_state.current_index < len(X_test):
    # Fetch real sample
    sample = X_test[st.session_state.current_index]
    true_label = y_test[st.session_state.current_index]

    prediction = predict_intrusion(sample)

    # Track true and predicted
    st.session_state.y_true.append(true_label)
    st.session_state.y_pred.append(prediction)

    if prediction == true_label:
        st.session_state.correct_predictions += 1

    if prediction == 1:
        st.session_state.attack_count += 1
        st.session_state.alerts.append(f"🚨 Attack detected at {time.strftime('%H:%M:%S')}")
        respond_to_intrusion(sample, prediction)
    else:
        st.session_state.normal_count += 1

    # Update traffic history
    current_time = time.strftime('%H:%M:%S')
    new_row = {"Time": current_time,
               "Normal": st.session_state.normal_count,
               "Attacks": st.session_state.attack_count}
    
    st.session_state.traffic_history = pd.concat(
        [st.session_state.traffic_history, pd.DataFrame([new_row])],
        ignore_index=True
    )

    # Move to next sample
    st.session_state.current_index += 1

    time.sleep(1)
    st.rerun()

# === After Processing All Packets ===
if st.session_state.current_index >= len(X_test) and st.session_state.running:
    st.success("✅ Completed processing all samples!")
    st.session_state.running = False

# === Display UI at every step ===
if st.session_state.alerts:
    alert_placeholder.write("\n".join(st.session_state.alerts[-5:]))

if not st.session_state.traffic_history.empty:
    traffic_plot = st.session_state.traffic_history.set_index('Time')
    chart_placeholder.line_chart(traffic_plot)

pie_chart_data = pd.DataFrame({
    'Traffic Type': ['Normal', 'Attack'],
    'Count': [st.session_state.normal_count, st.session_state.attack_count]
})
pie_fig = px.pie(pie_chart_data, names='Traffic Type', values='Count',
                 color_discrete_map={'Normal':'blue', 'Attack':'red'})
pie_placeholder.plotly_chart(pie_fig, use_container_width=True)

# === Live Confusion Matrix Display ===
if st.session_state.y_true and st.session_state.y_pred:
    cm = confusion_matrix(st.session_state.y_true, st.session_state.y_pred, labels=[0,1])

    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt='d', cmap="Blues", cbar=False,
                xticklabels=["Normal", "Attack"],
                yticklabels=["Normal", "Attack"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix (Live)")

    conf_matrix_placeholder.pyplot(fig)
