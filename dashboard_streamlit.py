# 📄 dashboard_streamlit.py

import streamlit as st
import pandas as pd
import numpy as np
import os
import time
import plotly.express as px
import random
import csv   # ✅ ADD THIS
import pathlib

# === Page Setup ===
st.set_page_config(page_title="AI-IDPS Live Dashboard", layout="wide")

# === Title ===
st.title("🛡️ AI-Powered Intrusion Detection Dashboard")
st.subheader("Monitoring real network traffic (via packet sniffer)...")

# === Paths
LOG_FILE = "data/processed/live_sniffer_log.csv"

# === Initialize State ===
if 'normal_count' not in st.session_state:
    st.session_state.normal_count = 0
if 'attack_count' not in st.session_state:
    st.session_state.attack_count = 0
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Normal", "Attack"])
if 'last_row_read' not in st.session_state:
    st.session_state.last_row_read = 0

# === User Controls ===
st.markdown("### 🧪 Demo Controls")

col1, col2 = st.columns([1, 1])
simulate_mode = col1.toggle("Enable Demo Mode (Simulate Attacks)", value=False)
reset_clicked = col2.button("🧹 Reset Logs")

if reset_clicked:
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    st.session_state.normal_count = 0
    st.session_state.attack_count = 0
    st.session_state.alerts = []
    st.session_state.traffic_history = pd.DataFrame(columns=["Time", "Normal", "Attack"])
    st.session_state.last_row_read = 0
    st.success("🧼 Logs cleared.")

# === Demo Simulation Mode (if enabled) ===
if simulate_mode:
    timestamp = time.strftime("%H:%M:%S")
    is_attack = 1 if random.random() < 0.3 else 0  # 30% chance it's an attack

    with open(LOG_FILE, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, is_attack])

    st.info(f"🧪 Simulated {'ATTACK' if is_attack else 'normal'} packet at {timestamp}")


# === Live Data Pull from Packet Sniffer ===
if os.path.exists(LOG_FILE):
    df = pd.read_csv(LOG_FILE, names=["Time", "Prediction"])
    new_data = df.iloc[st.session_state.last_row_read:]
    st.session_state.last_row_read = len(df)

    # Update metrics
    normal_new = (new_data["Prediction"] == 0).sum()
    attack_new = (new_data["Prediction"] == 1).sum()
    st.session_state.normal_count += normal_new
    st.session_state.attack_count += attack_new

    # Update alerts
    for _, row in new_data.iterrows():
        if row["Prediction"] == 1:
            st.session_state.alerts.append(f"🚨 Attack detected at {row['Time']}")

    # Update traffic history
    grouped = df.groupby("Time")["Prediction"].value_counts().unstack(fill_value=0)
    grouped = grouped.rename(columns={0: "Normal", 1: "Attack"}).reset_index()
    st.session_state.traffic_history = grouped

# === Layout Metrics ===
col1, col2, col3 = st.columns(3)
col1.metric("✅ Normal Packets", value=st.session_state.normal_count)
col2.metric("🚨 Detected Attacks", value=st.session_state.attack_count)
total = st.session_state.normal_count + st.session_state.attack_count
attack_ratio = (st.session_state.attack_count / total * 100) if total > 0 else 0
col3.metric("📊 Attack Rate", f"{attack_ratio:.2f} %")

st.divider()

# === Alerts ===
st.subheader("Live Alerts:")
if st.session_state.alerts:
    st.text("\n".join(st.session_state.alerts[-5:]))
else:
    st.info("Waiting for live packet data...")

st.divider()

# === Chart: Time Series ===
st.subheader("📈 Packet Flow Over Time")
if not st.session_state.traffic_history.empty:
    chart_df = st.session_state.traffic_history.set_index("Time")
    st.line_chart(chart_df)

# === Chart: Pie ===
st.subheader("📊 Traffic Type Distribution")
pie_data = pd.DataFrame({
    "Type": ["Normal", "Attack"],
    "Count": [st.session_state.normal_count, st.session_state.attack_count]
})
pie_fig = px.pie(pie_data, names='Type', values='Count', color='Type',
                 color_discrete_map={'Normal': 'blue', 'Attack': 'red'})
st.plotly_chart(pie_fig, use_container_width=True)

# --- Blocked IPs Panel ---
st.subheader("🛑 Blocked IPs Log")

LOG_FILE_BLOCKED = "data/processed/firewall_log.txt"

if pathlib.Path(LOG_FILE_BLOCKED).exists():
    with open(LOG_FILE_BLOCKED, "r") as f:
        lines = f.readlines()

    if lines:
        # Parse lines into a table: datetime and IP
        data = []
        for line in lines[-10:]:  # show last 10 blocked IPs
            parts = line.strip().split(" - Blocked IP: ")
            if len(parts) == 2:
                timestamp, ip = parts
                data.append({"Time": timestamp, "IP Address": ip})

        st.table(data)
    else:
        st.info("No IPs blocked yet.")
else:
    st.info("No firewall log found. No IPs blocked yet.")