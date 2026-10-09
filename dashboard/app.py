import streamlit as st
import pandas as pd
import sqlite3
import time

DB_PATH = "storage/packets.db"

st.set_page_config(page_title="Kali Guardian", layout="wide")
st.title("Kali Guardian – Real-Time Network & Alerts")

col1, col2 = st.columns(2)
traffic_chart = col1.line_chart()
icmp_chart = col2.line_chart()

alert_placeholder = st.empty()
packet_table = st.empty()

def get_data():
    conn = sqlite3.connect(DB_PATH)
    packets = pd.read_sql_query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 100", conn)
    alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50", conn)
    conn.close()
    return packets, alerts

while True:
    packets, alerts = get_data()

    if not packets.empty:
        traffic_chart.add_rows(packets[["timestamp", "size"]].set_index("timestamp"))
        icmp_packets = packets[packets["protocol"] == "ICMP"]
        if not icmp_packets.empty:
            icmp_chart.add_rows(icmp_packets[["timestamp", "size"]].set_index("timestamp"))

    alert_placeholder.table(alerts)
    packet_table.table(packets)

    time.sleep(2)
