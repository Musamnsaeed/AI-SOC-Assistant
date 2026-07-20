import os
import time
import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI Suricata SOC Dashboard", layout="wide")

st.title("🛡️ Enterprise AI SOC Assistant (Suricata IDS Ingestion)")
st.markdown("Live Network Intrusion Detection & MITRE ATT&CK Mapping powered by Llama 3.2")

csv_file = "alert_history.csv"

# Safe File Load with Error Handling
if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        st.warning("Reading live stream... Standby.")
        df = pd.DataFrame()
else:
    df = pd.DataFrame()

if not df.empty:
    # Handle possible column name variations safely
    verdict_col = 'AI_Verdict' if 'AI_Verdict' in df.columns else ('Verdict' if 'Verdict' in df.columns else None)
    mitre_col = 'MITRE_ID' if 'MITRE_ID' in df.columns else ('mitre_id' if 'mitre_id' in df.columns else None)
    
    total_alerts = len(df)
    
    if verdict_col:
        threats = len(df[df[verdict_col].astype(str).str.lower() == 'threat'])
        normal_events = len(df[df[verdict_col].astype(str).str.lower() == 'normal'])
    else:
        threats = 0
        normal_events = 0
    
    # Top Level Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Suricata IDS Alerts", total_alerts)
    col2.metric("Threats Flagged", threats, delta=f"{threats} active", delta_color="inverse")
    col3.metric("Normal / Benign", normal_events)
    
    st.markdown("---")
    
    left_col, right_col = st.columns([2, 1])
    
    with left_col:
        st.subheader("📝 Live Security Event Stream")
        st.dataframe(df, use_container_width=True)
        
    with right_col:
        st.subheader("🎯 MITRE ATT&CK Techniques Detected")
        if mitre_col:
            # Filter out N/A or empty values
            filtered_mitre = df[~df[mitre_col].astype(str).isin(['N/A', 'None', 'nan', ''])]
            if not filtered_mitre.empty:
                mitre_counts = filtered_mitre[mitre_col].value_counts()
                st.bar_chart(mitre_counts)
            else:
                st.info("No MITRE techniques mapped yet.")
        else:
            st.info("MITRE ID column not detected.")
else:
    st.info("⏳ Awaiting alert stream from Suricata IDS... (Run `suricata_ai_agent.py` to populate data)")

# Auto-refresh UI every 5 seconds for live dashboard experience
time.sleep(5)
st.rerun()