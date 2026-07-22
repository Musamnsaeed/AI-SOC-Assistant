import os
import time
import pandas as pd
import streamlit as st
from threat_intel import check_abuseipdb, check_virustotal

st.set_page_config(page_title="AI Suricata SOC Dashboard", layout="wide")

st.title("🛡️ Enterprise AI SOC Assistant (Suricata IDS Ingestion)")
st.markdown("Live Network Intrusion Detection & MITRE ATT&CK Mapping powered by Llama 3.2")

csv_file = "alert_history.csv"

# Safe File Load with Error Handling
if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
    try:
        df = pd.read_csv(csv_file, on_bad_lines='skip')
    except Exception as e:
        st.warning(f"Reading live stream... Standby. ({e})")
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
                # Value counts calculate karein
                mitre_counts = filtered_mitre[mitre_col].value_counts().reset_index()
                mitre_counts.columns = ["MITRE ID", "Count"]

                # Streamlit Bar Chart render karein
                st.bar_chart(data=mitre_counts, x="MITRE ID", y="Count")
            else:
                st.info("No MITRE techniques mapped yet.")
        else:
            st.warning("No MITRE ID data available to plot.")

    st.markdown("---")
    st.subheader("🔍 Threat Intelligence Lookup")
    
    col_input, col_btn = st.columns([3, 1])
    with col_input:
        selected_ip = st.text_input("Enter IP Address to Check Threat Intel:", value="118.25.6.39")
    with col_btn:
        st.write("") # vertical spacing
        st.write("")
        check_btn = st.button("Check IP Reputation", use_container_width=True)

    if check_btn or ("threat_intel_ip" in st.session_state and st.session_state["threat_intel_ip"] == selected_ip):
        if check_btn:
            with st.spinner(f"Querying AbuseIPDB & VirusTotal for {selected_ip}..."):
                abuse_res = check_abuseipdb(selected_ip)
                vt_res = check_virustotal(selected_ip)
                st.session_state["threat_intel_ip"] = selected_ip
                st.session_state["threat_intel_data"] = (abuse_res, vt_res)
        
        if "threat_intel_data" in st.session_state:
            abuse_res, vt_res = st.session_state["threat_intel_data"]
            
            if not abuse_res.get("is_public", True):
                st.info(f"ℹ️ **{selected_ip}** is a **Private / Internal IP address**. Threat intelligence databases (AbuseIPDB & VirusTotal) only index public Internet IPs.")
            else:
                col1, col2 = st.columns(2)

                with col1:
                    st.metric(
                        label="AbuseIPDB Confidence Score",
                        value=f"{abuse_res['abuse_score']}%",
                        delta="High Risk" if abuse_res['abuse_score'] > 50 else "Clean / Low Risk"
                    )
                    st.write(f"Total Reports: **{abuse_res['total_reports']}** | Status: **{abuse_res.get('status', 'OK')}**")

                with col2:
                    st.metric(
                        label="VirusTotal Malicious Detections",
                        value=f"{vt_res['malicious_votes']} Vendors",
                        delta="Flagged" if vt_res['malicious_votes'] > 0 else "Clean"
                    )
                    st.write(f"Status: **{vt_res.get('status', 'OK')}**")
else:
    st.info("⏳ Awaiting alert stream from Suricata IDS... (Run `suricata_ai_agent.py` to populate data)")

# Auto-refresh UI every 5 seconds for live dashboard experience
time.sleep(5)
st.rerun()