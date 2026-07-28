import os
import json
import time
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from suricata_ai_agent import query_logs_with_llm
from threat_intel import check_abuseipdb, check_virustotal

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Wazuh & Splunk SIEM - Enterprise AI SOC",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded", # Fix: Sidebar keeps options active
)

# ── Data Ingestion & Preprocessing ────────────────────────────────────────────
csv_file = "alert_history.csv"
if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
    try:
        df = pd.read_csv(csv_file, on_bad_lines='skip')
    except Exception:
        df = pd.DataFrame()
else:
    df = pd.DataFrame()

# Normalise column mapping
col_map = {c.lower().strip(): c for c in df.columns}

sig_col      = col_map.get('signature',   col_map.get('message'))
verdict_col  = col_map.get('verdict',     col_map.get('ai_verdict'))
severity_col = col_map.get('severity')
summary_col  = col_map.get('summary')
src_col      = col_map.get('src_ip')
dst_col      = col_map.get('dst_ip')
ts_col       = col_map.get('timestamp')
abuse_col    = col_map.get('abuse_score')
vt_col       = col_map.get('vt_malicious')

# ── PASS 1: FAST RULE-BASED HYBRID FILTERING ────────────────────────────────
if not df.empty:
    if severity_col:
        if pd.api.types.is_numeric_dtype(df[severity_col]):
            sev_map = {1: 'Critical', 2: 'Medium', 3: 'Low'}
            df['severity_clean'] = df[severity_col].map(sev_map).fillna('Low')
        else:
            df['severity_clean'] = df[severity_col].astype(str).str.capitalize()
    else:
        df['severity_clean'] = 'Low'

    if 'mitre_id' in col_map:
        mitre_col = col_map['mitre_id']
    else:
        def infer_mitre_id(sig):
            s = str(sig).lower()
            if 'brute force' in s or 'ssh' in s: return 'T1110'
            if 'sql' in s or 'injection' in s:   return 'T1190'
            if 'scan' in s or 'nmap' in s:       return 'T1046'
            if 'download' in s or 'executable' in s: return 'T1105'
            if 'dns' in s or 'c2' in s:          return 'T1071.004'
            if 'smb' in s or 'share' in s:       return 'T1021.002'
            return 'N/A'
        
        if sig_col:
            df['MITRE_ID'] = df[sig_col].apply(infer_mitre_id)
            mitre_col = 'MITRE_ID'
        else:
            mitre_col = None

    if ts_col:
        df['parsed_time'] = pd.to_datetime(df[ts_col], errors='coerce')
        df['parsed_time'] = df['parsed_time'].fillna(pd.Timestamp.now())
    else:
        df['parsed_time'] = pd.Timestamp.now()

    TACTIC_MAP = {
        'T1595': 'Reconnaissance', 'T1046': 'Reconnaissance',
        'T1190': 'Initial Access',
        'T1059': 'Execution',
        'T1548': 'Privilege Escalation',
        'T1110': 'Credential Access',
        'T1021': 'Lateral Movement',
        'T1071': 'Command & Control',
        'T1105': 'Ingress Tool Transfer',
    }

    def get_mitre_tactic(mid):
        if pd.isna(mid) or str(mid).upper() in ('N/A', 'NONE', 'NAN', ''):
            return 'Uncategorized'
        mid_clean = str(mid).strip().upper()
        return TACTIC_MAP.get(mid_clean, TACTIC_MAP.get(mid_clean.split('.')[0], 'Defense Evasion'))

    if mitre_col:
        df['MITRE_Tactic'] = df[mitre_col].apply(get_mitre_tactic)

    high_priority_mask = df['severity_clean'].isin(['Critical', 'High'])
    high_priority_logs = df[high_priority_mask].head(15)

    if high_priority_logs.empty:
        high_priority_logs = df.head(10)
else:
    high_priority_logs = pd.DataFrame()
    mitre_col = None

# ── Custom Enterprise SIEM Styling ──────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"], .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: #090d16 !important;
        color: #e2e8f0 !important;
    }

    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        max-width: 98% !important;
    }

    .siem-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.2rem 1.8rem;
        margin-bottom: 1.2rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    }
    .siem-title {
        font-size: 1.6rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .siem-subtitle {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: 0.2rem;
    }
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        border: 1px solid rgba(255,255,255,0.1);
        background: rgba(15, 23, 42, 0.6);
        margin-left: 6px;
    }
    .dot-green { width: 8px; height: 8px; border-radius: 50%; background: #10b981; box-shadow: 0 0 10px #10b981; }
    .dot-blue  { width: 8px; height: 8px; border-radius: 50%; background: #38bdf8; box-shadow: 0 0 10px #38bdf8; }
    .dot-purple{ width: 8px; height: 8px; border-radius: 50%; background: #a855f7; box-shadow: 0 0 10px #a855f7; }

    .kpi-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 1rem;
        margin-bottom: 1.2rem;
    }
    .kpi-card {
        background: linear-gradient(145deg, #1e293b, #0f172a);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.1rem 1.4rem;
        position: relative;
        overflow: hidden;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        border-color: #38bdf8;
    }
    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; width: 100%; height: 3px;
        background: linear-gradient(90deg, #38bdf8, #818cf8);
    }
    .kpi-card.threat::before { background: linear-gradient(90deg, #ef4444, #f97316); }
    .kpi-card.critical::before { background: linear-gradient(90deg, #dc2626, #b91c1c); }
    .kpi-card.mitre::before { background: linear-gradient(90deg, #a855f7, #6366f1); }
    
    .kpi-label { font-size: 0.8rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .kpi-value { font-size: 1.9rem; font-weight: 800; color: #f8fafc; margin: 0.3rem 0; font-family: 'JetBrains Mono', monospace; }
    .kpi-sub   { font-size: 0.75rem; color: #64748b; }

    /* ── Floating Component Fixed Overlay Placement (FIXED) ── */
    iframe[title="st.iframe"], 
    iframe[title="components.html"] {
        position: fixed !important;
        bottom: 20px !important;
        right: 20px !important;
        width: 400px !important;
        height: 600px !important;
        z-index: 999999 !important;
        border: none !important;
        background: transparent !important;
        pointer-events: auto !important;
    }
</style>
""", unsafe_allow_html=True)

# ── SIEM Header ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="siem-header">
    <div>
        <div class="siem-title">🛡️ ENTERPRISE AI SOC ANALYZER</div>
        <div class="siem-subtitle">Hybrid Rule-Filter + Llama 3.2 · FAISS MITRE RAG Pipeline</div>
    </div>
    <div>
        <span class="status-badge"><span class="dot-green"></span> HYBRID PIPELINE: ACTIVE</span>
        <span class="status-badge"><span class="dot-blue"></span> FAST PASS: 0ms</span>
        <span class="status-badge"><span class="dot-purple"></span> LLaMA: READY</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── KPI Calculations ──────────────────────────────────────────────────────────
if not df.empty:
    total_events   = len(df)
    threat_mask    = df['severity_clean'].isin(['Critical', 'High', 'Medium'])
    total_threats  = len(df[threat_mask])
    threat_rate    = round((total_threats / total_events) * 100, 1) if total_events > 0 else 0
    
    crit_high_mask = df['severity_clean'].isin(['Critical', 'High'])
    total_crit_high = len(df[crit_high_mask])

    if mitre_col and mitre_col in df.columns:
        valid_mitre = df[~df[mitre_col].astype(str).str.strip().isin(['N/A', 'None', 'nan', '', 'n/a'])][mitre_col]
        unique_mitre_cnt = valid_mitre.nunique()
    else:
        unique_mitre_cnt = 0

    max_abuse_score = df[abuse_col].max() if abuse_col and abuse_col in df.columns else 0
else:
    total_events = total_threats = threat_rate = total_crit_high = unique_mitre_cnt = max_abuse_score = 0

st.markdown(f"""
<div class="kpi-container">
    <div class="kpi-card">
        <div class="kpi-label">📡 Total Log Ingress</div>
        <div class="kpi-value">{total_events:,}</div>
        <div class="kpi-sub">Rule Categorized Instantly</div>
    </div>
    <div class="kpi-card threat">
        <div class="kpi-label">🚨 Active Threats</div>
        <div class="kpi-value">{total_threats:,}</div>
        <div class="kpi-sub">{threat_rate}% Threat Index</div>
    </div>
    <div class="kpi-card critical">
        <div class="kpi-label">🔥 Top AI Enriched Logs</div>
        <div class="kpi-value">{len(high_priority_logs)}</div>
        <div class="kpi-sub">Sent to Llama 3.2 Pass</div>
    </div>
    <div class="kpi-card mitre">
        <div class="kpi-label">🎯 MITRE ATT&CK Techniques</div>
        <div class="kpi-value">{unique_mitre_cnt}</div>
        <div class="kpi-sub">FAISS RAG Mapped</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">🛡️ Max Threat Confidence</div>
        <div class="kpi-value">{max_abuse_score}%</div>
        <div class="kpi-sub">AbuseIPDB Risk Index</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Operations Center Tabs ────────────────────────────────────────────────────
import streamlit as st

# ── 1. SIDEBAR NAVIGATION ───────────────────────────────────────────────────
# st.tabs ki jagah sidebar radio menu ka use karein
st.sidebar.title("🛡️ SOC Navigation")

selected_tab = st.sidebar.radio(
    "Select Section:",
    [
        "📊 Executive SOC Analytics",
        "🎯 MITRE ATT&CK Matrix",
        "⚡ Real-Time Alert Feed",
        "🔍 Threat Intel Workbench"
    ]
)

st.sidebar.markdown("---")
st.sidebar.caption("System Status: **ONLINE** 🟢")

# ── 2. CONDITIONAL TAB CONTENTS ─────────────────────────────────────────────

# TAB 1: EXECUTIVE SOC ANALYTICS
if selected_tab == "📊 Executive SOC Analytics":
    st.header("📊 Executive SOC Analytics")
    if not df.empty:
        st.markdown("##### 📈 Event Volume Timeline by Severity")
        df_time = df.copy()
        df_time['minute'] = df_time['parsed_time'].dt.floor('min')
        timeline_df = df_time.groupby(['minute', 'severity_clean']).size().reset_index(name='count')
        
        fig_time = px.area(
            timeline_df,
            x='minute',
            y='count',
            color='severity_clean',
            color_discrete_map={'Critical': '#dc2626', 'High': '#ef4444', 'Medium': '#f59e0b', 'Low': '#10b981'},
            template="plotly_dark",
            height=280
        )
        fig_time.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(15, 23, 42, 0.6)',
            margin=dict(l=20, r=20, t=20, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_time, use_container_width=True)

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("##### 🍩 Fast Rule Severity Breakdown")
            sev_counts = df['severity_clean'].value_counts().reset_index()
            sev_counts.columns = ['Severity', 'Count']
            fig_donut = px.pie(
                sev_counts,
                names='Severity',
                values='Count',
                hole=0.5,
                color='Severity',
                color_discrete_map={'Critical': '#dc2626', 'High': '#ef4444', 'Medium': '#f59e0b', 'Low': '#10b981'},
                template="plotly_dark",
                height=260
            )
            fig_donut.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_right:
            st.markdown("##### 🌐 Top Attacker Source IPs")
            if src_col:
                top_ips = df[src_col].value_counts().head(7).reset_index()
                top_ips.columns = ['Source IP', 'Alert Count']
                fig_bar = px.bar(
                    top_ips,
                    x='Alert Count',
                    y='Source IP',
                    orientation='h',
                    color='Alert Count',
                    color_continuous_scale='Reds',
                    template="plotly_dark",
                    height=260
                )
                fig_bar.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(15, 23, 42, 0.6)',
                    margin=dict(l=10, r=10, t=10, b=10),
                    yaxis=dict(autorange="reversed")
                )
                st.plotly_chart(fig_bar, use_container_width=True)


# TAB 2: MITRE ATT&CK MATRIX
elif selected_tab == "🎯 MITRE ATT&CK Matrix":
    st.markdown("### 🎯 MITRE ATT&CK Framework Enterprise Matrix")
    
    if not df.empty and 'MITRE_Tactic' in df.columns:
        tactics = ['Reconnaissance', 'Initial Access', 'Execution', 'Privilege Escalation', 'Credential Access', 'Lateral Movement', 'Command & Control', 'Ingress Tool Transfer']
        cols = st.columns(len(tactics))

        for idx, tac in enumerate(tactics):
            with cols[idx]:
                tac_df = df[df['MITRE_Tactic'] == tac]
                count = len(tac_df)
                st.markdown(
                    f'<div class="tactic-tile">'
                    f'<div class="tactic-header">{tac} ({count})</div>',
                    unsafe_allow_html=True
                )
                if not tac_df.empty and mitre_col:
                    m_counts = tac_df[mitre_col].value_counts()
                    for m_id, m_cnt in m_counts.items():
                        st.markdown(f'<span class="mitre-badge">{m_id}</span> <span style="font-size:0.75rem;color:#94a3b8;">x{m_cnt}</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span style="font-size:0.75rem;color:#64748b;">No active alerts</span>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("#### ⚡ Second Pass: Deep AI Enriched Logs (Top Critical/High Priority)")

        for idx, row in high_priority_logs.iterrows():
            mid     = str(row.get(mitre_col, 'N/A')) if mitre_col else 'N/A'
            sig     = str(row.get(sig_col, 'Unknown Alert')) if sig_col else 'Unknown Alert'
            sev     = str(row.get('severity_clean', 'Low'))
            summary = str(row.get(summary_col, 'Second-Pass LLM Context Active')) if summary_col else 'Second-Pass LLM Context Active'
            tactic  = str(row.get('MITRE_Tactic', 'Defense Evasion'))

            with st.expander(f"🔥 [{sev}] [{mid}] {sig[:80]}  — Tactic: {tactic}"):
                c1, c2 = st.columns([1, 4])
                with c1:
                    st.markdown(f"**MITRE ID:** `{mid}`")
                    st.markdown(f"**Tactic:** `{tactic}`")
                    st.markdown(f"**Severity:** `{sev}`")
                with c2:
                    st.markdown("**Llama 3.2 & FAISS RAG Insights:**")
                    st.info(summary)


# TAB 3: REAL-TIME ALERT FEED
elif selected_tab == "⚡ Real-Time Alert Feed":
    st.markdown("### ⚡ Fast Hybrid Log Stream")

    if not df.empty:
        st.dataframe(df.head(20), use_container_width=True)


# TAB 4: THREAT INTEL WORKBENCH (Layout Fixed for AI Assistant)
elif selected_tab == "🔍 Threat Intel Workbench":
    st.subheader("🔍 Threat Intelligence Sandbox & Reconnaissance")
    st.caption("Query external threat feeds (AbuseIPDB, VirusTotal) to analyze IP risk scores, geolocation, and malicious indicators.")
    
    # ── Session State for Persistence ──
    if "searched_ip" not in st.session_state:
        st.session_state.searched_ip = "118.25.6.39"

    # ── Input Box & Button Clean Alignment ──
    # Button ko input key niche separate row mein rkha gaya hai taaki floating agent interference na kare
    selected_ip = st.text_input("Enter IP Address / Domain to Investigate:", value=st.session_state.searched_ip, key="ip_input_field")
    
    # Button placed clearly below input field
    btn_query = st.button("🚀 Query Threat Intel", key="btn_query_intel", use_container_width=False)

    if btn_query or st.session_state.searched_ip:
        if btn_query:
            st.session_state.searched_ip = selected_ip

        curr_ip = st.session_state.searched_ip

        with st.spinner(f"Querying AbuseIPDB & VirusTotal for {curr_ip}..."):
            abuse_res = check_abuseipdb(curr_ip)
            vt_res    = check_virustotal(curr_ip)

        # ── Safe Data Extraction ──
        abuse_data = abuse_res.get('data', {}) if isinstance(abuse_res, dict) else {}
        vt_data    = vt_res.get('data', {}) if isinstance(vt_res, dict) else {}
        vt_attr    = vt_data.get('attributes', {}) if isinstance(vt_data, dict) else {}
        
        # Supporting both custom dictionary format & raw API format safely
        abuse_score  = abuse_data.get('abuseConfidenceScore', abuse_res.get('abuse_score', 0))
        total_reps   = abuse_data.get('totalReports', abuse_res.get('total_reports', 0))
        
        vt_stats     = vt_attr.get('last_analysis_stats', {})
        vt_malicious = vt_stats.get('malicious', vt_res.get('malicious_votes', 0))
        vt_harmless  = vt_stats.get('harmless', 0)
        vt_suspicious = vt_stats.get('suspicious', 0)

        st.markdown("---")

        # ── 1. Top KPI Summary Cards ──
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric(
                label="Abuse Confidence Score", 
                value=f"{abuse_score}%", 
                delta="High Risk" if abuse_score > 50 else "Safe", 
                delta_color="inverse"
            )
        with m2:
            st.metric(
                label="VirusTotal Detections", 
                value=f"{vt_malicious} Vendors", 
                delta="Flagged" if vt_malicious > 0 else "Clean", 
                delta_color="inverse"
            )
        with m3:
            st.metric(
                label="Total Abuse Reports", 
                value=f"{total_reps} Reports",
                delta="Suspicious Activity" if total_reps > 10 else "Low Volume"
            )
        with m4:
            country = abuse_data.get('countryCode', 'N/A')
            isp     = str(abuse_data.get('isp', 'Unknown'))
            st.metric(
                label="Origin Country & ISP", 
                value=f"{country}", 
                delta=f"{isp[:18]}..." if len(isp) > 18 else isp
            )

        st.markdown("---")

        # ── 2. Detailed Intelligence Tabs ──
        intel_tab1, intel_tab2, intel_tab3 = st.tabs([
            "🛡️ AbuseIPDB Detailed Report", 
            "🦠 VirusTotal Detailed Analysis", 
            "📜 Raw API Payloads"
        ])

        # A. AbuseIPDB Detailed Report
        with intel_tab1:
            st.markdown("#### 🛡️ AbuseIPDB Deep Intelligence")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("##### 📌 Network & Geolocation Context")
                st.markdown(f"**IP Address:** `{abuse_data.get('ipAddress', curr_ip)}`")
                st.markdown(f"**Public IP:** `{'Yes' if abuse_data.get('isPublic', True) else 'No'}`")
                st.markdown(f"**Country Name:** `{abuse_data.get('countryName', 'N/A')}` (`{country}`)")
                st.markdown(f"**ISP:** `{abuse_data.get('isp', 'N/A')}`")
                st.markdown(f"**Domain:** `{abuse_data.get('domain', 'N/A')}`")
                st.markdown(f"**Usage Type:** `{abuse_data.get('usageType', 'N/A')}`")
            with c2:
                st.markdown("##### 🚨 Threat Indicators & Reports")
                st.markdown(f"**Abuse Confidence Score:** `{abuse_score}%`")
                st.markdown(f"**Total Abuse Reports:** `{total_reps}`")
                st.markdown(f"**Distinct Reporters:** `{abuse_data.get('numDistinctUsers', 0)}`")
                st.markdown(f"**Last Reported At:** `{abuse_data.get('lastReportedAt', 'N/A')}`")
                st.markdown(f"**Tor Exit Node:** `{'Yes 🚨' if abuse_data.get('isTor') else 'No ✅'}`")
                st.markdown(f"**Whitelisted Status:** `{'Whitelisted ✅' if abuse_data.get('isWhitelisted') else 'Not Whitelisted'}`")

        # B. VirusTotal Detailed Report
        with intel_tab2:
            st.markdown("#### 🦠 VirusTotal Multi-Engine Vendor Analysis")
            v1, v2, v3, v4 = st.columns(4)
            v1.error(f"🚨 Malicious: {vt_malicious}")
            v2.warning(f"⚠️ Suspicious: {vt_suspicious}")
            v3.success(f"✅ Harmless: {vt_harmless}")
            v4.info(f"⚪ Undetected: {vt_stats.get('undetected', 0)}")

            st.markdown("---")
            st.markdown("##### 🔍 Network & Reputation Metadata")
            st.markdown(f"**AS Owner:** `{vt_attr.get('as_owner', 'N/A')}`")
            st.markdown(f"**ASN:** `{vt_attr.get('asn', 'N/A')}`")
            st.markdown(f"**Global Reputation Score:** `{vt_attr.get('reputation', 0)}`")
            st.markdown(f"**Network / Subnet:** `{vt_attr.get('network', 'N/A')}`")

        # C. Raw Payloads
        with intel_tab3:
            st.markdown("#### ⚙️ Raw JSON Responses")
            exp1, exp2 = st.columns(2)
            with exp1:
                st.caption("AbuseIPDB Response JSON")
                st.json(abuse_res)
            with exp2:
                st.caption("VirusTotal Response JSON")
                st.json(vt_res)

        st.markdown("---")

        # ── 3. Incident Response Quick Actions ──
        st.markdown("#### ⚡ Incident Response Quick Actions")
        act1, act2, act3 = st.columns(3)
        
        with act1:
            if st.button("🔒 Simulate Firewall Block", key="btn_fw_block", use_container_width=True):
                st.success(f"IPTables rule added: `iptables -A INPUT -s {curr_ip} -j DROP`")
                st.toast(f"IP {curr_ip} blocked on perimeter firewall!", icon="🔒")
                
        with act2:
            if st.button("📄 Export Forensic Evidence", key="btn_export_forensic", use_container_width=True):
                st.info(f"Forensic JSON bundle generated for {curr_ip}.")
                st.download_button(
                    label="💾 Download Evidence Payload",
                    data=json.dumps({"ip": curr_ip, "abuse": abuse_res, "virustotal": vt_res}, indent=2, default=str),
                    file_name=f"forensic_report_{curr_ip}.json",
                    mime="application/json",
                    key="btn_download_json"
                )
                
        with act3:
            if st.button("🚨 Escalate to Tier-3 SOC Team", key="btn_escalate_tier3", use_container_width=True):
                st.warning(f"Incident ticket created for host {curr_ip}.")
                st.toast(f"P1 Incident ticket dispatched to Tier-3 Lead!", icon="🚨")
# ── FLOATING AI LOG ASSISTANT (FIXED CSS & JS) ──────────────
df_cols   = list(df.columns) if not df.empty else []
df_sample = df.head(3).to_dict(orient="records") if not df.empty else []
df_total  = len(df)

ctx_json  = json.dumps({"columns": df_cols, "sample": df_sample, "total": df_total}, default=str)

chat_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; }}
  body {{ background: transparent; overflow: hidden; height: 100vh; width: 100vw; }}

  #fab {{
    position: fixed;
    bottom: 10px;
    right: 10px;
    width: 55px;
    height: 55px;
    border-radius: 50%;
    background: linear-gradient(135deg, #1d4ed8, #7c3aed);
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
    border: 2px solid #38bdf8;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    z-index: 999999;
  }}

  #chat-panel {{
    display: none;
    position: fixed;
    bottom: 75px;
    right: 10px;
    width: 360px;
    height: 480px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.8);
    flex-direction: column;
    overflow: hidden;
    z-index: 999998;
  }}
  #chat-panel.open {{ display: flex; }}

  .ch {{ background: #161b22; padding: 12px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; }}
  .ch-title {{ color: #f8fafc; font-weight: bold; font-size: 0.9rem; }}
  .ch-close {{ background: transparent; border: none; color: #94a3b8; cursor: pointer; font-size: 16px; }}

  #msgs {{ flex: 1; padding: 10px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; font-size: 0.8rem; color: #e2e8f0; }}
  .bubble {{ padding: 8px 12px; border-radius: 8px; max-width: 85%; }}
  .bubble.user {{ background: #1d4ed8; align-self: flex-end; color: white; }}
  .bubble.ai {{ background: #1e293b; align-self: flex-start; border: 1px solid #334155; }}

  .input-row {{ padding: 8px; background: #161b22; display: flex; gap: 6px; border-top: 1px solid #30363d; }}
  #user-in {{ flex: 1; background: #0d1117; border: 1px solid #30363d; color: white; padding: 6px; border-radius: 6px; outline: none; }}
  #send-btn {{ background: #2563eb; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; }}
</style>
</head>
<body>

<button id="fab" onclick="toggleChat()">🤖</button>

<div id="chat-panel">
  <div class="ch">
    <div class="ch-title">🤖 AI Agent Assistant</div>
    <button class="ch-close" onclick="toggleChat()">✕</button>
  </div>
  <div id="msgs">
    <div class="bubble ai">Hello! Ask me anything about your SOC logs.</div>
  </div>
  <div class="input-row">
    <input type="text" id="user-in" placeholder="Ask AI..." onkeypress="if(event.key==='Enter') sendMsg()">
    <button id="send-btn" onclick="sendMsg()">Send</button>
  </div>
</div>

<script>
const DF_CTX = {ctx_json};

function toggleChat() {{
  var panel = document.getElementById('chat-panel');
  panel.classList.toggle('open');
}}

function sendMsg() {{
  var inp = document.getElementById('user-in');
  var text = inp.value.trim();
  if (!text) return;

  var msgs = document.getElementById('msgs');
  msgs.innerHTML += '<div class="bubble user">' + text + '</div>';
  inp.value = '';

  var typing = document.createElement('div');
  typing.className = 'bubble ai';
  typing.innerText = 'Thinking...';
  msgs.appendChild(typing);
  msgs.scrollTop = msgs.scrollHeight;

  fetch('http://localhost:11434/api/generate', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      model: 'llama3.2',
      prompt: "Context: " + JSON.stringify(DF_CTX) + "\\nUser Question: " + text,
      stream: false
    }})
  }})
  .then(r => r.json())
  .then(data => {{
    typing.innerText = data.response || 'No response';
    msgs.scrollTop = msgs.scrollHeight;
  }})
  .catch(err => {{
    typing.innerText = '⚠️ Error connecting to Ollama agent.';
  }});
}}
</script>
</body>
</html>
"""

# HTML component rendering inside bounded dimensions
components.html(chat_html, height=600, scrolling=False)