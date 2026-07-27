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
    initial_sidebar_state="collapsed",
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

# ── PASS 1: FAST RULE-BASED HYBRID FILTERING (0 SECONDS PASS) ────────────────
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

    [data-testid="collapsedControl"],
    [data-testid="stSidebarNav"],
    section[data-testid="stSidebar"] {
        display: none !important;
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

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #0f172a;
        padding: 6px;
        border-radius: 10px;
        border: 1px solid #334155;
    }
    .stTabs [data-baseweb="tab"] {
        height: 42px;
        white-space: pre-wrap;
        border-radius: 8px;
        color: #94a3b8;
        font-weight: 600;
        font-size: 0.88rem;
        padding: 0 16px;
        border: none !important;
        background-color: transparent;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #1e293b, #334155) !important;
        color: #38bdf8 !important;
        border: 1px solid #0284c7 !important;
        box-shadow: 0 4px 12px rgba(2, 132, 199, 0.2);
    }

    .alert-row {
        background: #0f172a;
        border-left: 4px solid #38bdf8;
        border-radius: 6px;
        padding: 0.9rem 1.1rem;
        margin-bottom: 0.6rem;
        border-top: 1px solid #1e293b;
        border-right: 1px solid #1e293b;
        border-bottom: 1px solid #1e293b;
    }
    .alert-row.critical { border-left-color: #dc2626; background: rgba(220, 38, 38, 0.05); }
    .alert-row.high     { border-left-color: #ef4444; background: rgba(239, 68, 68, 0.04); }
    .alert-row.medium   { border-left-color: #f59e0b; background: rgba(245, 158, 11, 0.04); }
    .alert-row.low      { border-left-color: #10b981; background: rgba(16, 185, 129, 0.04); }

    .sev-pill {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 4px;
        text-transform: uppercase;
    }
    .sev-pill.critical { background: rgba(220, 38, 38, 0.2); color: #fca5a5; border: 1px solid #dc2626; }
    .sev-pill.high     { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }
    .sev-pill.medium   { background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid #f59e0b; }
    .sev-pill.low      { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid #10b981; }

    .mitre-badge {
        display: inline-block;
        background: linear-gradient(135deg, #312e81, #1e1b4b);
        color: #a5b4fc;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 6px;
        border: 1px solid #4338ca;
        margin-right: 6px;
    }

    .tactic-tile {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 0.8rem;
        min-height: 140px;
    }
    .tactic-header {
        font-size: 0.82rem;
        font-weight: 700;
        color: #38bdf8;
        border-bottom: 1px solid #334155;
        padding-bottom: 0.4rem;
        margin-bottom: 0.6rem;
        text-transform: uppercase;
    }

    /* ── Floating Custom Component Placement (FIXED OVERLAY CLICK ISSUE) ── */
    div[data-testid="stCustomComponentV1"],
    div[data-testid="element-container"]:has(iframe),
    .stElementContainer:has(iframe),
    iframe[title="components.html"],
    iframe[title="st.iframe"] {
        position: fixed !important;
        bottom: 0px !important;
        right: 0px !important;
        width: 420px !important;
        height: 650px !important;
        z-index: 999999 !important;
        background: transparent !important;
        border: none !important;
        pointer-events: none !important; /* 🔥 INVISIBLE IFRAME AREA KO CLICK-THROUGH BANA DEGA */
    }

    div[data-testid="element-container"]:has(iframe),
    .stElementContainer:has(iframe) {
        height: 0px !important;
        min-height: 0px !important;
        margin: 0px !important;
        padding: 0px !important;
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

# Render KPI Cards
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
tab_overview, tab_mitre, tab_investigator, tab_threatintel = st.tabs([
    "📊 Executive SOC Analytics",
    "🎯 MITRE ATT&CK Matrix",
    "⚡ Real-Time Alert Feed",
    "🔍 Threat Intel Workbench"
])

# TAB 1: EXECUTIVE SOC ANALYTICS
with tab_overview:
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
with tab_mitre:
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
with tab_investigator:
    st.markdown("### ⚡ Fast Hybrid Log Stream")
    
    if not df.empty:
        fc1, fc2 = st.columns([3, 1])
        with fc1:
            search_query = st.text_input("🔍 Search Logs:", placeholder="e.g. 192.168.1.105, SSH, T1110...", key="search_log_input")
        with fc2:
            sev_filter = st.multiselect("Filter Severity:", options=df['severity_clean'].unique(), default=[], key="filter_sev_select")

        filtered_df = df.copy()
        if search_query:
            q = search_query.lower()
            mask = filtered_df.astype(str).apply(lambda row: row.str.lower().str.contains(q).any(), axis=1)
            filtered_df = filtered_df[mask]
        if sev_filter:
            filtered_df = filtered_df[filtered_df['severity_clean'].isin(sev_filter)]

        for idx, row in filtered_df.iloc[::-1].head(25).iterrows():
            sig     = str(row.get(sig_col, 'Unknown Alert')) if sig_col else 'Unknown Alert'
            sev     = str(row.get('severity_clean', 'Low'))
            mid     = str(row.get(mitre_col, 'N/A')) if mitre_col else 'N/A'
            ts      = str(row.get(ts_col, '')) if ts_col else ''
            src     = str(row.get(src_col, '')) if src_col else ''
            dst     = str(row.get(dst_col, '')) if dst_col else ''

            card_cls = sev.lower() if sev.lower() in ('critical', 'high', 'medium', 'low') else 'low'

            st.markdown(
                f'<div class="alert-row {card_cls}">'
                f'<div style="display:flex;justify-content:space-between;">'
                f'<div><span class="sev-pill {card_cls}">{sev.upper()}</span> &nbsp; <b style="color:#f8fafc;">{sig}</b></div>'
                f'<span style="font-size:0.8rem;color:#64748b;">{ts[:19]}</span>'
                f'</div>'
                f'<div style="margin-top:0.4rem;font-size:0.82rem;color:#94a3b8;">'
                f'🌐 <b>Src:</b> {src} ➔ <b>Dst:</b> {dst} &nbsp;|&nbsp; <span class="mitre-badge">{mid}</span>'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True
            )

# TAB 4: THREAT INTEL WORKBENCH
with tab_threatintel:
    st.markdown("### 🔍 Threat Intelligence Sandbox & Reconnaissance")
    st.caption("Query external threat feeds (AbuseIPDB, VirusTotal) to analyze IP risk scores, geolocation, and malicious indicators.")
    
    if "searched_ip" not in st.session_state:
        st.session_state.searched_ip = None

    col_in1, col_in2 = st.columns([3, 1])
    with col_in1:
        target_ip_input = st.text_input("Enter IP Address / Domain to Investigate:", value="118.25.6.39", key="ip_input_field")
    with col_in2:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        btn_query = st.button("🚀 Query Threat Intel", key="btn_query_intel", use_container_width=True)

    if btn_query:
        st.session_state.searched_ip = target_ip_input

    if st.session_state.searched_ip:
        curr_ip = st.session_state.searched_ip

        with st.spinner(f"Running automated reconnaissance on {curr_ip}..."):
            abuse_res = check_abuseipdb(curr_ip)
            vt_res    = check_virustotal(curr_ip)

        abuse_data = abuse_res.get('data', {}) if isinstance(abuse_res, dict) else {}
        vt_data    = vt_res.get('data', {}) if isinstance(vt_res, dict) else {}
        vt_attr    = vt_data.get('attributes', {}) if isinstance(vt_data, dict) else {}
        
        abuse_score  = abuse_data.get('abuseConfidenceScore', 0)
        vt_stats     = vt_attr.get('last_analysis_stats', {})
        vt_malicious = vt_stats.get('malicious', 0)
        vt_harmless  = vt_stats.get('harmless', 0)
        vt_suspicious = vt_stats.get('suspicious', 0)

        # ── 1. Top KPI Summary Cards ──
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric(
                label="Abuse Confidence Score", 
                value=f"{abuse_score}%", 
                delta="High Risk" if abuse_score > 50 else "Low Risk", 
                delta_color="inverse"
            )
        with m2:
            st.metric(
                label="VirusTotal Detections", 
                value=f"{vt_malicious} Engines", 
                delta="Flagged Malicious" if vt_malicious > 0 else "Clean", 
                delta_color="inverse"
            )
        with m3:
            st.metric(
                label="VT Suspicious / Harmless", 
                value=f"{vt_suspicious} / {vt_harmless}"
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

        # ── 2. Detailed Reports Tabs ──
        intel_tab1, intel_tab2, intel_tab3 = st.tabs([
            "🛡️ AbuseIPDB Detailed Report", 
            "🦠 VirusTotal Detailed Analysis", 
            "📜 Raw API Payloads"
        ])

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
                st.markdown(f"**Total Abuse Reports:** `{abuse_data.get('totalReports', 0)}`")
                st.markdown(f"**Distinct Reporters:** `{abuse_data.get('numDistinctUsers', 0)}`")
                st.markdown(f"**Last Reported At:** `{abuse_data.get('lastReportedAt', 'N/A')}`")
                st.markdown(f"**Tor Exit Node:** `{'Yes 🚨' if abuse_data.get('isTor') else 'No ✅'}`")
                st.markdown(f"**Whitelisted Status:** `{'Whitelisted ✅' if abuse_data.get('isWhitelisted') else 'Not Whitelisted'}`")

        with intel_tab2:
            st.markdown("#### 🦠 VirusTotal Multi-Engine Vendor Analysis")
            if vt_stats:
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
            else:
                st.info("VirusTotal key rate limited ya empty format detection. Active indicators loaded.")

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

# ── FLOATING AI LOG ASSISTANT (HTML/JS COMPONENT WITH POINTER-EVENTS FIX) ──────
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
  body {{ background: transparent; overflow: hidden; pointer-events: none; }} /* 🔥 Click-through background */

  /* ── Floating FAB button ── */
  #fab {{
    position: fixed;
    bottom: 24px;
    right: 24px;
    width: 60px;
    height: 60px;
    border-radius: 50%;
    background: linear-gradient(135deg, #1d4ed8, #7c3aed);
    box-shadow: 0 4px 24px rgba(124,58,237,0.6);
    border: none;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    z-index: 9999;
    pointer-events: auto !important; /* Button fully interactive */
    animation: pulse 2.5s ease-in-out infinite;
    transition: transform 0.2s;
  }}
  #fab:hover {{ transform: scale(1.1); }}
  #fab .badge {{
    position: absolute;
    top: 3px; right: 3px;
    width: 13px; height: 13px;
    background: #22c55e;
    border-radius: 50%;
    border: 2px solid #0d1117;
    animation: blink 1.5s ease-in-out infinite;
  }}
  @keyframes pulse {{
    0%,100% {{ box-shadow: 0 4px 24px rgba(124,58,237,0.6); }}
    50%      {{ box-shadow: 0 4px 36px rgba(124,58,237,0.9); }}
  }}
  @keyframes blink {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.2; }} }}

  /* ── Chat panel ── */
  #chat-panel {{
    display: none;
    position: fixed;
    bottom: 96px;
    right: 24px;
    width: 360px;
    max-height: 520px;
    background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #30363d;
    border-radius: 16px;
    box-shadow: 0 12px 40px rgba(0,0,0,0.6);
    flex-direction: column;
    overflow: hidden;
    z-index: 9998;
    pointer-events: auto !important; /* Panel fully interactive */
    animation: slideUp 0.25s ease;
  }}
  @keyframes slideUp {{
    from {{ opacity:0; transform: translateY(20px); }}
    to   {{ opacity:1; transform: translateY(0); }}
  }}
  #chat-panel.open {{ display: flex; }}

  /* Header */
  .ch {{
    background: linear-gradient(135deg, #1d4ed8, #7c3aed);
    padding: 14px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }}
  .ch-title {{ color:#fff; font-weight:700; font-size:0.95rem; }}
  .ch-sub   {{ color:rgba(255,255,255,0.7); font-size:0.72rem; margin-top:2px; }}
  .ch-close {{
    background: rgba(255,255,255,0.15);
    border: none; color:#fff; cursor:pointer;
    width:28px; height:28px; border-radius:50%;
    font-size:16px; display:flex; align-items:center; justify-content:center;
  }}
  .ch-close:hover {{ background:rgba(255,255,255,0.3); }}

  /* Messages area */
  #msgs {{
    flex: 1;
    overflow-y: auto;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    scroll-behavior: smooth;
  }}
  #msgs::-webkit-scrollbar {{ width:4px; }}
  #msgs::-webkit-scrollbar-track {{ background:#0d1117; }}
  #msgs::-webkit-scrollbar-thumb {{ background:#30363d; border-radius:2px; }}

  .empty-state {{
    text-align:center; padding:24px 10px; color:#4a5568;
    font-size:0.8rem; line-height:1.7;
  }}
  .empty-state .es-icon {{ font-size:2.2rem; margin-bottom:8px; }}
  .empty-state i {{ color:#374151; }}

  .bubble {{ max-width:85%; padding:9px 13px; border-radius:14px; font-size:0.83rem; line-height:1.5; word-wrap:break-word; }}
  .bubble.user {{ align-self:flex-end; background:linear-gradient(135deg,#1d4ed8,#2563eb); color:#fff; border-radius:14px 14px 4px 14px; }}
  .bubble.ai   {{ align-self:flex-start; background:#1c2333; color:#e6edf3; border:1px solid #30363d; border-radius:14px 14px 14px 4px; }}
  .bubble.typing {{ color:#6e7681; font-style:italic; }}
  .lbl {{ font-size:0.68rem; color:#6e7681; margin-bottom:2px; }}
  .lbl.user {{ align-self:flex-end; }}
  .lbl.ai   {{ align-self:flex-start; }}

  /* Input row */
  .input-row {{
    padding: 10px 12px;
    border-top: 1px solid #21262d;
    display: flex;
    gap: 8px;
    flex-shrink: 0;
    background: #0d1117;
  }}
  #user-in {{
    flex:1;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    color: #e6edf3;
    font-size: 0.82rem;
    padding: 8px 12px;
    resize: none;
    outline: none;
    font-family: inherit;
  }}
  #user-in:focus {{ border-color: #1d4ed8; }}
  #user-in::placeholder {{ color:#4a5568; }}
  #send-btn {{
    background: linear-gradient(135deg, #1d4ed8, #7c3aed);
    border: none;
    border-radius: 10px;
    color: #fff;
    padding: 8px 14px;
    cursor: pointer;
    font-size:0.82rem;
    font-weight:600;
    white-space: nowrap;
    transition: opacity 0.2s;
  }}
  #send-btn:hover {{ opacity:0.85; }}
  #send-btn:disabled {{ opacity:0.4; cursor:not-allowed; }}

  .status-bar {{
    padding: 4px 14px 8px;
    font-size: 0.7rem;
    color: #4a5568;
    background: #0d1117;
    flex-shrink: 0;
  }}
  .dot-online {{ display:inline-block; width:6px; height:6px; background:#22c55e; border-radius:50%; margin-right:4px; vertical-align:middle; }}
</style>
</head>
<body>

<button id="fab" onclick="toggleChat()" title="Open AI Chat">
  🤖<span class="badge"></span>
</button>

<div id="chat-panel">
  <div class="ch">
    <div>
      <div class="ch-title">🤖 AI Log Assistant</div>
      <div class="ch-sub">Llama 3.2 · {df_total} alerts loaded</div>
    </div>
    <button class="ch-close" onclick="toggleChat()">✕</button>
  </div>

  <div id="msgs">
    <div class="empty-state" id="empty">
      <div class="es-icon">💬</div>
      Ask me anything about your<br>security alerts in plain English.<br><br>
      <i>e.g. "Show all critical threats"<br>"SSH brute force attempts"</i>
    </div>
  </div>

  <div class="status-bar">
    <span class="dot-online"></span>Ollama connected · {df_total} records ready
  </div>

  <div class="input-row">
    <textarea id="user-in" rows="2" placeholder="Ask about your alerts…"></textarea>
    <button id="send-btn" onclick="sendMsg()">Send ➤</button>
  </div>
</div>

<script>
const DF_CTX = {ctx_json};

function toggleChat() {{
  var panel = document.getElementById('chat-panel');
  panel.classList.toggle('open');
}}

document.getElementById('user-in').addEventListener('keydown', function(e) {{
  if (e.key === 'Enter' && !e.shiftKey) {{ e.preventDefault(); sendMsg(); }}
}});

function addMsg(role, text) {{
  var msgs = document.getElementById('msgs');
  var empty = document.getElementById('empty');
  if (empty) empty.remove();

  var lbl = document.createElement('div');
  lbl.className = 'lbl ' + role;
  lbl.textContent = role === 'user' ? 'You' : '🤖 AI';
  msgs.appendChild(lbl);

  var bub = document.createElement('div');
  bub.className = 'bubble ' + role;
  bub.textContent = text;
  msgs.appendChild(bub);
  msgs.scrollTop = msgs.scrollHeight;
  return bub;
}}

function sendMsg() {{
  var inp = document.getElementById('user-in');
  var btn = document.getElementById('send-btn');
  var text = inp.value.trim();
  if (!text) return;

  inp.value = '';
  addMsg('user', text);
  btn.disabled = true;

  var prompt = `You are an expert SOC analyst AI assistant.
The alert database has ${{DF_CTX.total}} records with columns: ${{DF_CTX.columns.join(', ')}}.
Sample records: ${{JSON.stringify(DF_CTX.sample)}}.

User question: "${{text}}"

Answer concisely and technically. If the user asks to filter/show records, describe what the filter would return based on the sample. Keep answer under 150 words.`;

  var typing = addMsg('ai', '⌛ Thinking…');
  typing.classList.add('typing');

  fetch('http://localhost:11434/api/generate', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      model: 'llama3.2',
      prompt: prompt,
      stream: false
    }})
  }})
  .then(function(r) {{ return r.json(); }})
  .then(function(data) {{
    typing.textContent = data.response || 'No response received.';
    typing.classList.remove('typing');
    btn.disabled = false;
    document.getElementById('msgs').scrollTop = 999999;
  }})
  .catch(function(err) {{
    typing.textContent = '⚠️ Could not reach Ollama. Make sure it is running at localhost:11434.';
    typing.classList.remove('typing');
    btn.disabled = false;
  }});
}}
</script>
</body>
</html>
"""

components.html(chat_html, height=650, scrolling=False)

time.sleep(5)
st.rerun()