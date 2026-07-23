import os
import time
import pandas as pd
import streamlit as st
from threat_intel import check_abuseipdb, check_virustotal

st.set_page_config(page_title="AI Suricata SOC Dashboard", layout="wide", page_icon="🛡️")

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark premium theme */
    .stApp { background-color: #0d1117; color: #e6edf3; }
    .block-container { padding-top: 1.5rem; }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #161b22, #1f2937);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 1rem 1.5rem;
    }

    /* MITRE badge */
    .mitre-badge {
        display: inline-block;
        background: linear-gradient(135deg, #1a3a5c, #1e40af);
        color: #93c5fd;
        font-family: monospace;
        font-size: 0.85rem;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 6px;
        border: 1px solid #1d4ed8;
        margin-right: 6px;
    }

    /* Alert card */
    .alert-card {
        background: linear-gradient(135deg, #161b22, #1c2333);
        border-left: 4px solid #ef4444;
        border-radius: 0 10px 10px 0;
        padding: 0.9rem 1.2rem;
        margin-bottom: 0.7rem;
    }
    .alert-card.normal { border-left-color: #22c55e; }
    .alert-card.medium { border-left-color: #f59e0b; }
    .alert-card.critical { border-left-color: #dc2626; }

    /* MITRE reasoning box */
    .mitre-reasoning {
        background: #0d1117;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        font-size: 0.82rem;
        color: #8b949e;
        line-height: 1.6;
        white-space: pre-wrap;
        margin-top: 0.5rem;
    }

    /* Section headers */
    .section-header {
        font-size: 1.1rem;
        font-weight: 700;
        color: #58a6ff;
        border-bottom: 1px solid #21262d;
        padding-bottom: 0.4rem;
        margin-bottom: 1rem;
    }

    /* Severity pill */
    .sev-critical { color: #dc2626; font-weight: 700; }
    .sev-high     { color: #ef4444; font-weight: 700; }
    .sev-medium   { color: #f59e0b; font-weight: 700; }
    .sev-low      { color: #22c55e; font-weight: 700; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Enterprise AI SOC Assistant")
st.markdown("**Live Network Intrusion Detection & MITRE ATT&CK Mapping** — powered by Llama 3.2 + FAISS RAG")
st.markdown("---")

csv_file = "alert_history.csv"

# ── Load CSV ──────────────────────────────────────────────────────────────────
if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
    try:
        df = pd.read_csv(csv_file, on_bad_lines='skip')
    except Exception as e:
        st.warning(f"Reading live stream... Standby. ({e})")
        df = pd.DataFrame()
else:
    df = pd.DataFrame()

# ── Normalise column names (handle both legacy & current schema) ──────────────
col_map = {}
for c in df.columns:
    col_map[c.lower().strip()] = c

sig_col      = col_map.get('signature',   col_map.get('message'))
verdict_col  = col_map.get('ai_verdict',  col_map.get('verdict'))
severity_col = col_map.get('severity')
summary_col  = col_map.get('summary')
src_col      = col_map.get('src_ip')
dst_col      = col_map.get('dst_ip')
ts_col       = col_map.get('timestamp')

# Smart MITRE column detection or auto-infer for legacy rows
if 'mitre_id' in col_map:
    mitre_col = col_map['mitre_id']
else:
    # Auto-infer MITRE IDs if viewing legacy CSV without MITRE_ID column
    def infer_mitre_id(sig):
        s = str(sig).lower()
        if 'brute force' in s or 'ssh' in s: return 'T1110'
        if 'sql' in s or 'injection' in s: return 'T1190'
        if 'scan' in s or 'nmap' in s: return 'T1046'
        if 'download' in s or 'executable' in s: return 'T1105'
        if 'dns' in s or 'c2' in s: return 'T1071.004'
        if 'smb' in s or 'share' in s: return 'T1021.002'
        return 'N/A'

    if not df.empty and sig_col:
        df['MITRE_ID'] = df[sig_col].apply(infer_mitre_id)
        mitre_col = 'MITRE_ID'
    else:
        mitre_col = None

# ── Main Dashboard ────────────────────────────────────────────────────────────
if not df.empty:

    total   = len(df)
    threats = len(df[df[verdict_col].astype(str).str.lower() == 'threat']) if verdict_col else 0
    normal  = total - threats

    # Unique MITRE IDs (exclude N/A and empty)
    if mitre_col and mitre_col in df.columns:
        mapped_mitre = df[~df[mitre_col].astype(str).str.strip().isin(['N/A', 'None', 'nan', '', 'n/a'])][mitre_col]
        unique_mitre = mapped_mitre.nunique()
    else:
        mapped_mitre = pd.Series(dtype=str)
        unique_mitre = 0

    # ── KPI Row ───────────────────────────────────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("📡 Total Alerts",       total)
    k2.metric("🚨 Threats Detected",   threats,      delta=f"{threats} active",  delta_color="inverse")
    k3.metric("✅ Benign Events",       normal)
    k4.metric("🎯 MITRE Techniques",   unique_mitre, delta="unique IDs mapped")

    st.markdown("---")

    # ── Two-column layout ─────────────────────────────────────────────────────
    left, right = st.columns([3, 2])

    # LEFT: Live Alert Feed with MITRE inline
    with left:
        st.markdown('<p class="section-header">📋 Live Alert Feed with MITRE ATT&CK Mapping</p>', unsafe_allow_html=True)

        # Show last 20 alerts newest first
        display_df = df.iloc[::-1].head(20).reset_index(drop=True)

        for _, row in display_df.iterrows():
            sig      = str(row.get(sig_col, 'Unknown Alert'))      if sig_col      else 'Unknown Alert'
            verdict  = str(row.get(verdict_col, 'Unknown'))         if verdict_col  else 'Unknown'
            sev      = str(row.get(severity_col, 'Low'))            if severity_col else 'Low'
            mid      = str(row.get(mitre_col,  'N/A'))              if mitre_col    else 'N/A'
            summary  = str(row.get(summary_col, ''))                if summary_col  else ''
            ts       = str(row.get(ts_col, ''))                     if ts_col       else ''
            src      = str(row.get(src_col, ''))                    if src_col      else ''

            card_cls = "critical" if sev.lower() == "critical" else \
                       "alert-card" if verdict.lower() == "threat" else "normal"
            sev_cls  = f"sev-{sev.lower()}"

            mitre_badge = f'<span class="mitre-badge">{mid}</span>' if str(mid).strip().upper() not in ('N/A', 'NONE', 'NAN', '') else ''
            summary_html = f'<span style="font-size:0.82rem; color:#94a3b8;">{summary[:160]}</span>' if summary else ''

            card_html = (
                f'<div class="alert-card {card_cls}">'
                f'<div style="display:flex; justify-content:space-between; align-items:center;">'
                f'<b style="color:#e6edf3;">{sig[:80]}</b>'
                f'<span class="{sev_cls}">{sev.upper()}</span>'
                f'</div>'
                f'<div style="margin-top:0.3rem; font-size:0.8rem; color:#8b949e;">'
                f'🕐 {ts[:19]} &nbsp;|&nbsp; 🌐 {src}'
                f'</div>'
                f'<div style="margin-top:0.4rem;">'
                f'{mitre_badge}{summary_html}'
                f'</div>'
                f'</div>'
            )
            st.markdown(card_html, unsafe_allow_html=True)

    # RIGHT: MITRE ATT&CK Panel
    with right:
        st.markdown('<p class="section-header">🎯 MITRE ATT&CK Techniques Detected</p>', unsafe_allow_html=True)

        if not mapped_mitre.empty:
            counts = mapped_mitre.value_counts().reset_index()
            counts.columns = ["MITRE ID", "Count"]
            st.bar_chart(data=counts, x="MITRE ID", y="Count", height=240)

            st.markdown("**Top Techniques Breakdown**")
            for _, r in counts.head(8).iterrows():
                mid_val = r["MITRE ID"]
                cnt_val = r["Count"]
                pct = int(cnt_val / len(mapped_mitre) * 100)
                st.markdown(
                    f'<div style="margin-bottom:6px;">'
                    f'<span class="mitre-badge">{mid_val}</span>'
                    f'<span style="font-size:0.85rem; color:#94a3b8;"> {cnt_val} alert(s) ({pct}%)</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.info("No MITRE techniques mapped yet.")

    st.markdown("---")

    # ── MITRE Detail Expander ─────────────────────────────────────────────────
    st.markdown('<p class="section-header">🔬 MITRE ATT&CK RAG Analysis — Per-Alert Detail</p>', unsafe_allow_html=True)
    st.caption("Click any alert below to see the full Llama 3.2 MITRE reasoning from the RAG pipeline.")

    with st.expander("📂 View All Alerts with MITRE Reasoning", expanded=True):
        for idx, row in display_df.iterrows():
            sig     = str(row.get(sig_col,     'Unknown Alert'))  if sig_col     else 'Unknown Alert'
            mid     = str(row.get(mitre_col,   'N/A'))            if mitre_col   else 'N/A'
            sev     = str(row.get(severity_col,'Low'))            if severity_col else 'Low'
            verdict = str(row.get(verdict_col, 'Unknown'))        if verdict_col  else 'Unknown'
            summary = str(row.get(summary_col, 'No analysis details recorded.')) if summary_col else 'No analysis details recorded.'

            icon = "🔴" if verdict.lower() == "threat" else "🟢"
            mitre_link = f"https://attack.mitre.org/techniques/{mid.split('.')[0]}/" if str(mid).strip().upper() not in ('N/A','NONE','NAN','') else "#"

            with st.expander(f"{icon}  {sig[:90]}  —  [{mid}]"):
                st.markdown(f"""
                **MITRE ID:** <span class="mitre-badge">{mid}</span> &nbsp;
                [🔗 View on MITRE ATT&CK]({mitre_link})
                """, unsafe_allow_html=True)
                st.markdown(f"**Severity:** `{sev}` &nbsp;|&nbsp; **Verdict:** `{verdict}`")
                st.markdown("**AI Analysis & Reasoning:**")
                st.markdown(f'<div class="mitre-reasoning">{summary}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # ── Threat Intel Lookup ───────────────────────────────────────────────────
    st.markdown('<p class="section-header">🔍 Threat Intelligence IP Lookup</p>', unsafe_allow_html=True)

    col_input, col_btn = st.columns([3, 1])
    with col_input:
        selected_ip = st.text_input("Enter IP Address:", value="118.25.6.39", label_visibility="collapsed",
                                    placeholder="Enter IP address to check...")
    with col_btn:
        check_btn = st.button("🔍 Check IP Reputation", use_container_width=True)

    if check_btn:
        with st.spinner(f"Querying AbuseIPDB & VirusTotal for {selected_ip}..."):
            abuse_res = check_abuseipdb(selected_ip)
            vt_res    = check_virustotal(selected_ip)
            st.session_state["threat_intel_ip"]   = selected_ip
            st.session_state["threat_intel_data"]  = (abuse_res, vt_res)

    if "threat_intel_data" in st.session_state:
        abuse_res, vt_res = st.session_state["threat_intel_data"]
        if not abuse_res.get("is_public", True):
            st.info(f"ℹ️ **{selected_ip}** is a private/internal IP. Threat intel databases only index public IPs.")
        else:
            ti1, ti2 = st.columns(2)
            with ti1:
                st.metric("AbuseIPDB Confidence", f"{abuse_res['abuse_score']}%",
                          delta="High Risk" if abuse_res['abuse_score'] > 50 else "Low Risk")
                st.caption(f"Total Reports: {abuse_res['total_reports']}")
            with ti2:
                st.metric("VirusTotal Detections", f"{vt_res['malicious_votes']} Vendors",
                          delta="⚠️ Flagged" if vt_res['malicious_votes'] > 0 else "✅ Clean")

    # ── Raw Data Table ────────────────────────────────────────────────────────
    with st.expander("📊 Raw Alert History Table"):
        st.dataframe(df, use_container_width=True)

else:
    st.info("⏳ Awaiting alert stream from Suricata IDS... Run `python suricata_ai_agent.py eve.json` to populate data.")

    st.markdown("---")
    st.markdown('<p class="section-header">🧪 MITRE RAG System — Live Test</p>', unsafe_allow_html=True)
    st.markdown("Run a quick MITRE ATT&CK lookup directly from the dashboard:")

    test_sig = st.text_input("Enter an alert signature to test RAG:", value="ET SCAN Potential Nmap Scan Detected")
    if st.button("🚀 Run MITRE RAG Lookup"):
        with st.spinner("Running FAISS retrieval + Llama 3.2 analysis..."):
            try:
                from rag_mitre import retrieve_mitre_context
                result = retrieve_mitre_context(test_sig)
                st.success("RAG analysis complete!")
                st.markdown("**MITRE ATT&CK Result:**")
                st.code(result, language="text")
            except Exception as e:
                st.error(f"RAG lookup failed: {e}")

# ── Auto-refresh ──────────────────────────────────────────────────────────────
time.sleep(5)
st.rerun()