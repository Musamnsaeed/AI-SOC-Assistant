import os
import time
import pandas as pd
import streamlit as st
from suricata_ai_agent import query_logs_with_llm
from threat_intel import check_abuseipdb, check_virustotal

st.set_page_config(
    page_title="AI Suricata SOC Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="collapsed"   # start full-width; FAB opens the chat
)

# ── Session state init ────────────────────────────────────────────────────────
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []   # list of {"role": "user"/"ai", "text": "..."}

# ── Load CSV (must be before sidebar & CSS so `df` is available everywhere) ───
csv_file = "alert_history.csv"
if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
    try:
        df = pd.read_csv(csv_file, on_bad_lines='skip')
    except Exception:
        df = pd.DataFrame()
else:
    df = pd.DataFrame()

# ── Normalise column names ────────────────────────────────────────────────────
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

    /* Hide the native Streamlit sidebar expand-arrow tab visually,
       but keep it in DOM so JS can still click() it to open sidebar */
    [data-testid="collapsedControl"] {
        opacity: 0 !important;
        pointer-events: none !important;
        width: 0 !important;
        overflow: hidden !important;
    }

    /* Ensure main content always stretches full width with smooth transition */
    .main .block-container {
        max-width: 100% !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        transition: all 0.3s ease;
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

    /* ── Floating Chat Bubble ──────────────────────────────────────────── */
    #chat-fab {
        position: fixed;
        bottom: 28px;
        right: 28px;
        width: 62px;
        height: 62px;
        border-radius: 50%;
        background: linear-gradient(135deg, #1d4ed8, #7c3aed);
        box-shadow: 0 6px 30px rgba(124,58,237,0.55), 0 2px 8px rgba(0,0,0,0.4);
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        z-index: 99999;
        transition: transform 0.25s cubic-bezier(.34,1.56,.64,1),
                    box-shadow 0.25s ease;
        border: none;
        outline: none;
        animation: fab-pulse 2.8s ease-in-out infinite;
    }
    #chat-fab:hover {
        transform: scale(1.12);
        box-shadow: 0 10px 40px rgba(124,58,237,0.7), 0 2px 12px rgba(0,0,0,0.5);
    }
    #chat-fab .fab-icon { font-size: 26px; line-height: 1; }
    #chat-fab .fab-badge {
        position: absolute;
        top: 4px; right: 4px;
        width: 14px; height: 14px;
        background: #22c55e;
        border-radius: 50%;
        border: 2px solid #0d1117;
        animation: badge-blink 1.5s ease-in-out infinite;
    }
    @keyframes fab-pulse {
        0%,100% { box-shadow: 0 6px 30px rgba(124,58,237,0.55), 0 2px 8px rgba(0,0,0,0.4); }
        50%      { box-shadow: 0 6px 40px rgba(124,58,237,0.85), 0 2px 8px rgba(0,0,0,0.4); }
    }
    @keyframes badge-blink {
        0%,100% { opacity: 1; } 50% { opacity: 0.3; }
    }

    /* ── Sidebar Chat Panel ────────────────────────────────────────────── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #161b22 100%) !important;
        border-right: 1px solid #21262d !important;
        min-width: 360px !important;
        max-width: 360px !important;
    }
    [data-testid="stSidebar"] > div:first-child { padding: 0 !important; }

    .chat-header {
        background: linear-gradient(135deg, #1d4ed8 0%, #7c3aed 100%);
        padding: 18px 20px 14px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .chat-header-icon { font-size: 28px; }
    .chat-header-text h3 { margin:0; font-size:1rem; font-weight:700; color:#fff; }
    .chat-header-text p  { margin:0; font-size:0.75rem; color:rgba(255,255,255,0.7); }

    .chat-bubble-user {
        background: linear-gradient(135deg, #1d4ed8, #2563eb);
        color: #fff;
        border-radius: 16px 16px 4px 16px;
        padding: 10px 14px;
        margin: 6px 0 6px 40px;
        font-size: 0.85rem;
        line-height: 1.5;
        word-wrap: break-word;
    }
    .chat-bubble-ai {
        background: linear-gradient(135deg, #1c2333, #1f2937);
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 16px 16px 16px 4px;
        padding: 10px 14px;
        margin: 6px 40px 6px 0;
        font-size: 0.85rem;
        line-height: 1.5;
        word-wrap: break-word;
    }
    .chat-label-user { text-align:right; font-size:0.7rem; color:#6e7681; margin: 0 0 2px 40px; }
    .chat-label-ai   { font-size:0.7rem; color:#6e7681; margin: 0 40px 2px 0; }
    .chat-divider { border:none; border-top:1px solid #21262d; margin: 10px 0; }
</style>
""", unsafe_allow_html=True)

# ── Floating Chat Bubble ────────────────────────────────────────────────────────────
st.markdown("""
<button id="chat-fab" onclick="socToggleSidebar()" title="Ask AI about your logs">
    <span class="fab-icon">💬</span>
    <span class="fab-badge"></span>
</button>
<script>
function socToggleSidebar() {
    var doc = window.parent.document;
    var sidebar = doc.querySelector('[data-testid="stSidebar"]');

    // Check if sidebar is currently OPEN (has real width)
    var isOpen = sidebar && sidebar.getBoundingClientRect().width > 10;

    if (!isOpen) {
        // ----- OPEN the sidebar -----
        // Try collapsedControl first (the native toggle, hidden visually but in DOM)
        var openBtn = doc.querySelector('[data-testid="collapsedControl"]') ||
                      doc.querySelector('button[title="Open sidebar"]') ||
                      doc.querySelector('[aria-label="Open sidebar"]');
        if (openBtn) { openBtn.click(); return; }

        // Fallback: directly show the sidebar element
        if (sidebar) {
            sidebar.style.setProperty('display', 'block', 'important');
            sidebar.style.setProperty('visibility', 'visible', 'important');
            sidebar.style.setProperty('width', '360px', 'important');
        }
    } else {
        // ----- CLOSE the sidebar -----
        var closeBtn =
            sidebar.querySelector('button[data-testid="stSidebarNavCloseButton"]') ||
            sidebar.querySelector('button[title="Close sidebar"]')  ||
            sidebar.querySelector('[aria-label="Close sidebar"]')   ||
            sidebar.querySelector('button');
        if (closeBtn) { closeBtn.click(); return; }

        // Fallback: hide the sidebar element
        if (sidebar) {
            sidebar.style.setProperty('width', '0', 'important');
            sidebar.style.setProperty('overflow', 'hidden', 'important');
        }
    }
}
</script>
""", unsafe_allow_html=True)


# ── Sidebar Chat Panel ────────────────────────────────────────────────────────
with st.sidebar:
    # --- Header banner ---
    st.markdown("""
    <div class="chat-header">
        <span class="chat-header-icon">🤖</span>
        <div class="chat-header-text">
            <h3>AI Log Assistant</h3>
            <p>Powered by Llama 3.2 &nbsp;•&nbsp; RAG + NLP</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Conversation history ---
    if st.session_state.chat_history:
        for msg in st.session_state.chat_history:
            if msg["role"] == "user":
                st.markdown(f'<p class="chat-label-user">You</p>', unsafe_allow_html=True)
                st.markdown(f'<div class="chat-bubble-user">{msg["text"]}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<p class="chat-label-ai">🤖 AI</p>', unsafe_allow_html=True)
                st.markdown(f'<div class="chat-bubble-ai">{msg["text"]}</div>', unsafe_allow_html=True)
        st.markdown('<hr class="chat-divider">', unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center; padding: 30px 10px; color:#4a5568;">
            <div style="font-size:2.5rem;">💬</div>
            <p style="margin-top:8px; font-size:0.82rem; line-height:1.6;">
                Ask me anything about your<br>security alerts in plain English.
            </p>
            <p style="font-size:0.75rem; color:#374151; margin-top:4px;">
                <i>e.g. "Show me all critical threats"<br>"SSH brute force from 10.0.0.5"</i>
            </p>
        </div>
        """, unsafe_allow_html=True)

    # --- Input area ---
    df_chat = df if not df.empty else pd.DataFrame()
    record_count = len(df_chat) if not df_chat.empty else 0

    if record_count:
        st.caption(f"📊 {record_count} alerts ready to query")
    else:
        st.caption("⚠️ No alert data — run the agent first")

    with st.form(key="chat_form", clear_on_submit=True):
        user_input = st.text_area(
            label="",
            placeholder="Ask about your logs…\ne.g. Show me all SSH brute force attempts",
            height=80,
            label_visibility="collapsed"
        )
        col_send, col_clear = st.columns([3, 1])
        with col_send:
            send = st.form_submit_button("➤ Send", use_container_width=True)
        with col_clear:
            clear = st.form_submit_button("🗑️", use_container_width=True, help="Clear chat")

    if clear:
        st.session_state.chat_history = []
        st.rerun()

    if send and user_input.strip():
        prompt = user_input.strip()
        st.session_state.chat_history.append({"role": "user", "text": prompt})

        if df_chat.empty:
            reply = "⚠️ No alert data loaded yet. Run `python suricata_ai_agent.py eve.json` to populate the database."
            st.session_state.chat_history.append({"role": "ai", "text": reply})
        else:
            with st.spinner("🤖 Analyzing…"):
                explanation, filtered_data = query_logs_with_llm(prompt, df_chat)
                if filtered_data.empty:
                    reply = f"🧠 **{explanation}**\n\nNo matching records found for that query."
                else:
                    reply = (
                        f"🧠 **{explanation}**\n\n"
                        f"✅ Found **{len(filtered_data)}** matching alert(s). "
                        f"Results shown below ⬇️"
                    )
                    # Store filtered data to display as table below sidebar
                    st.session_state["chat_result"] = filtered_data

            st.session_state.chat_history.append({"role": "ai", "text": reply})
        st.rerun()

# ── If chat returned tabular results, show them in main area ──────────────────
if "chat_result" in st.session_state and not st.session_state["chat_result"].empty:
    with st.expander("💬 AI Chat Query Result", expanded=True):
        st.success(f"✅ {len(st.session_state['chat_result'])} record(s) matched your last chat query")
        st.dataframe(st.session_state["chat_result"], use_container_width=True)
        if st.button("✖ Dismiss Result", key="dismiss_chat_result"):
            del st.session_state["chat_result"]
            st.rerun()


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Enterprise AI SOC Assistant")
st.markdown("**Live Network Intrusion Detection & MITRE ATT&CK Mapping** — powered by Llama 3.2 + FAISS RAG")
st.markdown("---")

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