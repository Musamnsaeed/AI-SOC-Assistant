import os
import json
import time
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from suricata_ai_agent import query_logs_with_llm
from threat_intel import check_abuseipdb, check_virustotal

st.set_page_config(
    page_title="AI Suricata SOC Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="collapsed",
)

# ── Load CSV first so `df` is available everywhere ────────────────────────────
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
    if not df.empty and sig_col:
        df['MITRE_ID'] = df[sig_col].apply(infer_mitre_id)
        mitre_col = 'MITRE_ID'
    else:
        mitre_col = None

# ── Custom CSS (dashboard only — no sidebar styles) ───────────────────────────
st.markdown("""
<style>
    /* ── Global theme ── */
    .stApp { background-color: #0d1117; color: #e6edf3; }
    .block-container { padding-top: 1.5rem; max-width: 100% !important; }

    /* Hide sidebar toggle arrow so dashboard is always full-width */
    [data-testid="collapsedControl"],
    [data-testid="stSidebarNav"]    { display: none !important; }
    section[data-testid="stSidebar"] { display: none !important; }

    /* ── Floating AI Chat Widget - Viewport Fixed ── */
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
    }
    div[data-testid="element-container"]:has(iframe),
    .stElementContainer:has(iframe) {
        height: 0px !important;
        min-height: 0px !important;
        margin: 0px !important;
        padding: 0px !important;
    }

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
    .alert-card.normal   { border-left-color: #22c55e; }
    .alert-card.medium   { border-left-color: #f59e0b; }
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

    /* Severity pills */
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

# ── Main Dashboard ────────────────────────────────────────────────────────────
if not df.empty:
    total   = len(df)
    threats = len(df[df[verdict_col].astype(str).str.lower() == 'threat']) if verdict_col else 0
    normal  = total - threats

    if mitre_col and mitre_col in df.columns:
        mapped_mitre = df[~df[mitre_col].astype(str).str.strip().isin(['N/A', 'None', 'nan', '', 'n/a'])][mitre_col]
        unique_mitre = mapped_mitre.nunique()
    else:
        mapped_mitre = pd.Series(dtype=str)
        unique_mitre = 0

    # ── KPI Row ───────────────────────────────────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("📡 Total Alerts",     total)
    k2.metric("🚨 Threats Detected", threats,      delta=f"{threats} active",  delta_color="inverse")
    k3.metric("✅ Benign Events",     normal)
    k4.metric("🎯 MITRE Techniques", unique_mitre, delta="unique IDs mapped")

    st.markdown("---")

    left, right = st.columns([3, 2])

    with left:
        st.markdown('<p class="section-header">📋 Live Alert Feed with MITRE ATT&CK Mapping</p>', unsafe_allow_html=True)
        display_df = df.iloc[::-1].head(20).reset_index(drop=True)

        for _, row in display_df.iterrows():
            sig     = str(row.get(sig_col,     'Unknown Alert')) if sig_col     else 'Unknown Alert'
            verdict = str(row.get(verdict_col, 'Unknown'))       if verdict_col else 'Unknown'
            sev     = str(row.get(severity_col,'Low'))           if severity_col else 'Low'
            mid     = str(row.get(mitre_col,   'N/A'))           if mitre_col   else 'N/A'
            summary = str(row.get(summary_col, ''))              if summary_col else ''
            ts      = str(row.get(ts_col, ''))                   if ts_col      else ''
            src     = str(row.get(src_col, ''))                  if src_col     else ''

            card_cls = "critical" if sev.lower() == "critical" else \
                       "alert-card" if verdict.lower() == "threat" else "normal"
            sev_cls  = f"sev-{sev.lower()}"
            mitre_badge  = f'<span class="mitre-badge">{mid}</span>' if str(mid).strip().upper() not in ('N/A','NONE','NAN','') else ''
            summary_html = f'<span style="font-size:0.82rem; color:#94a3b8;">{summary[:160]}</span>' if summary else ''

            st.markdown(
                f'<div class="alert-card {card_cls}">'
                f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                f'<b style="color:#e6edf3;">{sig[:80]}</b>'
                f'<span class="{sev_cls}">{sev.upper()}</span>'
                f'</div>'
                f'<div style="margin-top:0.3rem;font-size:0.8rem;color:#8b949e;">🕐 {ts[:19]} &nbsp;|&nbsp; 🌐 {src}</div>'
                f'<div style="margin-top:0.4rem;">{mitre_badge}{summary_html}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

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
                    f'<span style="font-size:0.85rem;color:#94a3b8;"> {cnt_val} alert(s) ({pct}%)</span>'
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
            sig     = str(row.get(sig_col,     'Unknown Alert'))               if sig_col     else 'Unknown Alert'
            mid     = str(row.get(mitre_col,   'N/A'))                         if mitre_col   else 'N/A'
            sev     = str(row.get(severity_col,'Low'))                         if severity_col else 'Low'
            verdict = str(row.get(verdict_col, 'Unknown'))                     if verdict_col  else 'Unknown'
            summary = str(row.get(summary_col, 'No analysis details recorded.')) if summary_col else 'No analysis details recorded.'

            icon = "🔴" if verdict.lower() == "threat" else "🟢"
            mitre_link = f"https://attack.mitre.org/techniques/{mid.split('.')[0]}/" \
                         if str(mid).strip().upper() not in ('N/A','NONE','NAN','') else "#"

            with st.expander(f"{icon}  {sig[:90]}  —  [{mid}]"):
                st.markdown(
                    f'**MITRE ID:** <span class="mitre-badge">{mid}</span> &nbsp;'
                    f'[🔗 View on MITRE ATT&CK]({mitre_link})',
                    unsafe_allow_html=True
                )
                st.markdown(f"**Severity:** `{sev}` &nbsp;|&nbsp; **Verdict:** `{verdict}`")
                st.markdown("**AI Analysis & Reasoning:**")
                st.markdown(f'<div class="mitre-reasoning">{summary}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # ── Threat Intel Lookup ───────────────────────────────────────────────────
    st.markdown('<p class="section-header">🔍 Threat Intelligence IP Lookup</p>', unsafe_allow_html=True)

    col_input, col_btn = st.columns([3, 1])
    with col_input:
        selected_ip = st.text_input("Enter IP Address:", value="118.25.6.39",
                                    label_visibility="collapsed",
                                    placeholder="Enter IP address to check...")
    with col_btn:
        check_btn = st.button("🔍 Check IP Reputation", use_container_width=True)

    if check_btn:
        with st.spinner(f"Querying AbuseIPDB & VirusTotal for {selected_ip}..."):
            abuse_res = check_abuseipdb(selected_ip)
            vt_res    = check_virustotal(selected_ip)
            st.session_state["threat_intel_ip"]   = selected_ip
            st.session_state["threat_intel_data"] = (abuse_res, vt_res)

    if "threat_intel_data" in st.session_state:
        abuse_res, vt_res = st.session_state["threat_intel_data"]
        if not abuse_res.get("is_public", True):
            st.info(f"ℹ️ **{selected_ip}** is a private/internal IP.")
        else:
            ti1, ti2 = st.columns(2)
            with ti1:
                st.metric("AbuseIPDB Confidence", f"{abuse_res['abuse_score']}%",
                          delta="High Risk" if abuse_res['abuse_score'] > 50 else "Low Risk")
                st.caption(f"Total Reports: {abuse_res['total_reports']}")
            with ti2:
                st.metric("VirusTotal Detections", f"{vt_res['malicious_votes']} Vendors",
                          delta="⚠️ Flagged" if vt_res['malicious_votes'] > 0 else "✅ Clean")

    with st.expander("📊 Raw Alert History Table"):
        st.dataframe(df, use_container_width=True)

else:
    st.info("⏳ Awaiting alert stream from Suricata IDS... Run `python suricata_ai_agent.py eve.json` to populate data.")
    st.markdown("---")
    st.markdown('<p class="section-header">🧪 MITRE RAG System — Live Test</p>', unsafe_allow_html=True)
    test_sig = st.text_input("Enter an alert signature to test RAG:", value="ET SCAN Potential Nmap Scan Detected")
    if st.button("🚀 Run MITRE RAG Lookup"):
        with st.spinner("Running FAISS retrieval + Llama 3.2 analysis..."):
            try:
                from rag_mitre import retrieve_mitre_context
                result = retrieve_mitre_context(test_sig)
                st.success("RAG analysis complete!")
                st.code(result, language="text")
            except Exception as e:
                st.error(f"RAG lookup failed: {e}")

# ── Floating AI Chat Widget (self-contained HTML component) ───────────────────
# Build df context to pass into the JS chat prompt
df_cols    = list(df.columns) if not df.empty else []
df_sample  = df.head(3).to_dict(orient="records") if not df.empty else []
df_total   = len(df)
ctx_json   = json.dumps({"columns": df_cols, "sample": df_sample, "total": df_total})

chat_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; }}
  body {{ background: transparent; overflow: hidden; }}

  /* ── Floating button ── */
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

<!-- Floating button -->
<button id="fab" onclick="toggleChat()" title="Open AI Chat">
  🤖<span class="badge"></span>
</button>

<!-- Chat panel -->
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

// Send on Enter (not Shift+Enter)
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

  // Build prompt with df context
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

# Inject CSS into parent page to make the component iframe fixed bottom-right
# This runs in the parent Streamlit document via st.markdown CSS injection
st.markdown("""
<style>
  /* Target all variations of Streamlit component wrappers to fix the iframe to the screen bottom-right */
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
  }

  /* Prevent empty block space at the bottom of the document flow */
  div[data-testid="element-container"]:has(iframe),
  .stElementContainer:has(iframe) {
    height: 0px !important;
    min-height: 0px !important;
    margin: 0px !important;
    padding: 0px !important;
  }

  /* Allow click interactions inside the iframe */
  iframe[title="components.html"],
  iframe[title="st.iframe"],
  div[data-testid="stCustomComponentV1"] iframe {
    pointer-events: auto !important;
  }
</style>
""", unsafe_allow_html=True)

# Render the floating chat — height=650 matches the CSS above
components.html(chat_html, height=650, scrolling=False)

# ── Auto-refresh ──────────────────────────────────────────────────────────────
time.sleep(5)
st.rerun()