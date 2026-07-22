import json
import requests
import csv
import os
import time
from threat_intel import check_abuseipdb, check_virustotal
from rag_mitre import retrieve_mitre_context

# Target the installed Suricata log path on Windows if it exists, otherwise fall back to local eve.json
DEFAULT_SURI_PATH = r"C:\Program Files\Suricata\log\eve.json"
if os.path.exists(DEFAULT_SURI_PATH):
    EVE_JSON_PATH = DEFAULT_SURI_PATH
else:
    EVE_JSON_PATH = "eve.json"

CSV_DATABASE = "alert_history.csv"
OLLAMA_URL = "http://localhost:11434/api/generate"

def query_llama_mitre(alert_data, abuse_data=None, vt_data=None):
    # Retrieve Ground-Truth MITRE Context via FAISS RAG
    mitre_context = retrieve_mitre_context(alert_data.get('signature', ''))
    
    # Format Threat Intelligence Info
    abuse_score = abuse_data.get("abuse_score", 0) if abuse_data else 0
    vt_malicious = vt_data.get("malicious_votes", 0) if vt_data else 0
    threat_intel_context = (
        f"- AbuseIPDB Confidence Score: {abuse_score}%\n"
        f"- VirusTotal Malicious Detections: {vt_malicious} vendors"
    )
    
    # RAG-Grounded SOC Analyst Prompt
    prompt = f"""
    You are an expert Tier-2 SOC Analyst. Analyze this Suricata Network IDS alert.
    
    ALERT DATA:
    - Signature/Rule: {alert_data.get('signature')}
    - Category: {alert_data.get('category')}
    - Source IP: {alert_data.get('src_ip')}:{alert_data.get('src_port')}
    - Destination IP: {alert_data.get('dest_ip')}:{alert_data.get('dest_port')}
    - Protocol: {alert_data.get('proto')}
    - Raw Severity Level: {alert_data.get('raw_severity')}

    THREAT INTELLIGENCE FEEDBACK:
    {threat_intel_context}

    RETRIEVED MITRE ATT&CK GROUND TRUTH KNOWLEDGE:
    {mitre_context}

    INSTRUCTIONS:
    Analyze this threat using ONLY the provided Ground Truth Knowledge where applicable.
    Return ONLY a single valid JSON object with NO extra text or markdown codeblocks using this schema:
    {{
        "verdict": "Threat" or "Normal",
        "severity": "Low" or "Medium" or "High" or "Critical",
        "mitre_id": "e.g. T1110 or T1595 or N/A",
        "action_required": "Yes" or "No",
        "summary": "Short 1-sentence technical explanation incorporating official mitigations"
    }}
    """
    
    payload = {
        "model": "llama3.2",
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }
    
    try:
        res = requests.post(OLLAMA_URL, json=payload)
        return res.json().get("response", "{}")
    except Exception as e:
        print(f"Error querying Ollama: {e}")
        return "{}"

def log_to_csv(timestamp, alert_data, ai_response, abuse_data=None, vt_data=None):
    file_exists = os.path.isfile(CSV_DATABASE)
    
    clean_resp = ai_response.strip()
    if clean_resp.startswith("```json"):
        clean_resp = clean_resp.replace("```json", "").replace("```", "").strip()
    elif clean_resp.startswith("```"):
        clean_resp = clean_resp.replace("```", "").strip()
        
    try:
        ai_json = json.loads(clean_resp)
        verdict = ai_json.get("verdict", "Unknown")
        severity = ai_json.get("severity", "Unknown")
        mitre_id = ai_json.get("mitre_id", "N/A")
        action = ai_json.get("action_required", "Unknown")
        summary = ai_json.get("summary", "")
    except Exception:
        verdict = "Threat" if alert_data.get('raw_severity') <= 2 else "Normal"
        severity = "High" if verdict == "Threat" else "Low"
        mitre_id = "T1595" if "Scan" in alert_data.get('signature', '') else "N/A"
        action = "Yes" if verdict == "Threat" else "No"
        summary = alert_data.get('signature')

    abuse_score = abuse_data.get("abuse_score", 0) if abuse_data else 0
    vt_malicious = vt_data.get("malicious_votes", 0) if vt_data else 0

    with open(CSV_DATABASE, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "Src_IP", "Dst_IP", "Signature", "AI_Verdict", "Severity", "MITRE_ID", "Action", "Summary", "Abuse_Score", "VT_Malicious"])
        
        writer.writerow([
            timestamp,
            f"{alert_data.get('src_ip')}:{alert_data.get('src_port')}",
            f"{alert_data.get('dest_ip')}:{alert_data.get('dest_port')}",
            alert_data.get('signature'),
            verdict,
            severity,
            mitre_id,
            action,
            summary,
            abuse_score,
            vt_malicious
        ])

def stream_suricata_logs(tail=True):
    print(f"[*] Starting Suricata IDS Log Listener on: {EVE_JSON_PATH}")
    
    if not os.path.exists(EVE_JSON_PATH):
        print(f"[-] Log file {EVE_JSON_PATH} not found. Please check the path.")
        return

    # Use encoding utf-8 and ignore errors for robustness against log encoding quirks
    with open(EVE_JSON_PATH, "r", encoding="utf-8", errors="ignore") as f:
        if tail:
            print("[*] Tailing new alerts in real-time... (Press Ctrl+C to stop)")
            # Move to the end of the file to only process newly appended lines
            f.seek(0, os.SEEK_END)
        else:
            print("[*] Processing existing logs from the beginning...")

        while True:
            line = f.readline()
            if not line:
                if not tail:
                    # If not tailing, we stop after processing existing lines
                    break
                time.sleep(0.5)
                continue
                
            try:
                log_entry = json.loads(line.strip())
                
                # Filter only Suricata "alert" events
                if log_entry.get("event_type") == "alert":
                    alert_info = log_entry.get("alert", {})
                    
                    alert_payload = {
                        "signature": alert_info.get("signature"),
                        "category": alert_info.get("category"),
                        "raw_severity": alert_info.get("severity"),
                        "src_ip": log_entry.get("src_ip"),
                        "src_port": log_entry.get("src_port"),
                        "dest_ip": log_entry.get("dest_ip"),
                        "dest_port": log_entry.get("dest_port"),
                        "proto": log_entry.get("proto")
                    }
                    
                    print(f"\n[+] Suricata Alert Captured: {alert_payload['signature']}")
                    
                    # Fetch Threat Intel Data for Source IP
                    src_ip_only = alert_payload['src_ip']
                    print(f"    Fetching Threat Intel for IP {src_ip_only}...")
                    abuse_data = check_abuseipdb(src_ip_only)
                    vt_data = check_virustotal(src_ip_only)
                    print(f"    Threat Intel -> AbuseIPDB Score: {abuse_data.get('abuse_score', 0)}%, VirusTotal Malicious: {vt_data.get('malicious_votes', 0)}")
                    
                    print("    Analyzing threat & mapping MITRE ATT&CK via Llama 3.2...")
                    ai_verdict = query_llama_mitre(alert_payload, abuse_data, vt_data)
                    print(f"    AI Response: {ai_verdict.strip()}")
                    
                    log_to_csv(log_entry.get("timestamp"), alert_payload, ai_verdict, abuse_data, vt_data)
                    print("    [+] Event processed and stored in database.")
                    
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    import sys
    tail_mode = True
    if "--all" in sys.argv:
        tail_mode = False
        sys.argv.remove("--all")
    
    # If the user provides a custom path, override EVE_JSON_PATH
    # (filtering out the script name itself)
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]
    if args:
        EVE_JSON_PATH = args[0]
    
    try:
        stream_suricata_logs(tail=tail_mode)
    except KeyboardInterrupt:
        print("\n[*] Log listener stopped by user.")