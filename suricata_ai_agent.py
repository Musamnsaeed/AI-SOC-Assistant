import json
import requests
import csv
import os
import time
EVE_JSON_PATH = r"C:\Program Files\Suricata\log\eve.json"
CSV_DATABASE = "alert_history.csv"

OLLAMA_URL = "http://localhost:11434/api/generate"
EVE_JSON_PATH = "eve.json" # Ya Suricata log path e.g., "C:\\Program Files\\Suricata\\log\\eve.json"
CSV_DATABASE = "alert_history.csv"

def query_llama_mitre(alert_data):
    # Enterprise-grade SOC Analyst prompt with MITRE ATT&CK Mapping
    prompt = f"""
    You are an expert Tier-2 SOC Analyst. Analyze this Suricata Network IDS alert:
    - Signature/Rule: {alert_data.get('signature')}
    - Category: {alert_data.get('category')}
    - Source IP: {alert_data.get('src_ip')}:{alert_data.get('src_port')}
    - Destination IP: {alert_data.get('dest_ip')}:{alert_data.get('dest_port')}
    - Protocol: {alert_data.get('proto')}
    - Raw Severity Level: {alert_data.get('raw_severity')}

    Analyze this threat and map it to MITRE ATT&CK framework.
    Return ONLY a single valid JSON object with NO extra text or markdown codeblocks using this schema:
    {{
        "verdict": "Threat" or "Normal",
        "severity": "Low" or "Medium" or "High" or "Critical",
        "mitre_id": "e.g. T1110 or T1595 or N/A",
        "action_required": "Yes" or "No",
        "summary": "Short 1-sentence technical explanation"
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

def log_to_csv(timestamp, alert_data, ai_response):
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

    with open(CSV_DATABASE, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "Src_IP", "Dst_IP", "Signature", "AI_Verdict", "Severity", "MITRE_ID", "Action", "Summary"])
        
        writer.writerow([
            timestamp,
            f"{alert_data.get('src_ip')}:{alert_data.get('src_port')}",
            f"{alert_data.get('dest_ip')}:{alert_data.get('dest_port')}",
            alert_data.get('signature'),
            verdict,
            severity,
            mitre_id,
            action,
            summary
        ])

def stream_suricata_logs():
    print(f"[*] Starting Suricata IDS Log Listener on: {EVE_JSON_PATH}")
    
    if not os.path.exists(EVE_JSON_PATH):
        print(f"[-] Log file {EVE_JSON_PATH} not found. Please create it or start Suricata.")
        return

    with open(EVE_JSON_PATH, "r") as f:
        # Move to the beginning or end of file
        lines = f.readlines()
        
    for line in lines:
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
                print("    Analyzing threat & mapping MITRE ATT&CK via Llama 3.2...")
                
                ai_verdict = query_llama_mitre(alert_payload)
                print(f"    AI Response: {ai_verdict.strip()}")
                
                log_to_csv(log_entry.get("timestamp"), alert_payload, ai_verdict)
                print("    [✓] Event processed and stored in database.")
                
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    stream_suricata_logs()