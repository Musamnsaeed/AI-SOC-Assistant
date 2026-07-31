import requests
import re
import csv
import os
import json

# 1. Function: Raw log text ko saaf JSON/Dictionary mein convert karna
def parse_log_line(log_line):
    pattern = r'\[(?P<timestamp>.*?)\] SRC=(?P<src_ip>\S+) DST=(?P<dst_ip>\S+) PROTO=(?P<proto>\S+) SPT=(?P<spt>\d+) DPT=(?P<dpt>\d+) MSG="(?P<msg>.*?)" STATUS=(?P<status>\S+)'
    match = re.match(pattern, log_line)
    if match:
        return match.groupdict()
    return None

# Helper to infer MITRE ID based on message text
def get_mitre_id(msg):
    m = msg.lower()
    if "brute force" in m or "ssh" in m: return "T1110"
    if "sql" in m or "injection" in m: return "T1190"
    if "scan" in m or "nmap" in m: return "T1046"
    if "download" in m or "executable" in m: return "T1105"
    if "smb" in m or "share" in m: return "T1021.002"
    return "T1000"  # Generic / Unclassified Fallback

# Helper to infer Rule-based Severity if Llama fails or gives Unknown
def fallback_severity_mapper(msg):
    m = msg.lower()
    if any(k in m for k in ["brute force", "sql", "injection", "root", "unauthorized"]):
        return "High"
    elif any(k in m for k in ["scan", "nmap", "port", "failed"]):
        return "Medium"
    return "Low"

# 2. Function: Local Llama 3.2 se assessment lena
def query_llama(parsed_data):
    url = "http://localhost:11434/api/generate"
    
    prompt = f"""
You are an automated tier-1 SOC analyst engine. Analyze this structured alert:
- Alert Message: {parsed_data['msg']}
- Source IP: {parsed_data['src_ip']}
- Destination IP: {parsed_data['dst_ip']}
- Target Port: {parsed_data['dpt']}
- Event Status: {parsed_data['status']}

Provide a JSON response ONLY with these exact keys:
{{
    "verdict": "Threat" or "Normal",
    "severity": "Low" or "Medium" or "High",
    "action_required": "Yes" or "No",
    "summary": "One sentence summary"
}}
"""
    
    payload = {
        "model": "llama3.2",
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }
    
    try:
        response = requests.post(url, json=payload, timeout=90)
        return response.json().get("response", "{}")
    except Exception as e:
        print(f"Error connecting to Ollama: {e}")
        return "{}"

# 3. Function: Results ko CSV database mein save karna (standardized 11-column format)
def log_to_csv(parsed_data, ai_verdict):
    db_path = "data/alert_history.csv"
    if not os.path.exists("data") and os.path.exists(os.path.join("..", "data")):
        db_path = os.path.join("..", "data", "alert_history.csv")
        
    file_exists = os.path.isfile(db_path)
    
    clean_verdict = ai_verdict.strip()
    if clean_verdict.startswith("```json"):
        clean_verdict = clean_verdict.replace("```json", "").replace("```", "").strip()
    elif clean_verdict.startswith("```"):
        clean_verdict = clean_verdict.replace("```", "").strip()
        
    try:
        ai_json = json.loads(clean_verdict)
        verdict = ai_json.get("verdict", "Threat")
        severity = ai_json.get("severity", "Unknown")
        action = ai_json.get("action_required", "Yes" if verdict == "Threat" else "No")
        summary = ai_json.get("summary", parsed_data.get('msg', ''))
        
        # Automatic Fallback if AI returns 'Unknown' or invalid string
        if severity not in ["Low", "Medium", "High"]:
            severity = fallback_severity_mapper(parsed_data.get('msg', ''))

    except Exception as e:
        print(f"    [!] Parsing fallback triggered: {e}")
        verdict = "Threat" if "Threat" in clean_verdict else ("Normal" if "Normal" in clean_verdict else "Threat")
        severity = fallback_severity_mapper(parsed_data.get('msg', ''))
        action = "Yes" if verdict == "Threat" else "No"
        summary = parsed_data.get('msg', '')
    
    mitre_id = get_mitre_id(parsed_data.get('msg', ''))

    # Direct directory assurance
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    with open(db_path, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "Src_IP", "Dst_IP", "Signature", "AI_Verdict", "Severity", "MITRE_ID", "Action", "Summary", "Abuse_Score", "VT_Malicious"])
        
        writer.writerow([
            parsed_data.get('timestamp', ''),
            f"{parsed_data.get('src_ip', '')}:{parsed_data.get('spt', '')}",
            f"{parsed_data.get('dst_ip', '')}:{parsed_data.get('dpt', '')}",
            parsed_data.get('msg', ''),
            verdict,
            severity,
            mitre_id,
            action,
            summary,
            0,
            0
        ])

class SOCPipeline:
    def __init__(self):
        pass

    @staticmethod
    def parse_log_line(log_line):
        return parse_log_line(log_line)

    @staticmethod
    def query_llama(parsed_data):
        return query_llama(parsed_data)

    @staticmethod
    def log_to_csv(parsed_data, ai_verdict):
        return log_to_csv(parsed_data, ai_verdict)

if __name__ == "__main__":
    print("--- Starting Automated Log Triage Engine ---")
    
    sample_path = "data/sample_logs.txt"
    if not os.path.exists("data") and os.path.exists(os.path.join("..", "data")):
        sample_path = os.path.join("..", "data", "sample_logs.txt")
        
    db_path = "data/alert_history.csv"
    if not os.path.exists("data") and os.path.exists(os.path.join("..", "data")):
        db_path = os.path.join("..", "data", "alert_history.csv")
    
    if os.path.exists(sample_path):
        with open(sample_path, "r") as f:
            lines = f.readlines()
            
        for line in lines:
            parsed = parse_log_line(line.strip())
            if parsed:
                print(f"\n[+] Parsed Event: {parsed['msg']} from {parsed['src_ip']}")
                print("    Querying Llama 3.2 for triage...")
                
                ai_response = query_llama(parsed)
                print(f"    AI Response: {ai_response.strip()}")
                
                log_to_csv(parsed, ai_response)
                print(f"    [OK] Log and AI verdict saved to {db_path}")
            else:
                print(f"[-] Could not parse line: {line.strip()}")