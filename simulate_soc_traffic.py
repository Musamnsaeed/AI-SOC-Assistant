"""
simulate_soc_traffic.py
-----------------------
Simulates a real-world enterprise network log stream for Suricata IDS.
Generates realistic eve.json logs across 15+ diverse attack vectors and benign noise.

Usage:
  python simulate_soc_traffic.py --batch       # Overwrites eve.json with 15+ diverse alerts
  python simulate_soc_traffic.py --live        # Streams live random alerts every 3 seconds to eve.json
"""

import json
import time
import random
import sys
import os
from datetime import datetime, timezone

EVE_FILE = "eve.json"

REALWORLD_ALERTS = [
    {
        "signature": "ET SCAN Potential Nmap Scan Detected",
        "category": "Attempted Information Leak",
        "severity": 2,
        "src_ip": "192.168.1.150", "src_port": 45230,
        "dest_ip": "10.0.0.5", "dest_port": 80, "proto": "TCP"
    },
    {
        "signature": "ET WEB_SERVER Possible SQL Injection Attempt in HTTP URI",
        "category": "Web Application Attack",
        "severity": 1,
        "src_ip": "203.0.113.42", "src_port": 51200,
        "dest_ip": "10.0.0.5", "dest_port": 80, "proto": "TCP"
    },
    {
        "signature": "ET POLICY SSH Brute Force Attempt Outbound",
        "category": "Attempted Administrator Privilege Gain",
        "severity": 1,
        "src_ip": "192.168.1.88", "src_port": 49812,
        "dest_ip": "198.51.100.14", "dest_port": 22, "proto": "TCP"
    },
    {
        "signature": "ET POLICY Executable Download over HTTP",
        "category": "Potentially Bad Traffic",
        "severity": 2,
        "src_ip": "10.0.0.12", "src_port": 53210,
        "dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP"
    },
    {
        "signature": "ET TROJAN DNS Query to Known Malware C2 Domain",
        "category": "Command and Control",
        "severity": 1,
        "src_ip": "10.0.0.45", "src_port": 61204,
        "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "UDP"
    },
    {
        "signature": "ET EXPLOIT Apache Log4j RCE Attempt (JNDI Lookup in User-Agent)",
        "category": "Web Application Attack",
        "severity": 1,
        "src_ip": "185.220.101.5", "src_port": 44120,
        "dest_ip": "10.0.0.5", "dest_port": 443, "proto": "TCP"
    },
    {
        "signature": "ET POLICY Malicious PowerShell Encoded Command Execution",
        "category": "Executable Code Detected",
        "severity": 1,
        "src_ip": "10.0.0.22", "src_port": 58900,
        "dest_ip": "104.21.55.2", "dest_port": 80, "proto": "TCP"
    },
    {
        "signature": "ET EXPLOIT SMB Probe Outbound / PsExec Lateral Movement",
        "category": "Attempted Information Leak",
        "severity": 1,
        "src_ip": "118.25.6.39", "src_port": 49152,
        "dest_ip": "192.168.1.6", "dest_port": 445, "proto": "TCP"
    },
    {
        "signature": "ET ATTACK_RESPONSE Multiple Failed Login Attempts - Password Spray",
        "category": "Attempted Administrator Privilege Gain",
        "severity": 2,
        "src_ip": "45.33.32.156", "src_port": 39120,
        "dest_ip": "10.0.0.5", "dest_port": 443, "proto": "TCP"
    },
    {
        "signature": "ET POLICY Large Outbound HTTP POST Data Exfiltration",
        "category": "Potentially Bad Traffic",
        "severity": 1,
        "src_ip": "10.0.0.18", "src_port": 51100,
        "dest_ip": "162.243.10.12", "dest_port": 8080, "proto": "TCP"
    },
    {
        "signature": "ET SCAN Potential RDP Brute Force Attempt",
        "category": "Attempted Information Leak",
        "severity": 2,
        "src_ip": "194.26.29.110", "src_port": 41200,
        "dest_ip": "10.0.0.8", "dest_port": 3389, "proto": "TCP"
    },
    {
        "signature": "ET TROJAN Cobalt Strike Malleable HTTP C2 Beacon",
        "category": "Command and Control",
        "severity": 1,
        "src_ip": "10.0.0.99", "src_port": 50123,
        "dest_ip": "185.190.140.22", "dest_port": 80, "proto": "TCP"
    },
    {
        "signature": "ET INFO HTTP GET Request to Public Web Server",
        "category": "Normal Traffic",
        "severity": 3,
        "src_ip": "10.0.0.15", "src_port": 50000,
        "dest_ip": "142.250.190.46", "dest_port": 80, "proto": "TCP"
    },
    {
        "signature": "ET INFO Standard DNS Query to Cloudflare 1.1.1.1",
        "category": "Normal Traffic",
        "severity": 3,
        "src_ip": "10.0.0.15", "src_port": 52100,
        "dest_ip": "1.1.1.1", "dest_port": 53, "proto": "UDP"
    }
]

def make_eve_entry(alert):
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"
    return {
        "timestamp": now_iso,
        "event_type": "alert",
        "src_ip": alert["src_ip"],
        "src_port": alert["src_port"],
        "dest_ip": alert["dest_ip"],
        "dest_port": alert["dest_port"],
        "proto": alert["proto"],
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": alert["signature"],
            "category": alert["category"],
            "severity": alert["severity"]
        }
    }

def generate_batch():
    print(f"[*] Generating batch of {len(REALWORLD_ALERTS)} real-world enterprise Suricata alerts into '{EVE_FILE}'...")
    with open(EVE_FILE, "w", encoding="utf-8") as f:
        for alert in REALWORLD_ALERTS:
            entry = make_eve_entry(alert)
            f.write(json.dumps(entry) + "\n")
    print(f"[+] Successfully wrote {len(REALWORLD_ALERTS)} enterprise alerts to '{EVE_FILE}'!")

def generate_live(interval=3):
    print(f"[*] Live Log Streamer started! Writing new alert to '{EVE_FILE}' every {interval}s... (Ctrl+C to stop)")
    while True:
        alert = random.choice(REALWORLD_ALERTS)
        entry = make_eve_entry(alert)
        with open(EVE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  [+] Live Log Injected: {alert['signature']} ({alert['src_ip']} -> {alert['dest_ip']})")
        time.sleep(interval)

if __name__ == "__main__":
    if "--live" in sys.argv:
        try:
            generate_live()
        except KeyboardInterrupt:
            print("\n[*] Live log generator stopped.")
    else:
        generate_batch()
