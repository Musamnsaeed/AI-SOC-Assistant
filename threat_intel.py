import requests

# Public API Keys (Replace with your actual keys)
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEYgit add ."

def clean_ip(ip_address):
    if not ip_address:
        return ""
    # Strip whitespace and port numbers if present (e.g. 192.168.1.1:80 -> 192.168.1.1)
    ip = str(ip_address).strip()
    if ":" in ip and not ip.startswith("::"): # Handle IPv4:port
        ip = ip.split(":")[0]
    return ip

def check_abuseipdb(ip_address):
    """
    Check IP reputation on AbuseIPDB
    """
    ip = clean_ip(ip_address)
    # Skip private / local IP addresses
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return {"abuse_score": 0, "total_reports": 0, "is_public": False, "status": "Private/Local IP"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_public": True,
                "status": "Success"
            }
        else:
            return {"abuse_score": 0, "total_reports": 0, "is_public": True, "status": f"API Error ({response.status_code})"}
    except Exception as e:
        print(f"AbuseIPDB API Error: {e}")
        return {"abuse_score": 0, "total_reports": 0, "is_public": True, "status": f"Connection Error: {e}"}


def check_virustotal(ip_address):
    """
    Check IP malicious history on VirusTotal
    """
    ip = clean_ip(ip_address)
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return {"malicious_votes": 0, "harmless_votes": 0, "is_public": False, "status": "Private/Local IP"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious_votes": stats.get("malicious", 0),
                "harmless_votes": stats.get("harmless", 0),
                "is_public": True,
                "status": "Success"
            }
        else:
            return {"malicious_votes": 0, "harmless_votes": 0, "is_public": True, "status": f"API Error ({response.status_code})"}
    except Exception as e:
        print(f"VirusTotal API Error: {e}")
        return {"malicious_votes": 0, "harmless_votes": 0, "is_public": True, "status": f"Connection Error: {e}"}