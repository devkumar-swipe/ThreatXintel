# xpose.py - ThreatXintel Main Script
import os
import json
import time
import requests
from shodan import Shodan

API_FILE = 'api_keys.json'
DB_FILE = 'seen_data.json'

# Load or store persistent API keys
def load_api_keys():
    if os.path.exists(API_FILE):
        with open(API_FILE, 'r') as f:
            return json.load(f)
    else:
        api_keys = {
            "virustotal": input("Enter your VirusTotal API Key: ").strip(),
            "shodan": input("Enter your Shodan API Key: ").strip(),
            "ipinfo": input("Enter your IPinfo API Key: ").strip(),
            "abuseipdb": input("Enter your AbuseIPDB API Key: ").strip()
        }
        with open(API_FILE, 'w') as f:
            json.dump(api_keys, f)
        return api_keys

# Store seen data
def load_seen_data():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {"ips": [], "hashes": []}

def save_seen_data(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# Tool 1: Check new IPs or hashes
def check_ip_or_hash(virustotal_key, ipinfo_key, abuseipdb_key, value):
    if not virustotal_key:
        print("[!] Please input the VirusTotal API key from https://www.virustotal.com/gui/join-us")
        return

    headers_vt = {"x-apikey": virustotal_key}
    headers_abuse = {"Key": abuseipdb_key, "Accept": "application/json"} if abuseipdb_key else None

    if len(value) >= 64:
        endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"

    try:
        print("\n[✓] VirusTotal Report:")
        resp = requests.get(endpoint, headers=headers_vt)
        resp.raise_for_status()
        print(json.dumps(resp.json(), indent=2))
    except requests.RequestException as e:
        print(f"[!] VirusTotal error: {e}")

    if len(value) < 64:
        if ipinfo_key:
            try:
                print("\n[✓] IPinfo Report:")
                ipinfo_url = f"https://ipinfo.io/{value}?token={ipinfo_key}"
                ipinfo_resp = requests.get(ipinfo_url)
                ipinfo_resp.raise_for_status()
                print(json.dumps(ipinfo_resp.json(), indent=2))
            except requests.RequestException as e:
                print(f"[!] IPinfo error: {e}")
        else:
            print("[!] Please input the IPinfo API key from https://ipinfo.io")

        if abuseipdb_key:
            try:
                print("\n[✓] AbuseIPDB Report:")
                abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={value}&maxAgeInDays=90"
                abuse_resp = requests.get(abuse_url, headers=headers_abuse)
                abuse_resp.raise_for_status()
                print(json.dumps(abuse_resp.json(), indent=2))
            except requests.RequestException as e:
                print(f"[!] AbuseIPDB error: {e}")
        else:
            print("[!] Please input the AbuseIPDB API key from https://abuseipdb.com")

# Tool 2: Automated Scan Report (using VirusTotal)
def automated_scan(api_key, value):
    if not api_key:
        print("[!] Please input the VirusTotal API key from https://www.virustotal.com/gui/join-us")
        return

    url = f"https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        response = requests.post(url, headers=headers, data={"url": value})
        response.raise_for_status()
        scan_id = response.json()['data']['id']

        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        time.sleep(10)
        report = requests.get(report_url, headers=headers)
        print(json.dumps(report.json(), indent=2))
    except requests.RequestException as e:
        print(f"[!] Error scanning {value}: {e}")

# Tool 3: Monitor own services using Shodan
def monitor_services(api_key, query):
    if not api_key:
        print("[!] Please input the Shodan API key from https://shodan.io")
        return

    try:
        api = Shodan(api_key)
        results = api.search(query)
        for result in results['matches']:
            print(f"[+] {result['ip_str']}:{result['port']} - {result['org']}")
    except Exception as e:
        print(f"[!] Shodan Error: {e}")

# Tool 4: Auto-alert on risky IPs (VirusTotal + AbuseIPDB)
def alert_risky_ip(virustotal_key, abuseipdb_key, ip):
    if not virustotal_key:
        print("[!] Please input the VirusTotal API key from https://www.virustotal.com/gui/join-us")
        return

    headers_vt = {"x-apikey": virustotal_key}
    headers_abuse = {"Key": abuseipdb_key, "Accept": "application/json"} if abuseipdb_key else None

    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers_vt)
        resp.raise_for_status()
        data = resp.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        if malicious > 0:
            print(f"[ALERT] VirusTotal - Risky IP Detected: {ip} - Malicious Score: {malicious}")
        else:
            print(f"[OK] VirusTotal - IP {ip} is clean.")
    except requests.RequestException as e:
        print(f"[!] VirusTotal error: {e}")

    if abuseipdb_key:
        try:
            abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            abuse_resp = requests.get(abuse_url, headers=headers_abuse)
            abuse_resp.raise_for_status()
            abuse_data = abuse_resp.json()['data']
            if abuse_data['abuseConfidenceScore'] > 0:
                print(f"[ALERT] AbuseIPDB - Risk Score: {abuse_data['abuseConfidenceScore']}")
            else:
                print(f"[OK] AbuseIPDB - No recent abuse reports.")
        except requests.RequestException as e:
            print(f"[!] AbuseIPDB error: {e}")
    else:
        print("[!] Please input the AbuseIPDB API key from https://abuseipdb.com")

# Tool 5: Check if email is breached using HaveIBeenPwned
def check_email_breach(email):
    print("\n[✓] Checking breaches on HaveIBeenPwned")
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "User-Agent": "ThreatIntelSuite"
            # Optional: add 'hibp-api-key': 'your_key_here' if you have it
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            print("[OK] No breaches found.")
        elif response.status_code == 200:
            breaches = response.json()
            for b in breaches:
                print(f"[!] Breach: {b['Name']} on {b['BreachDate']} - {b['Domain']}")
        else:
            print(f"[!] HIBP error: {response.status_code}")
    except Exception as e:
        print(f"[!] Error checking email: {e}")

# Banner Display
banner = """


░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░  ░▒▓██████▓▒░  ░▒▓███████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░        
 ░▒▓██████▓▒░ ░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░   
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░        ░▒▓██████▓▒░ ░▒▓███████▓▒░ ░▒▓████████▓▒░ 
                                                                       
                                                                       
          
            """

print("\033[31m" + banner + "\033[0m")

# Main Menu
if __name__ == "__main__":
    api_keys = load_api_keys()
    seen_data = load_seen_data()

    print("""
[1] Check IP or Hash
[2] Automated Scan Report
[3] Monitor Your Services (Shodan)
[4] Alert on Risky IP Hit
[5] Check Email for Breaches (HaveIBeenPwned)
""")

    choice = input("Select tool (1-5): ").strip()

    if choice == '1':
        value = input("Enter IP address or hash: ").strip()
        if value not in seen_data['ips'] + seen_data['hashes']:
            check_ip_or_hash(api_keys['virustotal'], api_keys['ipinfo'], api_keys['abuseipdb'], value)
            if len(value) >= 64:
                seen_data['hashes'].append(value)
            else:
                seen_data['ips'].append(value)
            save_seen_data(seen_data)
        else:
            print("[!] Already checked.")

    elif choice == '2':
        url = input("Enter URL to scan: ").strip()
        automated_scan(api_keys['virustotal'], url)

    elif choice == '3':
        query = input("Enter Shodan query: ").strip()
        monitor_services(api_keys['shodan'], query)

    elif choice == '4':
        ip = input("Enter IP to monitor: ").strip()
        alert_risky_ip(api_keys['virustotal'], api_keys['abuseipdb'], ip)

    elif choice == '5':
        email = input("Enter email to check for breaches: ").strip()
        check_email_breach(email)

    else:
        print("[!] Invalid selection.")
