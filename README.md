# ThreatXintel
**ThreatXintel** is a compact yet powerful threat intelligence suite written in Python. The tool combines multiple cybersecurity APIs to help analysts, researchers, and bug bounty hunters monitor, analyze, and respond to digital threats efficiently.

## 🔧 Features

| Module | Description |
|--------|-------------|
| 🧠 IP/Hash Analyzer | Detect threats using VirusTotal, IPinfo, and AbuseIPDB |
| 📄 URL Scan Reporter | Automated URL scan reports via VirusTotal |
| 🌐 Service Monitor | Monitor your services on the internet using Shodan |
| 🚨 Risky IP Alerts | Alerts you on detection of suspicious IPs |
| ✉️ Breach Lookup | Checks if your email has been exposed in data breaches using HaveIBeenPwned |


## 🛡️ Purpose of ThreatXintel
ThreatXintel is designed to serve as a lightweight threat intelligence toolkit that helps you:

Identify malicious IPs and file hashes
→ Using VirusTotal, IPinfo, and AbuseIPDB

Automatically scan suspicious URLs
→ With VirusTotal to see if a URL is dangerous

Monitor your public-facing infrastructure
→ Via Shodan, to detect exposed services and misconfigurations

Receive auto-alerts when risky IPs hit your server
→ Alerts based on VirusTotal and AbuseIPDB threat scores

Check if emails have been pwned in known breaches
→ Using the HaveIBeenPwned database

## 🗂 Main File
xpose.py – Main threat intelligence tool

api_keys.json – Securely stores API keys

seen_data.json – Tracks already scanned IPs and hashes

requirements.txt – Python dependencies


## 📦 Installation

First, make sure you have Python 3 and `pip` installed.

Then install following required packages:

```bash
pip install requests shodan
```

```bash
git clone https://github.com/devkumar-swipe/ThreatXintel.git
cd ThreatXintel
python3 xpose.py
```


