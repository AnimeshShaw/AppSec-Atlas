# 06 - Hands-on Lab: Automated Alert Triage

## Objective
In this self-contained lab, we will build a Python-based SOC Alert Enricher. It simulates receiving an alert containing an IP address, queries a (simulated) Threat Intelligence API, and then takes an automated action (SOAR pipeline).

## Scenario
Your SIEM generated an alert: `Multiple failed SSH logins detected from IP 203.0.113.50`. 
Instead of manually checking this IP, our script will handle the triage.

## Python Lab: SOC Threat Alert Enricher Tool

### 1. The Script (`soc_triage_pipeline.py`)

Create a file named `soc_triage_pipeline.py` and run it.

```python
import json
import time

# --- 1. Simulated Threat Intelligence API ---
def query_threat_intel(ip_address):
    """Simulates querying VirusTotal or AbuseIPDB."""
    print(f"[*] Querying Threat Intel for IP: {ip_address}...")
    time.sleep(1) # Simulate network delay
    
    # Mock Database
    mock_db = {
        "203.0.113.50": {"malicious_votes": 45, "tags": ["ssh-bruteforce", "botnet"]},
        "8.8.8.8": {"malicious_votes": 0, "tags": ["google", "dns"]},
        "198.51.100.22": {"malicious_votes": 12, "tags": ["scanner"]}
    }
    
    return mock_db.get(ip_address, {"malicious_votes": 0, "tags": []})

# --- 2. Automated Action (Remediation) ---
def block_ip_on_firewall(ip_address):
    """Simulates an API call to a firewall (e.g., Palo Alto or pfSense)."""
    print(f"[ACTION] Executing API call to block {ip_address} on edge firewall.")
    # In reality, this would be a requests.post() to the firewall API
    print(f"[SUCCESS] IP {ip_address} successfully blocked.\n")

def create_jira_ticket(ip_address, intel_data):
    """Simulates creating a ticketing system entry."""
    print(f"[ACTION] Creating Jira ticket for investigation of {ip_address}.")
    print(f"[SUCCESS] Ticket SOC-1024 created. Assigned to Tier 2.\n")

# --- 3. The Triage Pipeline ---
def process_alert(alert_data):
    print(f"\n--- New Alert Received ---")
    print(f"Alert ID: {alert_data['alert_id']}")
    print(f"Description: {alert_data['description']}")
    
    target_ip = alert_data['source_ip']
    
    # Step 1: Enrich
    intel = query_threat_intel(target_ip)
    print(f"[+] Enrichment Results: {intel['malicious_votes']} malicious votes. Tags: {intel['tags']}")
    
    # Step 2: Decision Logic (The 'Brain' of the SOAR)
    if intel['malicious_votes'] > 20:
        print("[!] HIGH CONFIDENCE THREAT DETECTED.")
        block_ip_on_firewall(target_ip)
        create_jira_ticket(target_ip, intel)
    elif intel['malicious_votes'] > 0:
        print("[!] SUSPICIOUS ACTIVITY DETECTED.")
        create_jira_ticket(target_ip, intel)
    else:
        print("[-] Benign activity or no data. Closing alert (False Positive/Noise).\n")

# --- Execution ---
if __name__ == "__main__":
    # Simulated incoming alerts from a SIEM
    alerts = [
        {"alert_id": "ALT-001", "description": "Multiple failed SSH logins", "source_ip": "203.0.113.50"},
        {"alert_id": "ALT-002", "description": "High volume DNS queries", "source_ip": "8.8.8.8"},
        {"alert_id": "ALT-003", "description": "Web directory brute-force", "source_ip": "198.51.100.22"}
    ]
    
    for alert in alerts:
        process_alert(alert)
        time.sleep(2)
```

### 2. Expected Output
When you run the script, you should see the pipeline dynamically route the response based on the "malicious_votes" score. The highly malicious IP gets blocked automatically, the suspicious one gets a ticket created, and the benign one is closed as noise.
