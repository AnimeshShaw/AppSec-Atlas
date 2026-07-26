---
title: 03 - SOC Automation and SOAR
description: SOAR platforms aim to reduce the manual workload on Tier 1 analysts by
  automating repetitive tasks, enriching alerts with threat intelligence, and exe...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '06'
- Defensive
- Soc
- Operations
- '03'
- Soc
- Automation
- And
- Soar
- Md
slug: /defensive/soc-operations/soc-automation-and-soar
---


# 03 - SOC Automation and SOAR

## Security Orchestration, Automation, and Response (SOAR)
SOAR platforms aim to reduce the manual workload on Tier 1 analysts by automating repetitive tasks, enriching alerts with threat intelligence, and executing standard response actions.

### Automated Enrichment Workflow
Before an analyst even looks at an alert, a SOAR platform can:
1. Extract IP addresses, domains, and file hashes (IOCs).
2. Query Threat Intelligence APIs (VirusTotal, AbuseIPDB, OTX) to determine reputation.
3. Query internal directories (Active Directory/Entra ID) to determine user roles and host criticality.
4. Append this compiled data to the alert ticket in Jira, ServiceNow, or TheHive.

### Working Python Code: Automated Alert Enricher
This simple Python script demonstrates how a SOAR platform might automatically enrich an IP address found in an alert using the AbuseIPDB API.

```python
import requests
import json
import os

def enrich_ip(ip_address, api_key):
    """Queries AbuseIPDB for IP reputation."""
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()['data']
            print(f"[*] Report for IP: {data['ipAddress']}")
            print(f"    - Abuse Confidence Score: {data['abuseConfidenceScore']}%")
            print(f"    - Total Reports: {data['totalReports']}")
            print(f"    - ISP: {data['isp']}")
            print(f"    - Country: {data['countryCode']}")
            
            # Simple automated decision logic
            if data['abuseConfidenceScore'] > 50:
                print("[!] High confidence of malicious activity. Recommend blocking on firewall.")
            else:
                print("[+] IP appears clean or low risk.")
        else:
            print(f"Error querying API: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # In a real environment, load this securely (e.g., via environment variables or AWS Secrets Manager)
    API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_API_KEY_HERE")
    SUSPICIOUS_IP = "185.153.196.213" # Example IP
    
    print(f"Starting automated enrichment for {SUSPICIOUS_IP}...")
    enrich_ip(SUSPICIOUS_IP, API_KEY)
```

### Automated Response Actions
Beyond enrichment, SOAR can execute actions (with or without human approval):
- **Isolate Host:** Send API call to EDR (e.g., CrowdStrike) to isolate a compromised machine from the network.
- **Block IP/Domain:** Update firewall blocklists dynamically.
- **Disable Account:** Temporarily disable a compromised AD account.
