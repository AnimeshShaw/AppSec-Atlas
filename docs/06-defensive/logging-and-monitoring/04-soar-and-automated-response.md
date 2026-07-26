---
title: 04 - SOAR & Automated Response
description: Security Orchestration, Automation, and Response (SOAR) takes the manual
  effort out of incident response. When a SIEM (or Sigma rule) triggers an aler...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '06'
- Defensive
- Logging
- And
- Monitoring
- '04'
- Soar
- And
- Automated
- Response
- Md
slug: /defensive/logging-and-monitoring/soar-and-automated-response
---


# 04 - SOAR & Automated Response

Security Orchestration, Automation, and Response (SOAR) takes the manual effort out of incident response. When a SIEM (or Sigma rule) triggers an alert, SOAR executes a predefined "Playbook".

## 🤖 What does SOAR do?

1. **Orchestration:** Connects disparate tools (Firewalls, IAM, Slack, Jira) via APIs.
2. **Automation:** Replaces manual Analyst steps (e.g., looking up an IP on VirusTotal).
3. **Response:** Takes action (e.g., blocking an IP, disabling a user).

## 🛠️ Typical SOAR Playbook Example

**Trigger:** SIEM detects "Suspicious Admin Login" (from our Sigma rule).
1. **Enrich:** SOAR queries AbuseIPDB or VirusTotal to check the reputation of the source IP.
2. **Notify:** SOAR sends a Slack message to the Security Operations Center (SOC) channel.
3. **Action:** If the IP is malicious, SOAR automatically adds the IP to the AWS WAF blocklist or Nginx deny list.
4. **Ticketing:** SOAR creates a Jira ticket for tracking.

## 🐍 Python Webhook Automation (Mini-SOAR)

You don't always need a million-dollar SOAR platform. You can build simple automated responses using webhooks and Python.

### Example: Automated Slack Alert & IP Block Script

```python
import requests
import json
import os

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def handle_siem_alert(alert_data):
    """
    Called when a SIEM webhook is triggered.
    """
    rule_name = alert_data.get("rule", "Unknown Alert")
    source_ip = alert_data.get("source_ip")
    
    # 1. Notify Slack
    slack_message = {
        "text": f"🚨 *Security Alert Triggered!* 🚨\n*Rule:* {rule_name}\n*Source IP:* {source_ip}\nInitiating automated block..."
    }
    requests.post(SLACK_WEBHOOK_URL, json=slack_message)
    
    # 2. Automated Response: Block IP (Simulation)
    block_ip_at_firewall(source_ip)

def block_ip_at_firewall(ip_address):
    """
    Simulates calling a Firewall/WAF API to block the IP.
    """
    print(f"[+] API CALL: Blocking IP {ip_address} on edge firewall.")
    # E.g., requests.post("https://api.cloudflare.com/client/v4/zones/.../firewall/access_rules/rules", ...)

# Simulating an incoming webhook payload from the SIEM
sample_alert = {
    "rule": "Suspicious Admin Login",
    "source_ip": "203.0.113.45"
}

if __name__ == "__main__":
    handle_siem_alert(sample_alert)
```
