---
title: 05 - SOC Tooling and Dashboards
description: Building a highly effective SOC doesn't require millions of dollars in
  licensing. Many organizations start with or heavily utilize open-source and fre...
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
- '05'
- Soc
- Tooling
- And
- Dashboards
- Md
slug: /defensive/soc-operations/soc-tooling-and-dashboards
---


# 05 - SOC Tooling and Dashboards

## Open-Source SOC Stack
Building a highly effective SOC doesn't require millions of dollars in licensing. Many organizations start with or heavily utilize open-source and free-tier tooling.

### 1. Wazuh (HIDS / SIEM)
Wazuh is an open-source security monitoring platform that provides host-based intrusion detection (HIDS), log data analysis, file integrity monitoring (FIM), and vulnerability detection.
- **Architecture:** Agents installed on endpoints forward telemetry to the Wazuh Manager, which correlates the data against threat intelligence and rulesets.
- **Use Case:** Detecting anomalous file changes, brute-force attacks, and compliance violations.

### 2. Shuffle (SOAR)
Shuffle is an open-source SOAR platform designed for accessibility.
- **Capabilities:** Visual playbook editor, webhook integrations, and API connectivity.
- **Use Case:** Automatically taking a Wazuh alert, parsing out an IP address, sending it to TheHive (Case Management), and querying VirusTotal.

### 3. MISP (Threat Intelligence Platform)
MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform for sharing, storing, and correlating Indicators of Compromise (IOCs).
- **Use Case:** Aggregating threat feeds (OSINT) and syncing them with the SIEM (e.g., Wazuh or Sentinel) to alert on known bad IPs/Hashes.

### 4. OpenSearch / Elastic Stack (Data Lake / Dashboards)
Used as the backend storage and visualization layer for SIEM data.
- **Dashboards:** Visualizing data is critical for Tier 1 analysts to quickly grasp the current state of the network.

## Building SOC Dashboards
Effective dashboards should answer critical questions at a glance.

### Essential Dashboard Visualizations:
1. **Total Alerts Over Time (Line Chart):** Helps identify spikes in activity (e.g., a sudden malware outbreak or scanning activity).
2. **Alerts by Severity (Pie Chart):** Quickly see the ratio of Critical/High alerts versus Low/Info.
3. **Top 10 Source IPs (Bar Chart):** Identify the most aggressive external attackers or compromised internal hosts.
4. **Top 10 Targeted Users (Bar Chart):** Identify which users are under the most frequent attack (e.g., phishing or credential stuffing).
5. **Geographic Map of Denied Traffic (Map):** Visualize where malicious scanning or attack attempts are originating globally.
