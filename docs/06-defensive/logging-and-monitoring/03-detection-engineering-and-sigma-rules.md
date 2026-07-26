---
title: 03 - Detection Engineering & Sigma Rules
description: Detection Engineering is the practice of identifying threats by writing
  rules that analyze log data. To avoid vendor lock-in (e.g., writing rules only...
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
- '03'
- Detection
- Engineering
- And
- Sigma
- Rules
- Md
slug: /defensive/logging-and-monitoring/detection-engineering-and-sigma-rules
---


# 03 - Detection Engineering & Sigma Rules

Detection Engineering is the practice of identifying threats by writing rules that analyze log data. To avoid vendor lock-in (e.g., writing rules only in Splunk SPL or Elastic KQL), the industry standard is **Sigma**.

## 📐 What is Sigma?

Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward YAML format. A Sigma rule can be converted into queries for almost any SIEM (Splunk, Elastic, QRadar, ArcSight, Microsoft Sentinel).

## 📝 Writing Sigma Rules

Let's write a Sigma rule to detect an administrator login from an unauthorized IP address or abnormal time.

### Example: Suspicious Admin Login

```yaml
title: Suspicious Admin Login
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects successful login to the 'admin' account from an external IP address.
author: AppSec Atlas
date: 2023-10-25
logsource:
    category: authentication
    product: webapp
detection:
    selection:
        event.action: 'user-login'
        event.outcome: 'success'
        user.name: 'admin'
    filter:
        source.ip|startswith: 
            - '10.'
            - '192.168.'
            - '172.16.'
    condition: selection and not filter
falsepositives:
    - Administrators logging in from a new VPN subnet (needs whitelisting).
level: high
```

## 🔄 Converting Sigma to SIEM Queries

Using the `sigma-cli` tool, you can translate the YAML rule into a backend-specific query.

### Convert to Elastic KQL
```bash
sigma convert -t kql -p ecs rule.yml
```
**Output:**
```kql
event.action:"user-login" AND event.outcome:"success" AND user.name:"admin" AND NOT source.ip:(10.* OR 192.168.* OR 172.16.*)
```

### Convert to Splunk SPL
```bash
sigma convert -t splunk rule.yml
```
**Output:**
```spl
(event.action="user-login" event.outcome="success" user.name="admin") NOT (source.ip="10.*" OR source.ip="192.168.*" OR source.ip="172.16.*")
```

## 🚨 Common Detection Scenarios

1. **Brute Force Attacks:** Detect `event.action: "user-login" AND event.outcome: "failure"` occurring more than 10 times in 1 minute from the same `source.ip`.
2. **SQL Injection:** Detect `url.query` or `http.request.body` containing keywords like `UNION SELECT`, `OR 1=1`, or `--`.
