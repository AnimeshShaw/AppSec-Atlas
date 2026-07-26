---
title: 02 - Alert Triage and Investigation
description: When a SIEM or EDR tool triggers an alert, the Tier 1 analyst executes
  a structured workflow to determine its validity.
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
- '02'
- Alert
- Triage
- And
- Investigation
- Md
slug: /defensive/soc-operations/alert-triage-and-investigation
---


# 02 - Alert Triage and Investigation

## Alert Triage Workflow
When a SIEM or EDR tool triggers an alert, the Tier 1 analyst executes a structured workflow to determine its validity.

### 1. Alert Contextualization
- **Who:** Which user account triggered this? Is it a standard user, an admin, or a service account?
- **What:** What was the action? (e.g., executing a suspicious PowerShell command, multiple failed logins).
- **Where:** Which host(s) are involved? Are they critical servers or standard workstations?

### 2. True Positive vs. Benign Noise (False Positive)
- **True Positive (TP):** Malicious activity correctly identified by the rule.
- **False Positive (FP):** Legitimate activity misidentified as malicious (e.g., an IT admin running a network scan).
- **Benign True Positive (BTP):** The rule triggered correctly on the activity, but the context makes it non-malicious (e.g., a vulnerability scanner running an authorized scan).

### MITRE ATT&CK Mapping
Mapping alerts to the **MITRE ATT&CK** framework provides a common language to understand the adversary's objective.

| Tactic | Technique | Example Alert |
|--------|-----------|---------------|
| **Initial Access** | Phishing (T1566) | Multiple clicks on known malicious URL |
| **Execution** | Command and Scripting Interpreter (T1059) | Encoded PowerShell command execution |
| **Persistence** | Scheduled Task/Job (T1053) | `schtasks.exe` creating a new task running from `C:\Temp` |
| **Credential Access** | OS Credential Dumping (T1003) | `lsass.exe` memory dump using ProcDump |

## Working Triage Playbook: "Suspicious PowerShell Execution"

When an alert for encoded PowerShell triggers:

1. **Extract the Payload:** Identify the base64 encoded string from the command line arguments.
2. **Decode:** Use CyberChef or a local script to decode the base64 payload.
3. **Analyze:**
   - Does it attempt to download a file? (e.g., `Invoke-WebRequest`, `Net.WebClient`)
   - Does it execute in memory? (e.g., `IEX`)
   - Does it disable AMSI (Anti-Malware Scan Interface)?
4. **Investigate the Host:**
   - What spawned the PowerShell process? (Parent Process ID - PPID). Was it `cmd.exe`, `explorer.exe`, or `winword.exe` (Word document)?
5. **Decision:**
   - If spawned by `winword.exe` and downloading an unknown payload -> **Escalate to Tier 2 (Critical Incident)**.
   - If spawned by a legitimate deployment tool running a known admin script -> **Mark as False Positive, Tune Rule**.
