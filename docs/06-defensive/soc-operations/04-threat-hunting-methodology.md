---
title: 04 - Threat Hunting Methodology
description: Threat hunting is the proactive, iterative process of searching through
  networks and datasets to detect and isolate advanced threats that evade existi...
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
- '04'
- Threat
- Hunting
- Methodology
- Md
slug: /defensive/soc-operations/threat-hunting-methodology
---


# 04 - Threat Hunting Methodology

## What is Threat Hunting?
Threat hunting is the proactive, iterative process of searching through networks and datasets to detect and isolate advanced threats that evade existing security solutions (like SIEM alerts or EDR signatures). It assumes the breach has already occurred (Assume Breach paradigm).

### Hypothesis-Driven Hunting
A mature threat hunt starts with a hypothesis. 
- **Hypothesis:** "Attackers are establishing persistence on Windows endpoints using Scheduled Tasks."
- **Data Source:** Windows Event Logs (Event ID 4698 - A scheduled task was created).
- **Analysis:** Look for anomalies in task names, execution paths (e.g., executing from `C:\Users\Public`), or execution binaries (e.g., running `powershell.exe -ep bypass`).

### Hunting for Persistence Mechanisms
Persistence ensures the attacker maintains access across reboots.

#### 1. Scheduled Tasks (Windows)
Attackers often create tasks disguised as legitimate updates.
* **KQL (Kusto Query Language) Example for Microsoft Sentinel:**
```kql
SecurityEvent
| where EventID == 4698
| parse EventData with * '<Data Name="TaskName">' TaskName '</Data>' *
| parse EventData with * '<Data Name="Command">' Command '</Data>' *
| where Command has_any ("powershell", "cmd", "wscript", "cscript")
| where Command has_any ("-enc", "-EncodedCommand", "download", "invoke")
| project TimeGenerated, Computer, Account, TaskName, Command
```

#### 2. Systemd Services (Linux)
Attackers create malicious systemd services to run miners or reverse shells.
* **Hunt Query (Splunk):**
```splunk
index=linux sourcetype=linux_secure OR sourcetype=syslog
| search "systemd" AND "Created symlink" AND ("*.service")
| stats count by host, process, _raw
```

#### 3. Registry Run Keys (Windows)
Attackers add entries to the Run or RunOnce registry keys.
* **Sigma Rule Example:**
```yaml
title: Suspicious Registry Run Key Creation
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects the creation of suspicious registry run keys for persistence.
logsource:
    category: registry_add
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Details|contains:
            - 'powershell.exe'
            - 'cmd.exe'
            - 'C:\Users\Public\'
            - 'C:\Temp\'
    condition: selection
falsepositives:
    - Legitimate administrative scripts (requires tuning)
level: high
```

## IOC Matching (Intelligence-Driven Hunting)
Instead of a hypothesis, you start with new Threat Intelligence (e.g., a list of IP addresses or file hashes from a recent APT report) and search retrospectively across historical logs (usually 30-90 days back) to see if those IOCs were ever observed in the environment.
