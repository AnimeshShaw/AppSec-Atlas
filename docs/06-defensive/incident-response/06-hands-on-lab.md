---
title: "06 - Hands-On Lab: Web Server Incident Triage"
description: "In this lab, you will act as a first responder. You have received an alert about suspicious activity on a web server. You will use a Python script to ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Incident Response", "06 Hands On Lab.Md"]
---

# 06 - Hands-On Lab: Web Server Incident Triage

In this lab, you will act as a first responder. You have received an alert about suspicious activity on a web server. You will use a Python script to parse an Nginx access log, identify a webshell upload, find the attacker's IP, and determine what commands were executed.

## Scenario
*   **Host:** `web-prod-01`
*   **Evidence:** `access.log` (provided below)
*   **Goal:** Identify the attack vector, the webshell name, the attacker's IP, and generate a remediation plan.

## 1. Setup the Evidence

Create a file named `access.log` with the following content (representing the compromised server's logs):

```text
192.168.1.15 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
203.0.113.50 - - [10/Oct/2023:14:01:12 +0000] "GET /admin/login.php HTTP/1.1" 200 1524 "-" "curl/7.68.0"
203.0.113.50 - - [10/Oct/2023:14:01:15 +0000] "POST /admin/login.php HTTP/1.1" 302 0 "-" "curl/7.68.0"
203.0.113.50 - - [10/Oct/2023:14:02:01 +0000] "POST /admin/upload.php HTTP/1.1" 200 45 "-" "curl/7.68.0"
203.0.113.50 - - [10/Oct/2023:14:02:10 +0000] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 33 "-" "curl/7.68.0"
203.0.113.50 - - [10/Oct/2023:14:02:15 +0000] "GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2048 "-" "curl/7.68.0"
192.168.1.20 - - [10/Oct/2023:14:05:00 +0000] "GET /about.html HTTP/1.1" 200 312 "-" "Mozilla/5.0"
```

## 2. Python Triage Script

Write a Python script (`triage.py`) to parse this log and extract IoCs.

```python
# triage.py
import re
from collections import defaultdict

LOG_FILE = 'access.log'

def parse_logs(filepath):
    # Regex to match basic Nginx combined log format
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<time>.*?)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>.*?)\s+HTTP/.*?"\s+(?P<status>\d+)'
    )
    
    suspicious_ips = defaultdict(int)
    commands_executed = []
    webshells = []

    print("[*] Analyzing logs for suspicious activity...\n")
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    ip = match.group('ip')
                    url = match.group('url')
                    status = match.group('status')
                    
                    # Hunt 1: Look for common webshell parameters (cmd, exec, c)
                    if 'cmd=' in url or 'exec=' in url:
                        suspicious_ips[ip] += 1
                        commands_executed.append(url)
                        
                        # Extract potential shell name
                        shell_name = url.split('?')[0]
                        if shell_name not in webshells:
                            webshells.append(shell_name)
                            
    except FileNotFoundError:
        print(f"[-] Error: Could not find {filepath}")
        return

    # Report Findings
    print("=== INCIDENT TRIAGE REPORT ===")
    
    if webshells:
        print(f"\n[!] POTENTIAL WEBSHELLS DETECTED:")
        for shell in webshells:
            print(f"    - {shell}")
            
    if commands_executed:
        print(f"\n[!] SUSPICIOUS COMMANDS EXECUTED:")
        for cmd in commands_executed:
            print(f"    - {cmd}")
            
    if suspicious_ips:
        print(f"\n[!] SUSPICIOUS IP ADDRESSES:")
        for ip, count in suspicious_ips.items():
            print(f"    - {ip} (Hit Count: {count})")
    else:
        print("\n[*] No suspicious activity detected in logs.")

if __name__ == '__main__':
    parse_logs(LOG_FILE)
```

## 3. Execution and Analysis

Run the script: `python triage.py`

**Expected Output:**
You should identify that IP `203.0.113.50` uploaded a file via `/admin/upload.php` and then accessed a webshell at `/uploads/shell.php`, executing `whoami` and `cat /etc/passwd`.

## 4. Containment and Remediation Plan

Based on the lab findings, write out your next steps:
1.  **Block IP:** Block `203.0.113.50` at the WAF/Firewall.
2.  **Isolate:** Isolate `web-prod-01`.
3.  **Investigate:** Check if `admin/login.php` was bypassed or brute-forced. Review the source code of `upload.php` for missing file extension validation.
4.  **Eradicate:** Remove `shell.php`, patch `upload.php` to prevent `.php` uploads, and rotate admin credentials.
