---
title: '06 - Hands-on Lab: Forensic Log Parser'
description: In this lab, we build a Python script to verify evidence integrity (SHA-256)
  and parse an artifact (mock auth.log) for malicious activity.
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '06'
- Defensive
- Digital
- Forensics
- '06'
- Hands
- 'On'
- Lab
- Md
slug: /defensive/digital-forensics/hands-on-lab
---


# 06 - Hands-on Lab: Forensic Log Parser

In this lab, we build a Python script to verify evidence integrity (SHA-256) and parse an artifact (mock auth.log) for malicious activity.

## `lab_forensics.py`

```python
import hashlib
import re

def verify_evidence(file_path, expected_hash):
    """Calculates SHA-256 hash of a file and compares it."""
    sha256 = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                
        calculated_hash = sha256.hexdigest()
        if calculated_hash == expected_hash:
            print(f"[+] Integrity Verified. Hash: {calculated_hash}")
            return True
        else:
            print(f"[-] Integrity Failed!\nExpected: {expected_hash}\nGot: {calculated_hash}")
            return False
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return False

def parse_auth_log(file_path):
    """Finds failed SSH logins and extracts IPs."""
    failed_logins = {}
    ip_pattern = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1
                    
        print("\n--- Failed Login Summary ---")
        for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
            print(f"IP: {ip} - {count} attempts")
            
    except FileNotFoundError:
         print(f"File {file_path} not found.")

if __name__ == "__main__":
    # Create a mock log file for testing
    with open("mock_auth.log", "w") as f:
        f.write("May 10 12:00:00 server sshd[123]: Failed password for root from 192.168.1.50 port 22\n")
        f.write("May 10 12:01:00 server sshd[123]: Failed password for root from 192.168.1.50 port 22\n")
        f.write("May 10 12:05:00 server sshd[125]: Accepted password for admin from 10.0.0.5\n")
    
    # Calculate its hash (for demo purposes)
    demo_hash = hashlib.sha256(open("mock_auth.log", "rb").read()).hexdigest()
    
    if verify_evidence("mock_auth.log", demo_hash):
        parse_auth_log("mock_auth.log")
```
