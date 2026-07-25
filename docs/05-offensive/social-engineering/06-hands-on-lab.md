---
title: "06. Hands-On Vulnerability Lab"
description: "In this hands-on lab, you will write a **Python Email Header & DMARC Audit Tool** to detect spoofed inbound emails, parse SPF/DKIM headers, and implem..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Social Engineering", "06 Hands On Lab.Md"]
---

# 06. Hands-On Vulnerability Lab

In this hands-on lab, you will write a **Python Email Header & DMARC Audit Tool** to detect spoofed inbound emails, parse SPF/DKIM headers, and implement a strict DMARC enforcement policy.

---

## 🧪 Lab Setup

### Step 1: Email Header Audit Tool (`audit_email_headers.py`)

```python
# audit_email_headers.py
import re

sample_spoofed_email = """
Received: from mail.evil-attacker.com (evil-attacker.com [198.51.100.42])
From: CEO <ceo@techcorp.com>
To: finance@techcorp.com
Subject: URGENT: Wire Transfer Request
Authentication-Results: spf=fail (sender IP 198.51.100.42 is not authorized) dkim=fail
"""

def audit_headers(raw_email: str):
    print("=== AUDITING INBOUND EMAIL HEADERS ===")
    
    from_match = re.search(r"From:\s*(.*)", raw_email)
    spf_match = re.search(r"spf=(\w+)", raw_email)
    dkim_match = re.search(r"dkim=(\w+)", raw_email)
    
    print(f"Header From: {from_match.group(1) if from_match else 'Unknown'}")
    print(f"SPF Status: {spf_match.group(1) if spf_match else 'None'}")
    print(f"DKIM Status: {dkim_match.group(1) if dkim_match else 'None'}")
    
    if spf_match and spf_match.group(1) == "fail":
        print("🚨 SECURITY ALERT: Email failed SPF check! Potential Spoofed/Phishing Email!")

audit_headers(sample_spoofed_email)
```

---

### Step 2: Hardened DNS DMARC Policy (`dmarc_record.txt`)

```text
# Hardened DMARC Record (p=reject)
_dmarc.techcorp.com. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@techcorp.com; ruf=mailto:dmarc-forensics@techcorp.com; fo=1"
```

---

*Next Chapter: [07. References & Standards →](07-references.md)*
