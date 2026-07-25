---
title: "05 - Technical Phishing Defenses"
description: "Beyond email authentication (DMARC) and user awareness, organizations must implement technical controls to analyze payloads and monitor the external t..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Social Engineering", "05 Technical Phishing Defenses.Md"]
---

# 05 - Technical Phishing Defenses

Beyond email authentication (DMARC) and user awareness, organizations must implement technical controls to analyze payloads and monitor the external threat landscape.

## Inbound Email Sandboxing

Sandboxing involves executing email attachments or opening links in a secure, isolated virtual environment to observe their behavior before delivering them to the user.

*   **Capabilities:** Detects zero-day malware, macro execution, network callbacks (C2 beacons), and credential harvesting pages.
*   **Time-of-Click Protection:** Attackers often send emails with benign links and weaponize the destination later. Time-of-click protection rewrites URLs in emails so they are analyzed *every time* the user clicks, not just upon delivery.

## Attachment Macro Disassembly

Malicious Microsoft Office documents containing VBA macros remain a prevalent threat vector. Analysts use tools to safely extract and analyze these scripts without executing the document.

### Using `oleVBA` (oletools)
`oletools` is a suite of Python tools for analyzing OLE2 files (Office docs).

```bash
# Install oletools
pip install oletools

# Extract and analyze macros
olevba malicious_document.docm
```
`olevba` will detect suspicious keywords (e.g., `AutoOpen`, `Shell`, `CreateObject`), Base64 encoded strings, and potential payload URLs.

## YARA Rules for Malicious Attachments

YARA is a pattern-matching Swiss knife for malware researchers. You can write rules to detect specific patterns within email attachments at the mail gateway level.

**Example YARA Rule for suspicious VBA macro execution:**
```yara
rule Suspicious_VBA_Macro {
    meta:
        description = "Detects documents with AutoOpen and Shell execution"
        author = "AppSec Atlas"
    strings:
        $auto = "AutoOpen" nocase ascii wide
        $shell = "WScript.Shell" nocase ascii wide
        $http = "MSXML2.XMLHTTP" nocase ascii wide
    condition:
        $auto and ($shell or $http)
}
```

## Domain Squatting Monitoring (dnstwist)

Attackers register domains that look similar to your organization's domain (typosquatting, homoglyphs) to use in phishing campaigns. Proactive monitoring allows you to identify and block these domains before they are weaponized.

### Using `dnstwist`
`dnstwist` generates a list of permutation domains and checks if they are registered or resolving.

```bash
# Install dnstwist
pip install dnstwist

# Run dnstwist against a domain
dnstwist --registered example.com
```

**Working Python Script: Automated Typo-Squatting Alerting**
```python
import dnstwist
import json

def check_typosquatting(domain):
    print(f"[*] Generating permutations for {domain}...")
    fuzz = dnstwist.DomainFuzz(domain)
    fuzz.generate()
    fuzz.threads = 10
    
    print(f"[*] Checking {len(fuzz.domains)} permutations...")
    fuzz.resolve()
    
    registered = []
    for domain_data in fuzz.domains:
        if 'dns-a' in domain_data or 'dns-mx' in domain_data:
            registered.append(domain_data)
            
    return registered

if __name__ == "__main__":
    target_domain = "google.com"
    results = check_typosquatting(target_domain)
    
    print(f"\n[!] Found {len(results)} registered permutations:")
    for res in results:
        print(f" - {res.get('domain-name')} (IP: {res.get('dns-a', ['N/A'])[0]})")
```
