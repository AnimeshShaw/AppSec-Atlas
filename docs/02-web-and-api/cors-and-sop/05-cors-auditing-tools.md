---
title: "05 - CORS Auditing Tools"
description: "Auditing CORS configurations involves sending HTTP requests with various `Origin` payloads to observe how the server's `Access-Control-Allow-Origin` (..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Cors And Sop", "05 Cors Auditing Tools.Md"]
---

# 05 - CORS Auditing Tools

Auditing CORS configurations involves sending HTTP requests with various `Origin` payloads to observe how the server's `Access-Control-Allow-Origin` (ACAO) header responds. 

## 1. Manual Testing with cURL
You can quickly test a CORS configuration using `curl` by injecting an `Origin` header.

**Test arbitrary origin:**
```bash
curl -H "Origin: https://evil.com" -I https://api.example.com/endpoint
```
*Look for: `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true`*

**Test `null` origin:**
```bash
curl -H "Origin: null" -I https://api.example.com/endpoint
```

**Test prefix/suffix bypass:**
```bash
curl -H "Origin: https://example.com.evil.com" -I https://api.example.com/endpoint
curl -H "Origin: https://evilexample.com" -I https://api.example.com/endpoint
```

## 2. Burp Suite Professional (CORS Scanner)
Burp Suite Professional includes automated checks for CORS misconfigurations in its Active Scanner.

- **Manual setup:** In Burp Repeater, you can manually modify the `Origin` header in the request to test for reflection.
- **Extensions:** The "CORS *" extension from the BApp Store adds passive and active scanning capabilities specifically targeted at identifying complex CORS bypasses (e.g., regex flaws).

## 3. CORStest
[CORStest](https://github.com/RUB-NDS/CORStest) is a fast, specialized command-line tool written in Python for finding CORS misconfigurations.

**Installation:**
```bash
git clone https://github.com/RUB-NDS/CORStest.git
cd CORStest
```

**Usage:**
Provide a list of URLs in a text file.
```bash
python corstest.py urls.txt
```
The tool automatically checks for reflection, wildcard usage with credentials, and `null` origin trust.

## 4. Custom Python Auditing Script
You can script custom audits if you need to integrate CORS checks into a CI/CD pipeline or custom security scanning framework.

```python
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def audit_cors(url, allowed_domain):
    payloads = [
        "https://evil.com",
        "null",
        f"https://{allowed_domain}.evil.com",
        f"https://evil{allowed_domain}"
    ]
    
    print(f"Auditing CORS for: {url}")
    
    for origin in payloads:
        headers = {'Origin': origin}
        try:
            resp = requests.options(url, headers=headers, verify=False, timeout=5)
            acao = resp.headers.get('Access-Control-Allow-Origin')
            acac = resp.headers.get('Access-Control-Allow-Credentials')
            
            if acao == origin:
                print(f"[!] Vulnerable to Reflection. Payload: {origin}")
                if acac == 'true':
                    print(f"    --> CRITICAL: Credentials Allowed!")
            elif acao == '*':
                print(f"[!] Wildcard detected for payload: {origin}")
        except Exception as e:
            print(f"Error testing {origin}: {e}")

# Example Usage
# audit_cors("https://api.vulnerable.com/data", "vulnerable.com")
```
