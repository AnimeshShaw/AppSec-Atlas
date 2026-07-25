---
title: "05 - CORS Auditing & Security Tooling"
description: "Audit CORS security using cURL, Burp Suite, CORStest, Nuclei, custom Python scanners, and Semgrep SAST rules for CI/CD pipelines."
keywords: ["AppSec", "CORS Auditing", "cURL", "CORStest", "Nuclei", "Semgrep", "Security Testing", "Burp Suite", "SAST"]
---

# 05 - CORS Auditing & Security Tooling

Auditing CORS implementation involves inspecting how backend servers process incoming `Origin` headers. Effective assessment requires combining manual CLI verification (`cURL`), automated scanner utilities (`CORStest`, `Nuclei`), custom Python auditing scripts, and Static Application Security Testing (SAST) rules.

---

## 1. Manual Verification Suite with `cURL`

`cURL` provides a precise mechanism for probing server CORS responses. When auditing an endpoint, execute the following six core tests:

### Test 1: Arbitrary Origin Reflection
```bash
curl -i -H "Origin: https://evil-attacker.com" \
     -H "Cookie: session=test_session_token" \
     https://api.example.com/v1/user/profile
```
- **Vulnerable Finding:** Response includes `Access-Control-Allow-Origin: https://evil-attacker.com` AND `Access-Control-Allow-Credentials: true`.

---

### Test 2: The `null` Origin Test
```bash
curl -i -H "Origin: null" \
     https://api.example.com/v1/user/profile
```
- **Vulnerable Finding:** Response includes `Access-Control-Allow-Origin: null`.

---

### Test 3: Domain Suffix Bypass Test
```bash
curl -i -H "Origin: https://example.com.evil-attacker.com" \
     https://api.example.com/v1/user/profile
```
- **Vulnerable Finding:** Response echoes `Access-Control-Allow-Origin: https://example.com.evil-attacker.com`.

---

### Test 4: Domain Prefix Bypass Test
```bash
curl -i -H "Origin: https://evilexample.com" \
     https://api.example.com/v1/user/profile
```
- **Vulnerable Finding:** Response echoes `Access-Control-Allow-Origin: https://evilexample.com`.

---

### Test 5: Preflight `OPTIONS` Verification
```bash
curl -i -X OPTIONS https://api.example.com/v1/user/profile \
     -H "Origin: https://evil-attacker.com" \
     -H "Access-Control-Request-Method: DELETE" \
     -H "Access-Control-Request-Headers: Authorization, X-Custom-Header"
```
- **Vulnerable Finding:** Response approves non-standard methods (`DELETE`) and custom headers for unauthorized origins.

---

### Test 6: Cache Poisoning (`Vary: Origin`) Check
```bash
curl -i -H "Origin: https://evil-attacker.com" \
     https://api.example.com/v1/user/profile
```
- **Vulnerable Finding:** Missing `Vary: Origin` response header.

---

## 2. Automated CORS Scanners

### A. CORStest
[CORStest](https://github.com/RUB-NDS/CORStest) is a Python-based CLI utility designed to scan target domains for common CORS misconfigurations.

```bash
# Installation
git clone https://github.com/RUB-NDS/CORStest.git
cd CORStest

# Scan a single target URL
python corstest.py https://api.example.com/v1/user/profile

# Scan a bulk list of endpoints
python corstest.py -i endpoints.txt -o cors_results.txt
```

---

### B. Nuclei Scanner Templates
[Nuclei](https://github.com/projectdiscovery/nuclei) allows running YAML-based templates across large attack surfaces to detect CORS flaws.

#### Custom Nuclei Template (`cors-misconfig.yaml`)
```yaml
id: cors-origin-reflection

info:
  name: CORS Arbitrary Origin Reflection & Credentials Enabled
  author: appsec-atlas
  severity: high
  description: Detects API endpoints that reflect arbitrary Origin headers with credentials.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    headers:
      Origin: "https://evil-attacker.com"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Access-Control-Allow-Origin: https://evil-attacker.com"
        part: header

      - type: word
        words:
          - "Access-Control-Allow-Credentials: true"
        part: header
```

Run command:
```bash
nuclei -u https://api.example.com -t cors-misconfig.yaml
```

---

## 3. Custom Python Auditing Script

Save the following script as `cors_auditor.py`. It probes a target URL using 10 distinct payload patterns and evaluates returned headers.

```python
#!/usr/bin/env python3
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def audit_cors_endpoint(target_url, trusted_domain="example.com"):
    print(f"[*] Starting CORS Security Audit for: {target_url}\n")
    
    test_payloads = [
        ("Arbitrary Origin", "https://evil-attacker.com"),
        ("Null Origin", "null"),
        ("Suffix Bypass", f"https://{trusted_domain}.evil-attacker.com"),
        ("Prefix Bypass", f"https://evil{trusted_domain}"),
        ("Unescaped Dot Match", f"https://x{trusted_domain}"),
        ("Subdomain Trust", f"https://dev.{trusted_domain}"),
        ("HTTP Scheme Downgrade", f"http://{trusted_domain}"),
    ]
    
    findings = 0
    
    for test_name, payload in test_payloads:
        headers = {"Origin": payload}
        try:
            res = requests.get(target_url, headers=headers, verify=False, timeout=5)
            acao = res.headers.get("Access-Control-Allow-Origin")
            acac = res.headers.get("Access-Control-Allow-Credentials")
            vary = res.headers.get("Vary")
            
            print(f"[Test: {test_name}] Payload: {payload}")
            print(f"  -> ACAO Header: {acao}")
            print(f"  -> ACAC Header: {acac}")
            print(f"  -> Vary Header: {vary}")
            
            if acao == payload:
                findings += 1
                if acac == "true":
                    print(f"  [!] CRITICAL: Arbitrary Origin Reflection WITH Credentials Enabled!")
                else:
                    print(f"  [!] HIGH: Arbitrary Origin Reflection (No Credentials).")
            elif acao == "null":
                findings += 1
                print(f"  [!] HIGH: Target trusts the 'null' origin!")
            elif acao == "*" and acac == "true":
                findings += 1
                print(f"  [!] HIGH: Invalid CORS configuration (Wildcard + Credentials).")
            
            if vary is None or "Origin" not in vary:
                print(f"  [WARN] Missing 'Vary: Origin' header! Risk of CDN Cache Poisoning.")
                
            print("-" * 60)
            
        except requests.RequestException as e:
            print(f"  [ERROR] Connection failed for {payload}: {e}\n")
            
    print(f"\n[*] Audit Complete. Total Potential Vulnerabilities Identified: {findings}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cors_auditor.py <target_url> [trusted_domain]")
        sys.exit(1)
        
    url = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else "example.com"
    audit_cors_endpoint(url, domain)
```

---

## 4. SAST Detection Rules (Semgrep)

Integrate the following custom Semgrep rules into your CI/CD pipeline to catch dangerous CORS code patterns prior to deployment.

### Semgrep Rule: Detect Insecure Express CORS Reflection (`cors-express-reflection.yaml`)

```yaml
rules:
  - id: express-dynamic-cors-reflection
    languages: [javascript, typescript]
    severity: ERROR
    message: "Insecure CORS: Reflecting incoming Origin header dynamically alongside credentials allows cross-origin data exfiltration."
    patterns:
      - pattern-either:
          - pattern: |
              `$RES.header('Access-Control-Allow-Origin', $`REQ.headers.origin);
          - pattern: |
              `$RES.setHeader('Access-Control-Allow-Origin', $`REQ.headers.origin);
          - pattern: |
              `$RES.set('Access-Control-Allow-Origin', $`REQ.get('Origin'));
    metadata:
      cwe: "CWE-942: Permissive Cross-Domain Policy"
      owasp: "A01:2021 - Broken Access Control"
```

---

### Semgrep Rule: Detect Flask Dynamic Origin Reflection (`cors-flask-reflection.yaml`)

```yaml
rules:
  - id: flask-dynamic-cors-reflection
    languages: [python]
    severity: ERROR
    message: "Flask dynamic CORS reflection detected. Do not echo request.headers.get('Origin') directly into Access-Control-Allow-Origin."
    patterns:
      - pattern: |
          $RESP.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
    metadata:
      cwe: "CWE-942: Permissive Cross-Domain Policy"
      owasp: "A05:2021 - Security Misconfiguration"
```
