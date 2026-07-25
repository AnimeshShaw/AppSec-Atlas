# 05 - Web Security Scanners

Dynamic Application Security Testing (DAST) tools are vital for identifying runtime vulnerabilities such as misconfigurations, exposed endpoints, and injection flaws.

## 1. OWASP ZAP (Zed Attack Proxy)
An open-source, powerful intercepting proxy and vulnerability scanner.

### CLI Usage (Docker)
Run a quick baseline scan against a target:
```bash
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://example.com
```
Run a full scan (spiders and attacks):
```bash
docker run -t owasp/zap2docker-stable zap-full-scan.py -t https://example.com
```

## 2. Burp Suite Community Edition
The industry standard for manual web security testing.

### Setup and Basic Usage
1. Download and install from PortSwigger.
2. Launch Burp Suite and open the embedded Chromium browser via the **Proxy > Intercept** tab.
3. Browse your target application; traffic will automatically be routed through Burp.
4. Send requests to the **Repeater** to manually manipulate parameters and observe responses.
5. Use the **Intruder** for fuzzing parameters and brute-forcing (rate-limited in Community Edition).

## 3. Nikto
A comprehensive open-source web server scanner that tests for thousands of dangerous files/programs and outdated software versions.

### CLI Command
```bash
nikto -h http://example.com -Tuning 123
```
*Tuning options let you specify types of tests, such as file upload or misconfigurations.*

## 4. Nmap NSE Scripts
Nmap is famous for port scanning, but its Nmap Scripting Engine (NSE) has powerful HTTP auditing scripts.

### Checking HTTP Headers and Methods
```bash
nmap -p 80,443 --script http-security-headers,http-methods <target>
```

### Enumerating Directories
```bash
nmap -p 80,443 --script http-enum <target>
```
