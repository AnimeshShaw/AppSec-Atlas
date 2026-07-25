# 02. Reconnaissance & Target Mapping

Reconnaissance is the initial phase of mapping an organization's external attack surface.

---

## 1. Sub-Domain Discovery (Amass & Subfinder)

```bash
# Subfinder for fast passive subdomain enumeration
subfinder -d techcorp.com -o subdomains.txt

# OWASP Amass for comprehensive active and passive mapping
amass enum -d techcorp.com -o amass_results.txt
```

---

## 2. Nmap Port Scanning & Service Fingerprinting

```bash
# Fast SYN scan of top 1000 ports with service version detection
nmap -sS -sV -T4 target.techcorp.com -oA nmap_fast_scan

# Comprehensive script scan on open ports
nmap -sC -sV -p 80,443,8080,8443 target.techcorp.com -oA nmap_detailed
```

---

*Next Chapter: [03. Vulnerability Audit & Scanning Methodology →](03-vulnerability-assessment-and-exploitation.md)*
