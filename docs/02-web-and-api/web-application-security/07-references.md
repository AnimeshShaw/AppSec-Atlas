---
title: 07 - References and Security Resources
description: Comprehensive AppSec Atlas directory of official security standards,
  RFC specifications, real-world CVE case studies, OWASP cheat sheets, and DAST/SAST
  tooling documentation.
keywords:
- AppSec
- OWASP
- WSTG
- OWASP
- ASVS
- NIST
- SP
- 800-53
- CVE
- Case
- Studies
- SSRF
- CVEs
- Log4Shell
- PortSwigger
- Academy
- Security
- Cheat
- Sheets
slug: /web-and-api/web-application-security/references
---


# 07 - References and Security Resources

This directory provides an exhaustive compilation of official security standards, RFC specifications, real-world CVE case studies, OWASP cheat sheets, and tool documentation relevant to web application security engineering.

---

## 1. Official Standards & Security Frameworks

* **OWASP Application Security Verification Standard (ASVS v4.0.3):**
  * Definitive technical requirements for designing, building, and testing secure web applications.
  * [OWASP ASVS Documentation](https://owasp.org/www-project-application-security-verification-standard/)
* **OWASP Web Security Testing Guide (WSTG v4.2):**
  * Premier cybersecurity testing methodology for web applications and APIs.
  * [OWASP WSTG Repository](https://owasp.org/www-project-web-security-testing-guide/)
* **OWASP Top 10 Web Application Security Risks (2021):**
  * Industry benchmark awareness document for developer security priorities.
  * [OWASP Top 10 Official Portal](https://owasp.org/www-project-top-ten/)
* **NIST SP 800-53 Rev 5:**
  * Security and Privacy Controls for Information Systems and Organizations.
  * [NIST Computer Security Resource Center](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

## 2. Technical RFC Specifications & Web Standards

* **RFC 6749 - The OAuth 2.0 Authorization Framework:**
  * [IETF RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
* **RFC 7519 - JSON Web Token (JWT):**
  * [IETF RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
* **RFC 6638 - Cookie Prefixes (`__Host-` and `__Secure-`):**
  * [IETF RFC 6638 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-prefixes-00)
* **W3C Content Security Policy (CSP) Level 3:**
  * [W3C CSP Candidate Recommendation](https://www.w3.org/TR/CSP3/)

---

## 3. Real-World CVE Vulnerability Case Studies

```
+--------------------------------------------------------------------------------------------------+
| CVE IDENTIFIER  | VULNERABILITY TYPE      | AFFECTED SYSTEM      | IMPACT OVERVIEW               |
+-----------------+-------------------------+----------------------+-------------------------------+
| CVE-2021-44228  | Remote Code Execution   | Apache Log4j2        | JNDI / SSRF RCE via Header    |
| CVE-2019-14287  | SSRF / IMDS Exfiltration| AWS Cloud Instances  | Capital One IAM Key Leak      |
| CVE-2022-22965  | Class Loader Binding    | Spring Framework     | DataBinder RCE (Spring4Shell) |
| CVE-2021-22205  | File Upload / ExifTool  | GitLab Enterprise    | Image Upload Polyglot RCE     |
+--------------------------------------------------------------------------------------------------+
```

* **CVE-2021-44228 (Log4Shell):**
  * Analysis of JNDI injection via unsanitized log strings triggering outbound SSRF connections.
  * [NIST NVD - CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
* **Capital One SSRF Incident (2019):**
  * Case study on WAF misconfiguration permitting SSRF calls to AWS IMDSv1 endpoints.
  * [US Department of Justice Case Summary](https://www.justice.gov/usao-wdwa/pr/former-tech-worker-convicted-wire-fraud-and-data-theft)
* **CVE-2022-22965 (Spring4Shell):**
  * RCE in Spring Framework via HTTP request parameter binding to class loader attributes.
  * [Spring Security Advisory](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)
* **CVE-2021-22205 (GitLab ExifTool RCE):**
  * Unrestricted file upload flaw in ExifTool metadata parsing allowing shell code execution via DJVU image payloads.
  * [GitLab Security Release Announcement](https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/)

---

## 4. OWASP Security Cheat Sheets

* **XSS Prevention Cheat Sheet:**
  * [OWASP XSS Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* **CSRF Prevention Cheat Sheet:**
  * [OWASP CSRF Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* **SSRF Prevention Cheat Sheet:**
  * [OWASP SSRF Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* **File Upload Security Cheat Sheet:**
  * [OWASP File Upload Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
* **Session Management Cheat Sheet:**
  * [OWASP Session Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## 5. Tooling & Security Automation Resources

* **OWASP ZAP (Zed Attack Proxy):**
  * [ZAP Official User Guide & Automation Docs](https://www.zaproxy.org/docs/)
* **PortSwigger Burp Suite:**
  * [Burp Suite Documentation & Web Security Academy](https://portswigger.net/burp/documentation)
* **ProjectDiscovery Nuclei:**
  * [Nuclei Engine & Template Reference](https://nuclei.projectdiscovery.io/)
* **Semgrep SAST Engine:**
  * [Semgrep Rule Docs & Registry](https://semgrep.dev/docs/)

---

## 6. Interactive Practice Labs & Vulnerable Apps

* **PortSwigger Web Security Academy:**
  * Free, interactive labs covering modern web exploits.
  * [PortSwigger Academy](https://portswigger.net/web-security)
* **OWASP Juice Shop:**
  * Modern, multi-tier vulnerable web application built on Node.js, Express, and Angular.
  * [OWASP Juice Shop Portal](https://owasp.org/www-project-juice-shop/)
* **OWASP WebGoat:**
  * Deliberately insecure application designed to teach web application security lessons.
  * [OWASP WebGoat GitHub](https://github.com/WebGoat/WebGoat)
