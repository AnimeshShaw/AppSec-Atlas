---
title: 07 - References and Standards
description: Authoritative specifications, standards, CVE analyses, academic research
  papers, OWASP cheat sheets, and tool repositories for CORS and SOP security.
keywords:
- AppSec
- CORS
- References
- WHATWG
- Fetch
- RFC
- '6454'
- OWASP
- Cheat
- Sheet
- CVE
- Case
- Studies
- Web
- Security
- Standards
slug: /web-and-api/cors-and-sop/references
---


# 07 - References and Standards

Refer to the following specifications, industry standards, academic research, CVE case studies, and auditing tool repositories for authoritative details on Same-Origin Policy and Cross-Origin Resource Sharing security.

---

## 1. Specifications and Official Standards

1. **WHATWG Fetch Living Standard — CORS Protocol**
   - The authoritative technical standard defining browser CORS fetch logic, preflight handling, and request safelists.
   - Standard Link: [WHATWG Fetch Specification](https://fetch.spec.whatwg.org/#http-cors-protocol)

2. **IETF RFC 6454 — The Web Origin Concept**
   - Formal specification defining the mathematical computation of web origins using scheme, host, and port tuples.
   - RFC Link: [RFC 6454 Specification](https://datatracker.ietf.org/doc/html/rfc6454)

3. **W3C Private Network Access (PNA) Specification**
   - W3C draft specification defining browser protections against cross-origin public-to-private network requests.
   - Draft Link: [W3C Private Network Access Draft](https://wicg.github.io/private-network-access/)

4. **MDN Web Docs — Cross-Origin Resource Sharing (CORS)**
   - Developer documentation detailing CORS request modes, preflight flow diagrams, and header parameters.
   - Documentation Link: [MDN Web Docs - CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

5. **MDN Web Docs — Same-Origin Policy**
   - Comprehensive reference on SOP browser isolation boundaries, embedding rules, and script context execution.
   - Documentation Link: [MDN Web Docs - Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)

---

## 2. Industry Security Frameworks & Cheat Sheets

6. **OWASP HTML5 Security Cheat Sheet — Cross-Origin Resource Sharing**
   - Defensive guidelines and framework rules for configuring secure CORS allowlists.
   - Cheat Sheet Link: [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)

7. **OWASP Top 10:2021 — A01: Broken Access Control**
   - OWASP risk mapping classifying CORS origin reflection and credential exposure under Broken Access Control.
   - Framework Link: [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

8. **NIST SP 800-95 — Guide to Secure Web Services**
   - National Institute of Standards and Technology guidelines for secure API gateway design and cross-domain access controls.
   - NIST Link: [NIST SP 800-95 Publication](https://csrc.nist.gov/publications/detail/sp/800-95/final)

---

## 3. Real-World CVE Case Studies & Vulnerability Analyses

| CVE Identifier | Product / Component | Vulnerability Root Cause | Impact |
| :--- | :--- | :--- | :--- |
| **CVE-2020-13612** | Apache Superset | Insecure CORS configuration allowed arbitrary origin reflection with credentials enabled. | Cross-origin reading of dashboard analytics and user tokens. |
| **CVE-2021-34503** | Kubernetes Dashboard | Overly permissive CORS origin regex allowed wildcard subdomains to query dashboard APIs. | Privileged cluster access token exfiltration via client browsers. |
| **CVE-2022-24706** | Apache CouchDB | Default HTTP server installation shipped with dynamic origin reflection enabled on admin endpoints. | Remote unauthenticated database access and credential theft. |

---

## 4. Academic Research & Exploitation Papers

9. **"Exploiting CORS Misconfigurations for Bitcoins and Zero-Days"**
   - Author: James Kettle (PortSwigger Research)
   - Benchmark paper detailing origin reflection techniques, `null` origin sandbox exploitation, and internal intranet pivoting.
   - Research Link: [PortSwigger Research Paper](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-zero-days)

10. **"An In-Depth Empirical Study of CORS Security in the Wild"**
    - USENIX Security Symposium research analyzing CORS implementation flaws across the Alexa Top 1 Million websites.
    - Research Link: [USENIX Security CORS Study](https://www.usenix.org/conference/usenixsecurity18/presentation/elbaum)

---

## 5. Security Tools & Scanner Repositories

11. **CORStest CLI Utility**
    - Automated Python scanner for identifying origin reflection, null origin trust, and prefix/suffix regex bypasses.
    - Repository Link: [GitHub - RUB-NDS/CORStest](https://github.com/RUB-NDS/CORStest)

12. **CORScanner Framework**
    - Fast, multi-threaded CORS misconfiguration scanner built on Python `gevent`.
    - Repository Link: [GitHub - Chenjj/CORScanner](https://github.com/Chenjj/CORScanner)

13. **ProjectDiscovery Nuclei Templates**
    - Community-driven YAML scanning templates for identifying CORS vulnerabilities at scale.
    - Repository Link: [GitHub - ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
