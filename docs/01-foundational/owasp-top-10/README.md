# OWASP Top 10 Deep Dive

> **Section:** 🏗️ Foundational Security  
> **Level:** Beginner to Intermediate  
> **Time to Complete:** ~90 minutes  
> **Prerequisites:** Basic understanding of Web Applications, HTTP, and any programming language (Python, Node.js, Go, or Java)  
> **Status:** ✅ Complete & Production-Ready

---

## 🎯 Overview & Learning Objectives

The **OWASP Top 10** represents the standard awareness document for developers and web application security. It represents a broad consensus on the most critical security risks facing web applications today.

By the end of this practical guide, you will be able to:
- [x] **Understand** the root causes of each OWASP Top 10 risk category.
- [x] **Identify** vulnerable code patterns in Python, Node.js, Go, and Java.
- [x] **Exploit** vulnerabilities safely in controlled local test environments to verify risk impact.
- [x] **Apply** production-grade fixes and defenses side-by-side.
- [x] **Automate** vulnerability detection using SAST (Semgrep) and DAST (OWASP ZAP) tools.
- [x] **Solve** a hands-on end-to-end Python vulnerability lab.

---

## 📚 Module Navigation

1. **[01. Overview & Threat Landscape](01-introduction.md)** — Introduction to OWASP Top 10 risk methodology, impact scoring, and SAST/DAST integration.
2. **[02. A01: Broken Access Control & IDOR](02-a01-broken-access-control.md)** — Insecure Direct Object References (IDOR), Privilege Escalation, and RBAC/ABAC fixes.
3. **[03. A02: Cryptographic Failures](03-a02-cryptographic-failures.md)** — Sensitive data exposure, password hashing (Argon2/bcrypt), weak ciphers, and secret management.
4. **[04. A03: Injection (SQLi & Command Injection)](04-a03-injection.md)** — SQL Injection, Command Injection, and SSRF (Server-Side Request Forgery) with live exploits and parameterized query fixes.
5. **[05. A04 & A05: Insecure Design & Misconfiguration](05-a04-insecure-design-and-misconfig.md)** — Rate limiting, XML External Entities (XXE), CORS misconfigurations, and default credentials.
6. **[06. Defenses & Secure Coding Cheatsheet](06-defenses-cheatsheet.md)** — Cross-language defense matrix and code review checklists for Python, Node.js, Go, and Java.
7. **[07. Hands-On Vulnerability Lab](07-hands-on-lab.md)** — Complete runnable Python Web App: Vulnerable Code + Exploit Test + Secure Fix.
8. **[08. References & Tooling](08-references.md)** — SAST rules, OWASP ZAP automated scanning scripts, and CVE benchmarks.

---

*Begin reading: [01. Overview & Threat Landscape →](01-introduction.md)*
