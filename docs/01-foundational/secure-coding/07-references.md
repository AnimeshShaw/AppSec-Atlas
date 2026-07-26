---
title: 'Chapter 7: References & Standards'
description: 'Comprehensive AppSec reference directory: CVE breakdowns, CWE Top 25
  mappings, OWASP ASVS v4.0 standards, NIST SSDF guidelines, and security library
  documentation.'
keywords:
- AppSec
- CVE
- Breakdown
- CWE
- Top
- '25'
- OWASP
- ASVS
- NIST
- SSDF
- SEI
- CERT
- Security
- References
slug: /foundational/secure-coding/references
---


# Chapter 7: References & Standards

## Real-World CVE Breakdown

Examining historical security advisories provides crucial context on how secure coding failures impact enterprise production environments.

| CVE ID | Vulnerability Class | Affected Component | Root Cause | Secure Coding Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2021-44228** | JNDI Remote Code Execution | Apache Log4j2 | Untrusted input logged in string format was evaluated as executable lookup expressions. | Treat log strings strictly as static data; disable remote lookup parsers. |
| **CVE-2021-41773** | Path Traversal & RCE | Apache HTTP Server 2.4.49 | Alias mapping failed to normalize path segment double dots (`.%2e/`). | Perform canonical path resolution (`abspath`) before boundary validation. |
| **CVE-2018-1271** | Directory Traversal | Spring Framework | Resource handler parsed un-normalized Windows/POSIX path separators (`..\`). | Validate absolute canonical containment (`Path.normalize().startsWith`). |
| **CVE-2022-22965** | ClassLoader Data Binding | Spring Framework | Unbounded HTTP request payload property binding enabled ClassLoader manipulation. | Enforce strict schema allowlists for HTTP request body properties. |
| **CVE-2020-11022** | Cross-Site Scripting (XSS) | jQuery (< 3.5.0) | Passing HTML strings containing `<option>` elements to `.html()` caused mXSS mutation. | Use safe context-aware DOM sanitizers (DOMPurify) instead of regex parsing. |

---

## CWE Top 25 & OWASP ASVS Mapping

| CWE ID | Vulnerability Name | OWASP 2021 Category | ASVS v4.0 Requirement |
| :--- | :--- | :--- | :--- |
| **CWE-20** | Improper Input Validation | A03:2021 - Injection | V5.1.1 - Verify that input data is validated using allowlists. |
| **CWE-22** | Path Traversal (Improper Limitation of a Pathname) | A01:2021 - Broken Access Control | V12.3.1 - Verify that path traversal controls block unauthorized file access. |
| **CWE-79** | Cross-Site Scripting (Improper Output Neutralization) | A03:2021 - Injection | V5.3.1 - Verify that context-aware output encoding is applied to user data. |
| **CWE-89** | SQL Injection | A03:2021 - Injection | V5.3.4 - Verify that database access uses parameterized interfaces. |
| **CWE-116** | Improper Encoding or Escaping of Output | A03:2021 - Injection | V5.3.2 - Verify that encoding libraries handle all special characters. |
| **CWE-434** | Unrestricted File Upload of Dangerous Type | A08:2021 - Software & Data Integrity | V12.1.1 - Verify that file uploads are validated via binary signature (magic bytes). |

---

## Industry Standards & Frameworks

### 1. OWASP Standards
* **[OWASP Secure Coding Practices Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)**: High-level technology-agnostic security checklist for developers.
* **[OWASP Application Security Verification Standard (ASVS v4.0.3)](https://owasp.org/www-project-application-security-verification-standard/)**: Technical security requirements framework for designing, building, and testing secure web applications.
* **[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)**: Tactical implementation advice for Input Validation, XSS Prevention, and File Uploads.

### 2. NIST & Enterprise Benchmarks
* **[NIST SP 800-218 (Secure Software Development Framework - SSDF v1.1)](https://csrc.nist.gov/Projects/ssdf)**: Federal standards for integrating security tasks into software development lifecycles.
* **[SEI CERT Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode/SEI+CERT+Coding+Standards)**: Rule sets for secure software development in C, C++, Java, and Perl.
* **[CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)**: Annual community-curated list of common software vulnerabilities.

---

## Tooling, Libraries & Documentation

### Security Testing & Analysis
* **[Semgrep Rule Registry](https://semgrep.dev/explore)**: Explore production static analysis rules for Python, JS/TS, Go, Java, and Docker.
* **[Helmet JS](https://helmetjs.github.io/)**: Express middleware for hardening HTTP security headers.
* **[DOMPurify GitHub](https://github.com/cure53/DOMPurify)**: Ultra-fast HTML/SVG XSS sanitizer for Node.js and browser environments.

### Schema Validation & Encoding Libraries
* **[Pydantic v2 Documentation](https://docs.pydantic.dev/latest/)**: Fast data validation using Python type hints.
* **[Zod Documentation](https://zod.dev/)**: TypeScript-first schema validation with type inference.
* **[Go Playground Validator](https://github.com/go-playground/validator)**: Go struct and field validation using tags.
* **[OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)**: High-performance Java context-aware output encoding library.
* **[nh3 Python Sanitizer](https://github.com/messense/nh3)**: Fast Python binding for Rust's Ammonia HTML sanitizer.

---

> [!NOTE]
> Keep your security baseline aligned with OWASP ASVS Level 2 for enterprise web applications, and mandate automated SAST scanning in all CI/CD deployment pipelines.
