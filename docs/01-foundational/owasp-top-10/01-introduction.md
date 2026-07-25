# 01. Overview & Threat Landscape

The Open Web Application Security Project (OWASP) Top 10 is the globally recognized standard awareness document for developers and application security engineers.

---

## 1. The OWASP Top 10 Risk Matrix

OWASP evaluates web security risks based on three main factors:
1. **Likelihood of Exploit**: How easy is it for an attacker to discover and exploit the flaw?
2. **Impact**: How severe is the business damage if exploited (data breach, system takeover)?
3. **Prevalence**: How frequently is this flaw detected across millions of audited applications?

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        OWASP Top 10 Summary                             │
├───────┬──────────────────────────────────┬──────────────────────────────┤
│ Rank  │ Category                         │ Primary Root Cause           │
├───────┼──────────────────────────────────┼──────────────────────────────┤
│ A01   │ Broken Access Control            │ Missing authorization checks │
│ A02   │ Cryptographic Failures           │ Weak algorithms / plaintext  │
│ A03   │ Injection                        │ Mixing code and untrusted data│
│ A04   │ Insecure Design                  │ Architectural security gaps  │
│ A05   │ Security Misconfiguration        │ Defaults, verbose errors     │
│ A06   │ Vulnerable & Outdated Components │ Unpatched third-party libs   │
│ A07   │ Identification & Auth Failures   │ Weak sessions / passwords    │
│ A08   │ Software & Data Integrity Failures│ Unsigned updates / CI pipelines│
│ A09   │ Security Logging & Monitoring    │ Missing audit logs / alerts  │
│ A10   │ Server-Side Request Forgery      │ Untrusted URL fetching       │
└───────┴──────────────────────────────────┴──────────────────────────────┘
```

---

## 2. Why Vulnerabilities Occur: The Core Root Causes

Almost all web application security flaws stem from one of three fundamental mistakes:

### A. Implicit Trust in User Input
Assuming data sent from client devices (HTTP headers, query parameters, cookies, request bodies) is valid or safe.

### B. Lack of Server-Side Enforcement
Relying on client-side controls (UI button hiding, JavaScript validation) without validating permissions on the server.

### C. Insecure Defaults & Configuration
Deploying default credentials, verbose debug stack traces in production, or unencrypted data channels.

---

## 3. Shift-Left Security: SAST & DAST

To catch OWASP Top 10 vulnerabilities early in the software development lifecycle:

```
[ Code Commit ] ──► [ SAST: Semgrep / CodeQL ] ──► [ SCA: Dependency-Check ]
                                                            │
[ Staging Deploy ] ◄────────────────────────────────────────┘
        │
        ▼
[ DAST: OWASP ZAP Automated Scan ] ──► [ Production Deployment ]
```

- **SAST (Static Application Security Testing)**: Scans source code for vulnerable function calls without running the app (e.g., Semgrep, SonarQube).
- **DAST (Dynamic Application Security Testing)**: Tests running applications from the outside by sending exploit payloads (e.g., OWASP ZAP, Burp Suite).
- **SCA (Software Composition Analysis)**: Scans third-party dependencies (`package.json`, `requirements.txt`, `pom.xml`) for known CVEs.

---

*Next Chapter: [02. A01: Broken Access Control & IDOR →](02-a01-broken-access-control.md)*
