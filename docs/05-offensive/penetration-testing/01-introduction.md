---
title: 01. Overview & PTES / OWASP WSTG Standards
description: Professional penetration testing follows structured methodology frameworks
  to ensure thorough coverage and legal compliance.
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '05'
- Offensive
- Penetration
- Testing
- '01'
- Introduction
- Md
slug: /offensive/penetration-testing/introduction
---


# 01. Overview & PTES / OWASP WSTG Standards

Professional penetration testing follows structured methodology frameworks to ensure thorough coverage and legal compliance.

---

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## 1. The PTES Framework Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              Penetration Testing Execution Standard (PTES)                  │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ 1. Scoping      │ Define IP ranges, domains, out-of-scope targets, RoE      │
│ 2. Intelligence │ Passive & Active OSINT reconnaissance                     │
│ 3. Threat Model │ Identify primary target assets and data flow              │
│ 4. Vuln Audit   │ Scan and manually verify configuration weaknesses         │
│ 5. Verification │ Confirm vulnerability impact safely without data damage   │
│ 6. Reporting    │ Document findings with CVSS v4.0 scores & remediation     │
└─────────────────┴───────────────────────────────────────────────────────────┘
```

---

## 2. Scoping & Legal Rules of Engagement (RoE)

Before initiating any audit activity, security assessors MUST obtain a signed **Permission to Test / Rules of Engagement** document:

### Essential RoE Elements:
- **Written Authorization**: Signed by authorized corporate executive.
- **Target In-Scope List**: Explicit list of IP addresses, FQDNs, and API endpoints.
- **Out-of-Scope Explicit Exclusions**: Production payment gateways, third-party SaaS vendors.
- **Testing Windows**: Approved time windows for scanning (e.g., off-peak hours).

---

*Next Chapter: [02. Reconnaissance & Target Mapping →](02-reconnaissance-and-enumeration.md)*
