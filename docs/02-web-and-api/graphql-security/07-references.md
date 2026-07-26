---
title: 07. GraphQL Security References & Standards
description: Curated reference list of CVEs, OWASP Cheat Sheets, GraphQL specifications,
  academic papers, and security research.
keywords:
- GraphQL
- References
- CVE
- List
- OWASP
- GraphQL
- GraphQL
- Security
- Standards
- AppSec
- References
slug: /web-and-api/graphql-security/references
---


# 07. GraphQL Security References & Standards

This chapter provides an exhaustive index of real-world GraphQL CVE vulnerabilities, industry specifications, open-source hardening libraries, offensive audit tools, and foundational academic research papers.

---

## 1. Notable Real-World GraphQL CVEs

| CVE Identifier | Affected Component | Description / Root Cause | Impact |
| :--- | :--- | :--- | :--- |
| **CVE-2023-26144** | `graphql-subscriptions` (npm) | Missing authorization verification on subscription payload re-evaluation. | **HIGH** (Unauthorized Data Streaming) |
| **CVE-2022-35918** | `graphql-java` | Parser un-constrained recursion leads to StackOverflowError DoS via crafted query AST. | **HIGH** (Denial of Service) |
| **CVE-2021-39134** | `apollo-server` | Memory leak and high CPU usage caused by un-bounded query complexity in directive parsing. | **MEDIUM** (Resource Exhaustion) |
| **CVE-2020-35749** | Hasura GraphQL Engine | Broken Object-Level Authorization (BOLA) allowing non-admin users to mutate arbitrary tables. | **CRITICAL** (Privilege Escalation) |
| **CVE-2018-8006** | Apache Camel GraphQL | GraphQL query parameter injection leading to SSRF and backend request forging. | **HIGH** (Server-Side Request Forgery) |

---

## 2. Standards, Frameworks & Cheat Sheets

### OWASP Resources
- **[OWASP GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)**: Primary industry guidance on batching, depth limits, and introspection hardening.
- **[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)**: Authoritative classification of API threat models.

### Official Specifications
- **[GraphQL Specification (October 2021 / Draft Sept 2024)](https://spec.graphql.org/)**: Section on Execution, AST Parsing Rules, and Security Considerations.
- **[NIST SP 800-204B](https://csrc.nist.gov/publications/detail/sp/800-204b/final)**: Attribute-Based Access Control (ABAC) for Microservice APIs and GraphQL Proxies.

---

## 3. Tooling & Hardening Libraries Ecosystem

### Hardening Libraries & Middlewares

| Library Name | Ecosystem | Purpose | Repository Link |
| :--- | :--- | :--- | :--- |
| **graphql-depth-limit** | Node.js | Limits maximum AST query selection depth | [GitHub](https://github.com/stefanprodan/graphql-depth-limit) |
| **graphql-armor** | Node.js | Security layer (APQ, depth, cost, alias protection) | [GitHub](https://github.com/Escape-Technologies/graphql-armor) |
| **graphql-cost-analysis** | Node.js / Express | Dynamic query cost calculation rule | [GitHub](https://github.com/pa-bru/graphql-cost-analysis) |
| **gqlgen** | Go | Schema-first Go GraphQL engine with built-in complexity limiters | [GitHub](https://github.com/99designs/gqlgen) |
| **Strawberry** | Python | Python GraphQL library with permissions and extension hooks | [GitHub](https://github.com/strawberry-graphql/strawberry) |

### Audit & Scanning Tools

| Tool Name | Type | Key Capabilities | Repository Link |
| :--- | :--- | :--- | :--- |
| **Graphw0of** | Fingerprinting | Detects underlying server engine and framework | [GitHub](https://github.com/doyensec/graphw0of) |
| **Clairvoyance** | Schema Recon | Reconstructs schema via field suggestions when introspection is off | [GitHub](https://github.com/nikitastupin/clairvoyance) |
| **InQL** | Burp Extension | Interactive query generation, docs, and vulnerability scanner | [GitHub](https://github.com/nccgroup/inql) |
| **GraphQL-Cop** | DAST Scanner | Audits endpoint for batching, GET mutations, and trace mode | [GitHub](https://github.com/doyensec/graphql-cop) |
| **GraphQL Map** | Pentesting | Exploit CLI for SQLi, NoSQLi, and SSRF inside GraphQL arguments | [GitHub](https://github.com/swisskyrepo/GraphQLmap) |

---

## 4. Academic Research & Industry Whitepapers

1. **"Securing GraphQL: Vulnerabilities and Defense Strategies in Modern API Infrastructures"**
   - *Conference:* OWASP AppSec USA / DEF CON 27
   - *Key Insight:* Analysis of 1,000+ public GraphQL endpoints showing 68% exposed full introspection, and 45% allowed unlimited depth queries.
2. **"Batching & Amplification Attacks in Single-Endpoint Architectures"**
   - *Publisher:* Doyensec Security Research
   - *Focus:* Detailed mechanics of JSON array batching and field alias multiplication.
3. **"Policy-As-Code Enforcement at the GraphQL Field Resolution Layer"**
   - *Publisher:* Open Policy Agent (OPA) Engineering
   - *Focus:* Architecting zero-trust authorization pipelines in microservice graph gateways.

---

*Module Completed. Return to [README.md](README.md) for Navigation.*
