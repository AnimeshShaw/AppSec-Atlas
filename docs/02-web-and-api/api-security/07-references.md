---
title: 07. References & Testing Tools
description: Comprehensive reference directory for API security standards, open-source
  auditing and testing tools, SAST/DAST rulesets, and notable CVE case studies.
keywords:
- AppSec
- API
- Security
- Tools
- Nuclei
- Kiterunner
- Schemathesis
- GraphQLmap
- Semgrep
- OpenAPI
- CVEs
slug: /web-and-api/api-security/references
---


# 07. References & Testing Tools

This chapter provides an organized reference catalog of official security standards, open-source auditing tools, automated SAST/DAST rulesets, and notable CVE case studies for API security engineers and penetration testers.

---

## 1. Official Standards & Technical Specifications

- **[OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/)** — Official OWASP framework categorizing top API security risks.
- **[OpenAPI Specification v3.1.0](https://spec.openapis.org/oas/v3.1.0)** — The standard machine-readable interface description format for RESTful APIs.
- **[NIST SP 800-204: Security Strategies for Microservices Architecture](https://csrc.nist.gov/publications/detail/sp/800-204/final)** — National Institute of Standards and Technology guidance on microservice & API security.
- **[RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)** — IETF standard specification for compact claims representation.
- **[RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)** — Extension to OAuth 2.0 for public clients to prevent code interception.
- **[RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)** — Industry standard protocol for authorization.

---

## 2. API Security Testing & Discovery Toolchain

| Tool | Category | Primary Function & Usage Command |
| :--- | :--- | :--- |
| **[Nuclei](https://github.com/projectdiscovery/nuclei)** | DAST / Vulnerability Scanner | Fast template-based vulnerability scanner for API misconfigurations & CVEs.<br/>`nuclei -u https://api.target.local -t http/vulnerabilities/` |
| **[Kiterunner](https://github.com/assetnote/kiterunner)** | API Discovery | Context-aware API route and parameter discovery engine.<br/>`kr scan https://api.target.local -w routes-large.kite` |
| **[Schemathesis](https://github.com/schemathesis/schemathesis)** | Property-Based Contract Testing | Property-based API testing tool that reads OpenAPI specs to generate malformed payloads.<br/>`schemathesis run https://api.target.local/openapi.json` |
| **[GraphQLmap](https://github.com/swisskyrepo/GraphQLmap)** | GraphQL Audit | CLI engine for auditing and exploiting GraphQL endpoints.<br/>`python graphqlmap.py -u https://target.local/graphql` |
| **[Astra](https://github.com/flipkart/astra)** | Automated API Scanner | Automated security testing framework for REST APIs integrated into CI/CD pipelines. |
| **[OWASP ZAP API Scan](https://www.zaproxy.org/)** | DAST Scanner | Dynamic scanner configured for OpenAPI/GraphQL endpoints.<br/>`zap-api-scan.py -t https://api.target.local/openapi.json -f openapi` |
| **[Spectral](https://github.com/stoplightio/spectral)** | OpenAPI Linter | Static linter for OpenAPI/AsyncAPI specifications enforcing security rules. |

---

## 3. Automated SAST Rulesets (Semgrep Rules)

Static Application Security Testing (SAST) rules can catch BOLA, BFLA, and Mass Assignment flaws during code review.

### Semgrep Rule: BOLA Detection (Missing User Filter in Query)
```yaml
rules:
  - id: python-flask-possible-bola
    patterns:
      - pattern: `$MODEL.query.get($`ID)
      - pattern-not-inside: |
          $MODEL.query.filter_by(..., user_id=..., ...)
    message: "Potential BOLA: Database object fetched using raw ID parameter without explicit user_id filter."
    severity: WARNING
    languages: [python]
```

### Semgrep Rule: JWT `alg: none` or Missing Algorithm Enforcement
```yaml
rules:
  - id: nodejs-jwt-missing-algorithm-restriction
    patterns:
      - pattern: jwt.verify(`$TOKEN, $`SECRET)
      - pattern-not: jwt.verify(`$TOKEN, $`SECRET, { algorithms: [...] })
    message: "JWT verification lacks explicit algorithm allowlist, making it vulnerable to alg:none or HS256/RS256 key confusion."
    severity: ERROR
    languages: [javascript, typescript]
```

---

## 4. Notable Real-World API CVE Case Studies

### CVE-2022-22965 (Spring4Shell)
- **Vulnerability Class**: Mass Assignment / Data Binding RCE (OWASP API3:2023).
- **Mechanism**: Spring Framework's data binder allowed HTTP parameters to bind to class properties (`class.module.classLoader...`). Attackers manipulated the Tomcat logging properties via parameter binding to write an arbitrary JSP web shell to disk.
- **Remediation**: Allowlisting allowed properties or upgrading Spring Framework.

### CVE-2023-30845 (Apollo Server DoS)
- **Vulnerability Class**: Unrestricted Resource Consumption (OWASP API4:2023).
- **Mechanism**: Apollo Server versions prior to v4.7.1 allowed memory exhaustion when parsing recursive inline fragments in GraphQL queries.
- **Remediation**: Upgrade Apollo Server and enforce `MaxTokensLimiter` / `graphql-depth-limit`.

### CVE-2023-44487 (HTTP/2 Rapid Reset)
- **Vulnerability Class**: Infrastructure DoS affecting gRPC / HTTP/2 servers.
- **Mechanism**: Adversaries abused HTTP/2 multiplexing by generating opening streams (`HEADERS`) and instantly canceling them (`RST_STREAM`) in rapid bursts, causing high CPU allocation on gRPC reverse proxies.
- **Remediation**: Configure `MAX_CONCURRENT_STREAMS` and apply patch updates to Envoy, Nginx, and gRPC runtimes.

---

*Return to [Module Overview & Index →](README.md)*
