---
title: 05. GraphQL Security Tools & Automation
description: 'Hands-on guide to GraphQL security auditing tools: InQL, Clairvoyance,
  GraphQL-Cop, Graphw0of, Burp Suite Extensions, and custom Semgrep SAST rules.'
keywords:
- GraphQL
- Tools
- InQL
- Clairvoyance
- GraphQL-Cop
- Graphw0of
- Semgrep
- DAST
- SAST
slug: /web-and-api/graphql-security/tools
---


# 05. GraphQL Security Tools & Automation

Security engineers must possess a robust toolkit for fingerprinting, auditing, exploiting, and statically analyzing GraphQL applications. This chapter provides concrete installation commands, CLI syntax, custom SAST rules, and CI/CD integration pipelines.

---

## 1. Fingerprinting & Schema Reconstruction Tools

### A. Graphw0of (GraphQL Engine Fingerprinting)
**Graphw0of** identifies the underlying GraphQL engine/framework powering an endpoint (e.g., Apollo Server, Hasura, Sangria, Graphene, Ruby GraphQL) by detecting subtle variations in error message formatting, engine response structures, and directive handling.

```bash
# Installation
git clone https://github.com/dolevf/graphw00f
cd graphw0of

# Execution Syntax
python3 graphw0of.py -u https://api.target.com/graphql

# Sample Output:
# [*] Checking introspection...
# [*] Introspection enabled!
# [*] Fingerprinting GraphQL engine...
# [+] Found engine: Apollo Server (Confidence: 98%)
```

### B. Clairvoyance (Schema Reconstruction via Field Suggestions)
When introspection is disabled, **Clairvoyance** uses fuzzy field suggestion error harvesting (`"Did you mean ...?"`) to reconstruct the full schema graph automatically.

```bash
# Installation
pip install clairvoyance

# Execution Syntax
clairvoyance https://api.target.com/graphql \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/graphql-keys.txt \
  -o reconstructed_schema.json

# View reconstructed schema SDL
cat reconstructed_schema.json
```

---

## 2. DAST Security Scanners & Exploitation Utilities

### A. GraphQL-Cop (Lightweight Security Auditor)
**GraphQL-Cop** is a Python-based utility that audits an endpoint for standard security misconfigurations: Introspection, Field Suggestions, Batching, Trace mode, GET mutations, and CSRF header enforcement.

```bash
# Installation
git clone https://github.com/dolevf/graphql-cop
cd graphql-cop
pip install -r requirements.txt

# Execution Syntax
python3 graphql-cop.py -t https://api.target.com/graphql

# Sample Audit Summary Output:
# [HIGH] Introspection is enabled on production endpoint!
# [HIGH] Alias batching allowed (Tested 50 aliases, response time 42ms).
# [MEDIUM] Field suggestions enabled (Information disclosure risk).
# [LOW] GET method accepted for GraphQL Mutations (CSRF risk).
```

### B. InQL (Burp Suite Extension & CLI)
**InQL** is an enterprise-grade extension for Burp Suite (and standalone CLI) developed by NCC Group. It parses introspection responses, generates standard query templates for every available query/mutation, and identifies authorization bypasses.

```bash
# CLI Installation
pip install inql

# Generate formatted HTML documentation & operational query templates
inql -t https://api.target.com/graphql -o ./inql_report/
```

```
inql_report/
├── index.html                  # Browsable Interactive Schema Docs
├── queries/
│   ├── User_getUser.query      # Generated Query Template
│   └── Order_listOrders.query  # Generated Query Template
└── mutations/
    └── User_deleteUser.mutation
```

---

## 3. SAST: Custom Semgrep Rules for GraphQL

Automate static analysis in your codebase using custom **Semgrep** rules tailored for GraphQL backend vulnerabilities.

### Rule 1: Introspection Enabled in Production (Node.js - Apollo Server)

```yaml
rules:
  - id: apollo-introspection-enabled-in-production
    languages: [javascript, typescript]
    severity: ERROR
    message: |
      Apollo Server introspection is explicitly enabled without checking the production environment.
      Introspection leaks full schema definitions to untrusted callers.
    pattern-either:
      - pattern: |
          new ApolloServer({
            ...,
            introspection: true,
            ...
          })
    metadata:
      cwe: "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
      owasp: "API8:2023 Security Misconfiguration"
```

### Rule 2: Missing Depth Limit Rules (Node.js)

```yaml
rules:
  - id: apollo-missing-depth-limit
    languages: [javascript, typescript]
    severity: WARNING
    message: |
      Apollo Server instantiated without 'graphql-depth-limit' in validationRules.
      This endpoint may be vulnerable to Denial of Service (DoS) via recursive nested queries.
    pattern: |
      new ApolloServer({
        ...,
        resolvers: $R
        ...
      })
    pattern-not-inside: |
      new ApolloServer({
        ...,
        validationRules: [..., depthLimit(...), ...],
        ...
      })
    metadata:
      cwe: "CWE-400: Uncontrolled Resource Consumption"
      owasp: "API4:2023 Unrestricted Resource Consumption"
```

### Rule 3: Strawberry Python Schema Missing Auth Extension

```yaml
rules:
  - id: strawberry-missing-auth-extension
    languages: [python]
    severity: WARNING
    message: |
      Strawberry GraphQL router created without security extensions or custom permission classes.
    pattern: |
      strawberry.Schema(query=`$Q, mutation=$`M)
    metadata:
      cwe: "CWE-285: Improper Authorization"
      owasp: "API1:2023 Broken Object Level Authorization"
```

---

## 4. Automated CI/CD Pipeline Integration

Integrate GraphQL static and dynamic security checks into **GitHub Actions**:

```yaml
# .github/workflows/graphql-security-ci.yml
name: GraphQL Security Audit Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sast-scan:
    name: Semgrep Static Security Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Run Semgrep SAST Rules
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/ci p/security-audit

  dast-scan:
    name: GraphQL DAST Automated Audit
    runs-on: ubuntu-latest
    needs: sast-scan
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python 3.10
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"

      - name: Launch Test Server Container
        run: |
          docker-compose -f docker-compose.test.yml up -d
          sleep 5 # Wait for server startup

      - name: Execute GraphQL-Cop Auditor
        run: |
          git clone https://github.com/dolevf/graphql-cop.py
          cd graphql-cop.py
          pip install -r requirements.txt
          python3 graphql-cop.py -t http://localhost:4000/graphql -f json -o cop-report.json

      - name: Upload Security Audit Report
        uses: actions/upload-artifact@v3
        with:
          name: graphql-security-report
          path: cop-report.json
```

---

*Next Chapter: [06. Hands-on Security Lab →](06-labs.md)*
