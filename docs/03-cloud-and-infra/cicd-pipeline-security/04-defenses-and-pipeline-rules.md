---
title: "04. Pipeline Security Gates & Branch Protection"
description: "Enforcing automated security gates inside your CI/CD pipeline ensures vulnerable code is blocked before reaching the `main` branch or production."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Cicd Pipeline Security", "04 Defenses And Pipeline Rules.Md"]
---

# 04. Pipeline Security Gates & Branch Protection

Enforcing automated security gates inside your CI/CD pipeline ensures vulnerable code is blocked before reaching the `main` branch or production.

---

## 1. Complete CI/CD Security Pipeline Template

```yaml
# .github/workflows/security-gate.yml
name: Security Pipeline Gate

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  secret-scan:
    name: Secret Leak Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: TruffleHog Secret Scan
        uses: trufflesecurity/trufflehog-actions-scan@v3.0.0

  sast-scan:
    name: SAST Code Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep SAST Scan
        uses: semgrep/actions@v1
        with:
          config: p/default

  dependency-scan:
    name: SCA Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy Vulnerability Scanner
        uses: aquasecurity/trivy-action@v0.20.0
        with:
          scan-type: 'fs'
          security-checks: 'vuln,config'
          exit-code: '1' # Fail pipeline if HIGH/CRITICAL vulnerabilities exist
```

---

## 2. GitHub Branch Protection & CODEOWNERS Setup

Create a `.github/CODEOWNERS` file to mandate security team review for sensitive infrastructure and pipeline configuration files:

```text
# .github/CODEOWNERS
# Require Security Team approval for CI workflows
.github/workflows/   @AnimeshShaw @techcorp-security-team
Dockerfile           @AnimeshShaw @techcorp-security-team
Terraform/           @techcorp-cloud-team
```

---

*Next Chapter: [05. Hands-On Vulnerability Lab →](05-hands-on-lab.md)*
