---
title: "02 - Security in CI/CD Pipelines"
description: "Comprehensive guide and best practices for 02 - Security in CI/CD Pipelines in the devsecops-handbook section of AppSec Atlas. Learn how to secure your infrastr"
keywords: ['devsecops-handbook', '02---security-in-ci/cd-pipelines', 'appsec', 'security', 'compliance']
---
# 02 - Security in CI/CD Pipelines

A mature DevSecOps pipeline automates various security checks. This chapter covers the core scanners and provides a complete GitHub Actions example.

## Core Pipeline Integrations

### 1. Secret Scanning (e.g., TruffleHog, Gitleaks)
**Goal:** Prevent hardcoded passwords, API keys, and tokens from entering the codebase.
- **When to run:** Pre-commit hooks (locally) and on every Push/PR.
- **Action:** Break the build immediately if a secret is found.

### 2. Static Application Security Testing (SAST) (e.g., Semgrep, CodeQL)
**Goal:** Analyze source code for security vulnerabilities (e.g., SQLi, XSS) without executing it.
- **When to run:** On Pull Requests.
- **Action:** Comment on the PR with findings. Break the build for High/Critical issues.

### 3. Software Composition Analysis (SCA) (e.g., Trivy, Snyk, Dependabot)
**Goal:** Detect known vulnerabilities (CVEs) in third-party open-source dependencies and container images.
- **When to run:** On Pull Requests and daily on the default branch.
- **Action:** Generate a Software Bill of Materials (SBOM) and block builds introducing new Critical CVEs.

### 4. Dynamic Application Security Testing (DAST) (e.g., OWASP ZAP, Nuclei)
**Goal:** Interact with a running application from the outside to find runtime vulnerabilities (e.g., misconfigurations, authentication bypass).
- **When to run:** After deployment to a staging or QA environment.
- **Action:** Alert the security team; rarely breaks the build automatically due to longer run times and potential false positives.

---

## 💻 GitHub Actions DevSecOps Pipeline Example

Below is a production-ready GitHub Actions workflow (`.github/workflows/devsecops.yml`) that integrates Secret Scanning, SAST, and SCA for a Dockerized Node.js application.

```yaml
name: DevSecOps Pipeline

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  secret-scanning:
    name: Secret Scanning (TruffleHog)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # TruffleHog needs history
      
      - name: Run TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --only-verified

  sast-semgrep:
    name: SAST (Semgrep)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        
      - name: Run Semgrep CI
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/default"
          generateSarif: "1"
          
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep.sarif

  sca-container-scan:
    name: SCA & Container Scan (Trivy)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        
      - name: Build Docker Image
        run: docker build -t my-app:${{ github.sha }} .
        
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-app:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
```


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
