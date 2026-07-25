---
title: "02. GitHub Actions Security Hardening"
description: "GitHub Actions is the most popular CI/CD engine for open-source and commercial software. Misconfigurations in GitHub Actions workflows can lead to sec..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Cicd Pipeline Security", "02 Github Actions Hardening.Md"]
---

# 02. GitHub Actions Security Hardening

GitHub Actions is the most popular CI/CD engine for open-source and commercial software. Misconfigurations in GitHub Actions workflows can lead to secret theft, repository takeover, and supply chain poisoning.

---

## 1. Vulnerability 1: The `pull_request_target` Trap

The `pull_request_target` event triggers a workflow in the context of the **base repository**, granting access to repository secrets and write permissions even when triggered by a fork PR!

### ❌ Vulnerable Workflow (`.github/workflows/label_pr.yml`)
```yaml
# VULNERABLE: Checkout code from the fork PR and run it under pull_request_target!
name: PR Auto Labeler
on:
  pull_request_target: # Has access to repo SECRETS and write token!

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }} # Danger: Checking out untrusted code!
      - name: Run Build Test
        run: |
          npm install # Attacker's package.json postinstall script runs with WRITE permissions & SECRETS!
```

### ✅ Secure Workflow Pattern
```yaml
# SECURE: Use standard 'pull_request' trigger (Runs with READ-ONLY token, NO secrets)
name: PR Auto Labeler
on:
  pull_request: # Safe: Fork PRs cannot read repository SECRETS

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Tests
        run: npm test
```

---

## 2. Vulnerability 2: Unpinned Actions (Tag Spoofing)

Referencing third-party Actions by mutable version tags (e.g., `uses: actions/checkout@v4` or `uses: thirdparty/action@v1`) allows an attacker who compromises the third-party repo to overwrite tag `v1` with a malicious payload.

### ❌ Vulnerable (Mutable Tag)
```yaml
uses: thirdparty/security-scan@v1 # Attacker can update tag v1 anytime!
```

### ✅ Secure (Immutable Commit SHA Pinning)
```yaml
# SECURE: Pin exact 40-character git commit SHA
uses: thirdparty/security-scan@a1b2c3d4e5f678901234567890abcdef12345678 # v1.2.3
```

---

## 3. Vulnerability 3: Eliminating Static Cloud Credentials with OIDC

Storing long-lived AWS Access Keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) in GitHub Secrets creates a risk of key leakage if a pipeline is compromised.

### ✅ Secure OIDC Authentication (AWS)
```yaml
name: Deploy to AWS
on:
  push:
    branches: [ main ]

permissions:
  id-token: write # Required for requesting OIDC JWT token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS Credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          aws-region: us-east-1
          # NO STATIC KEYS STORED IN SECRETS! Short-lived token created dynamically.
```

---

*Next Chapter: [03. Secrets, Dependencies & Artifact Signing →](03-secrets-and-dependency-confusion.md)*
