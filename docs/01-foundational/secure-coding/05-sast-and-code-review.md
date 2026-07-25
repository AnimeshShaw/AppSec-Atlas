---
title: "Chapter 5: SAST & Code Review"
description: "SAST tools analyze source code for vulnerabilities without executing it. They integrate into the CI/CD pipeline to block insecure code before it merge..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Secure Coding", "05 Sast And Code Review.Md"]
---

# Chapter 5: SAST & Code Review

## Static Application Security Testing (SAST)
SAST tools analyze source code for vulnerabilities without executing it. They integrate into the CI/CD pipeline to block insecure code before it merges.

### Integrating Semgrep
Semgrep is a fast, open-source static analysis tool.

**Installation:**
```bash
python3 -m pip install semgrep
```

**Running Semgrep locally:**
```bash
# Scan using the standard security ruleset
semgrep scan --config "p/security-audit" .
```

### Pre-Commit Hooks
Catch vulnerabilities locally before committing. Add this to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.17.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/ci', '--error']
```

## Security Code Review Checklist
When reviewing pull requests, check for:
- [ ] Are all inputs explicitly validated against an allowlist?
- [ ] Are parameterised queries used for all database access?
- [ ] Is output encoded properly for its context?
- [ ] Are file uploads restricted by type, size, and stored securely?
- [ ] Are sensitive logs (passwords, tokens) scrubbed before logging?
- [ ] Does the application fail securely without leaking stack traces?
