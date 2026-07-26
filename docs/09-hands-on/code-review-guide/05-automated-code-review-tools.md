---
title: 05 Automated Code Review Tools
description: Static Application Security Testing (SAST) tools help automate the discovery
  of security defects.
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- 09
- Hands
- 'On'
- Code
- Review
- Guide
- '05'
- Automated
- Code
- Review
- Tools
- Md
slug: /hands-on/code-review-guide/automated-code-review-tools
---


# 05 Automated Code Review Tools

Static Application Security Testing (SAST) tools help automate the discovery of security defects.

## 1. Semgrep

Semgrep is a fast, open-source static analysis tool that excels at finding bugs using customizable rules. It understands code semantics, not just strings.

### Installing and Running Semgrep
```bash
# Install Semgrep
pip install semgrep

# Run with default security rules
semgrep --config "p/security-audit" src/

# Run a custom rule file
semgrep --config custom-rules.yaml src/
```

### Custom Semgrep Rule Example
Here is a Semgrep rule to detect the use of weak random number generation (`random` instead of `secrets`) in Python:

```yaml
rules:
  - id: insecure-random-module
    languages:
      - python
    message: |
      The standard `random` module is not cryptographically secure. 
      Use the `secrets` module for generating security-sensitive data.
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: random.random()
          - pattern: random.randint(...)
          - pattern: random.choice(...)
```

## 2. SonarQube

SonarQube is a popular platform for continuous inspection of code quality and security.

### Configuration (`sonar-project.properties`)
```properties
sonar.projectKey=my_secure_app
sonar.projectName=My Secure Application
sonar.sources=src
# Enable specific security rulesets
sonar.qualitygate.wait=true
```

## 3. Pre-Commit Hooks

Integrating tools like `detect-secrets` into git pre-commit hooks prevents hardcoded secrets from ever entering the repository.

### `.pre-commit-config.yaml`
```yaml
repos:
-   repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
    -   id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```
