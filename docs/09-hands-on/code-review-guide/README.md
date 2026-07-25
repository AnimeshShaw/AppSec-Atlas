# Secure Code Review Guide

## Overview
Welcome to the Secure Code Review Guide. This module provides a comprehensive deep dive into the methodology, practice, and tooling required to perform effective secure code reviews. It transitions security from a reactive testing phase into a proactive defect-discovery phase during the Software Development Life Cycle (SDLC).

## Prerequisites
- Basic understanding of web application vulnerabilities (OWASP Top 10).
- Familiarity with reading code in modern languages (Python, Node.js, Go, Java).
- Basic knowledge of version control systems (Git) and pull request workflows.

## Learning Objectives
By the end of this guide, you will be able to:
- Establish a structured Secure Code Review methodology.
- Identify critical security flaws in authentication, data handling, and cryptography through manual inspection.
- Distinguish between vulnerable and secure code patterns across multiple languages.
- Leverage Automated Code Review Tools (SAST) like Semgrep and configure custom rules.
- Perform a hands-on review of a vulnerable pull request and provide actionable remediation advice.

## Navigation
- [01 Introduction](01-introduction.md): Secure Code Review methodology, manual vs SAST code review, code review checklists.
- [02 Reviewing Authentication and Authorization](02-reviewing-authentication-and-authorization.md): Code patterns for broken auth, weak password hashes, JWT verification bugs, BOLA/IDOR.
- [03 Reviewing Data Handling and Injection](03-reviewing-data-handling-and-injection.md): Code patterns for SQLi, Command Injection, SSRF, XSS, unsafe deserialization.
- [04 Reviewing Crypto and Secrets](04-reviewing-crypto-and-secrets.md): Code patterns for hardcoded secrets, weak AES-ECB, hardcoded IVs, weak random generators.
- [05 Automated Code Review Tools](05-automated-code-review-tools.md): Semgrep custom rule creation, SonarQube rule configuration, pre-commit hooks setup.
- [06 Hands-on Lab](06-hands-on-lab.md): Self-contained Python Lab with vulnerable PR diffs, reviewer findings, and hardened refactored code.
- [07 References](07-references.md): OWASP guidelines, CERT standards, and external documentation.
