---
title: DevSecOps Handbook
description: Comprehensive guide and best practices for DevSecOps Handbook in the
  devsecops-handbook section of AppSec Atlas. Learn how to secure your infrastructure.
keywords:
- devsecops-handbook
- devsecops-handbook
- appsec
- security
- compliance
slug: /compliance/devsecops-handbook
---

# DevSecOps Handbook

Welcome to the **DevSecOps Handbook** – the definitive guide for integrating security seamlessly into your Software Development Life Cycle (SDLC) and CI/CD pipelines. This guide is built to help engineering and security teams automate compliance, enforce policy as code, and measure security maturity.

## 📖 Overview
Historically, security was an afterthought—a bottleneck introduced at the end of the software delivery process. DevSecOps shifts this paradigm by building security directly into agile development and operations, ensuring that the software is secure by design.

## 🎯 Learning Objectives
By the end of this module, you will be able to:
- Understand the **Shift-Left Philosophy** and build a scalable Security Champions program.
- Automate security testing within CI/CD pipelines using SAST, DAST, SCA, and Secret Scanning.
- Implement **Policy as Code (PaC)** to automatically govern infrastructure and Kubernetes configurations using OPA and Kyverno.
- Triage vulnerabilities using risk-based prioritization (CVSS v4.0) and enforce SLA tracking.
- Measure your organization's DevSecOps maturity using frameworks like OWASP SAMM.

## 🛠️ Prerequisites
- Basic understanding of CI/CD concepts (GitHub Actions, GitLab CI, or Jenkins).
- Familiarity with containerization (Docker) and orchestration (Kubernetes).
- Basic scripting and YAML syntax.

## 🧭 Navigation
- [01 Introduction](01-introduction.md) - Shift-left, Agile integration, and Security Champions.
- [02 Security in CI/CD Pipelines](02-security-in-ci-cd-pipelines.md) - Integrating SAST, SCA, Secret Scanning, and DAST (YAML included).
- [03 Policy as Code & Compliance](03-policy-as-code-and-compliance-automation.md) - OPA, Conftest, Kyverno, and automated mapping to SOC 2 / ISO 27001.
- [04 Vulnerability Triage and SLAs](04-vulnerability-triage-and-sla.md) - CVSS v4.0, risk scoring, and tracking developer remediation.
- [05 DevSecOps Metrics & Maturity](05-devsecops-metrics-and-maturity.md) - OWASP SAMM, MTTR, and evaluating security culture.
- [06 Hands-On Lab](06-hands-on-lab.md) - Build a self-contained DevSecOps GitHub Actions pipeline.
- [07 References](07-references.md) - Industry standards, DoD references, and useful links.
