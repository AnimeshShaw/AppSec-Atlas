# CI/CD Pipeline Security Guide

> **Section:** ☁️ Cloud & Infrastructure Security  
> **Level:** Intermediate  
> **Time to Complete:** ~60 minutes  
> **Prerequisites:** Basic knowledge of GitHub Actions / GitLab CI, Git, and cloud infrastructure  
> **Status:** ✅ Complete & Production-Ready

---

## 🎯 Overview & Learning Objectives

CI/CD Pipeline Security focuses on securing continuous integration and deployment pipelines against supply chain attacks, pipeline poisoning, secret leakage, and unauthorized artifact tampering. Modern software delivery relies heavily on automated pipelines; compromised build agents or malicious pull requests can lead to instant production compromise.

By the end of this practical guide, you will be able to:
- [x] **Understand** supply chain threat vectors (SLSA framework, SolarWinds, XZ Utils).
- [x] **Identify** vulnerable GitHub Actions patterns (`pull_request_target`, unpinned actions, script injections).
- [x] **Harden** CI/CD pipelines using OIDC authentication (eliminating static cloud credentials).
- [x] **Prevent** dependency confusion and typosquatting attacks in npm, PyPI, and Maven.
- [x] **Implement** cryptographic container image signing using Sigstore/Cosign.
- [x] **Solve** a hands-on lab: Vulnerable GitHub Actions workflow + Poisoned PR exploit + Secure Fix.

---

## 📚 Module Navigation

1. **[01. Overview & Supply Chain Threat Landscape](01-introduction.md)** — Introduction to CI/CD supply chain attacks, the SLSA framework (Supply-chain Levels for Software Artifacts), and real-world breach case studies.
2. **[02. GitHub Actions Security Hardening](02-github-actions-hardening.md)** — Insecure `pull_request_target`, action pinning by commit SHA, untrusted inline script execution, and OIDC federated authentication for AWS/GCP.
3. **[03. Secrets, Dependencies & Artifact Signing](03-secrets-and-dependency-confusion.md)** — Dependency confusion prevention (npm, PyPI), automated secret scanning (TruffleHog), and container signing via Sigstore/Cosign.
4. **[04. Pipeline Security Gates & Branch Protection](04-defenses-and-pipeline-rules.md)** — Enforcing strict branch protection rules, `CODEOWNERS` policies, and automated SAST/DAST/SCA security gates in pipelines.
5. **[05. Hands-On Vulnerability Lab](05-hands-on-lab.md)** — Self-contained Lab: Vulnerable Workflow + Poisoned PR Exploit Payload + Secure Remediation YAML.
6. **[06. References & Tooling](06-references.md)** — GitHub Security Hardening Guides, SLSA specification, StepSecurity Harden-Runner, and Cosign references.

---

*Begin reading: [01. Overview & Supply Chain Threat Landscape →](01-introduction.md)*
