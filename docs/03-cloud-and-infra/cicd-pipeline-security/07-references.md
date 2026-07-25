---
title: "07. References & Standards"
description: "Authoritative security standards, CVE bibliography, framework specifications, and open-source tooling repositories for CI/CD Pipeline Security."
keywords: ["AppSec", "Cybersecurity", "SLSA Framework", "OWASP CI/CD", "NIST SP 800-218", "TruffleHog", "Sigstore Cosign", "Security Tools"]
---

# 07. References & Standards

Authoritative resources, security specifications, open-source audit tools, and CVE case studies for CI/CD Pipeline Security.

---

## 1. Industry Frameworks & Specifications

| Framework / Standard | Organization | Focus Area | Resource Link |
| :--- | :--- | :--- | :--- |
| **SLSA Framework (v1.0)** | OpenSSF / Google | Software provenance & build level security | [slsa.dev](https://slsa.dev/) |
| **OWASP Top 10 for CI/CD** | OWASP Foundation | CI/CD pipeline risk classification | [owasp.org/www-project-top-10-ci-cd-security-risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) |
| **NIST SP 800-218 (SSDF)** | NIST | Secure Software Development Framework | [csrc.nist.gov/publications/detail/sp/800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final) |
| **CIS GitHub Actions Benchmark** | Center for Internet Security | Hardening benchmark for GitHub Actions | [cisecurity.org/benchmarks](https://www.cisecurity.org/benchmarks) |
| **CISA Open Source Strategy** | US CISA | Supply chain defense strategy | [cisa.gov/resources-tools/resources/open-source-software-security-roadmap](https://www.cisa.gov/resources-tools/resources/open-source-software-security-roadmap) |

---

## 2. Essential CI/CD Security Tooling

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           RECOMMENDED CI/CD SECURITY STACK                              │
├───────────────────┬──────────────────────────────────┬──────────────────────────────────┤
│ Category          │ Tool Name                        │ Repository / Project             │
├───────────────────┼──────────────────────────────────┼──────────────────────────────────┤
│ Secret Scanning   │ TruffleHog                       │ github.com/trufflesecurity/trufflehog │
│ Secret Scanning   │ Gitleaks                         │ github.com/gitleaks/gitleaks    │
│ SAST Audit        │ Semgrep                          │ github.com/semgrep/semgrep       │
│ Action Linter     │ zizmor                           │ github.com/woodruffw/zizmor      │
│ Action Linter     │ actionlint                       │ github.com/rhysd/actionlint      │
│ SCA Vulnerability │ Trivy                            │ github.com/aquasecurity/trivy    │
│ Egress Guard      │ StepSecurity Harden-Runner       │ github.com/step-security/harden-runner │
│ Artifact Signing  │ Sigstore / Cosign                │ github.com/sigstore/cosign       │
│ Policy-as-Code    │ Conftest (OPA Rego)              │ github.com/open-policy-agent/conftest │
│ Admission Control │ Kyverno                          │ github.com/kyverno/kyverno       │
│ Provenance        │ SLSA GitHub Generator            │ github.com/slsa-framework/slsa-github-generator │
└───────────────────┴──────────────────────────────────┴──────────────────────────────────┘
```

---

## 3. CVE & Supply Chain Incident Bibliography

| Incident / CVE | Year | Vector / Mechanism | Analysis Reference |
| :--- | :--- | :--- | :--- |
| **SolarWinds SUNBURST** | 2020 | MSBuild compilation plugin injection & signed DLL backdoor | [CISA Alert AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) |
| **Codecov Uploader** | 2021 | GCS script tamper & environment variable exfiltration | [Codecov Security Update](https://about.codecov.io/security-update/) |
| **CVE-2024-3094 (XZ Utils)** | 2024 | M4 macro build injection & SSH authentication bypass | [NIST NVD CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094) |
| **CircleCI Breach** | 2023 | Engineer malware compromise & runner secret theft | [CircleCI Security Report](https://circleci.com/blog/january-4-2023-security-incident-incident-report/) |
| **Alex Birsan Dependency Confusion** | 2021 | Public vs private registry version priority exploitation | [Medium Research Post](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) |

---

## 4. Documentation & Further Reading

- **[GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)** — Official security guidance for GitHub Actions workflows.
- **[Sigstore Official Documentation](https://docs.sigstore.dev/)** — Architecture guide for Cosign, Fulcio, and Rekor keyless signing.
- **[OpenSSF Supply Chain Security](https://openssf.org/)** — Open Source Security Foundation initiatives and security tooling standards.

---

> [!NOTE]
> All guides in AppSec Atlas are open-source and continuously updated against emerging threats.

---

*Return to [Module Overview & Index →](README.md)*
