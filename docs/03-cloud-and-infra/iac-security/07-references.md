---
title: 07 - References, Standards and Tooling Index
description: Comprehensive catalog of industry security standards, NIST controls,
  CIS benchmarks, OWASP cheatsheets, open-source security tools, and Cloud provider
  security documentation.
keywords:
- IaC
- Security
- References
- CIS
- Benchmarks
- NIST
- SP
- 800-53
- OWASP
- IaC
- Checkov
- Docs
- OPA
- Rego
- Docs
- Security
- Standards
slug: /cloud-and-infra/iac-security/references
---


# 07 - References, Standards and Tooling Index

To support continuous learning and production implementation of Infrastructure as Code (IaC) security, this chapter provides a curated index of industry standards, regulatory frameworks, open-source security tools, and official cloud provider documentation.

---

## 📚 Industry Standards & Security Frameworks

### Center for Internet Security (CIS) Benchmarks
The CIS Benchmarks serve as the global consensus standard for hardening cloud environments and IaC configurations:
- [CIS Amazon Web Services Foundations Benchmark v2.0.0](https://www.cisecurity.org/benchmark/amazon_web_services/)
- [CIS Microsoft Azure Foundations Benchmark v2.0.0](https://www.cisecurity.org/benchmark/azure/)
- [CIS Google Cloud Computing Platform Benchmark v2.0.0](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/)

### NIST SP 800-53 Rev. 5 Security Controls
Key controls mapped to Infrastructure as Code security implementation:
- **CM-2 (Baseline Configuration)**: Maintaining documented, version-controlled IaC baselines.
- **CM-6 (Configuration Settings)**: Mandatory automated scanning of IaC parameters prior to deployment.
- **SA-11 (Developer Testing and Evaluation)**: Integrating SAST and Policy as Code into CI/CD pipelines.
- **SC-28 (Protection of Information at Rest)**: Enforcing KMS key encryption for state storage and cloud data stores.

### OWASP & US Government Guidance
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [OWASP Cloud Native Security Top 10](https://owasp.org/www-project-cloud-native-security-top-10/)
- [NSA / CISA Cybersecurity Information Sheet: Mitigating Cloud Vulnerabilities](https://media.defense.gov/2020/Jan/22/2002237416/-1/-1/0/U_OO_105004_20.PDF)

---

## 🛠️ Security Tools & Open-Source Projects

### Static Application Security Testing (SAST)
- **Checkov (Prisma Cloud)**
  - Documentation: [https://www.checkov.io/](https://www.checkov.io/)
  - Source Code: [https://github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov)
- **tfsec (Aqua Security / Trivy)**
  - Documentation: [https://aquasecurity.github.io/tfsec/](https://aquasecurity.github.io/tfsec/)
  - Source Code: [https://github.com/aquasecurity/tfsec](https://github.com/aquasecurity/tfsec)
- **Terrascan (Tenable)**
  - Documentation: [https://runterrascan.io/](https://runterrascan.io/)
  - Source Code: [https://github.com/tenable/terrascan](https://github.com/tenable/terrascan)
- **KICS (Checkmarx Keep Infrastructure as Code Secure)**
  - Documentation: [https://kics.io/](https://kics.io/)
  - Source Code: [https://github.com/Checkmarx/kics](https://github.com/Checkmarx/kics)

### Policy as Code Engines
- **Open Policy Agent (OPA)**
  - Documentation: [https://www.openpolicyagent.org/docs/latest/](https://www.openpolicyagent.org/docs/latest/)
  - Rego Language Reference: [https://www.openpolicyagent.org/docs/latest/policy-language/](https://www.openpolicyagent.org/docs/latest/policy-language/)
  - Terraform Integration Guide: [https://www.openpolicyagent.org/docs/latest/terraform/](https://www.openpolicyagent.org/docs/latest/terraform/)
- **HashiCorp Sentinel**
  - Documentation: [https://docs.hashicorp.com/sentinel/](https://docs.hashicorp.com/sentinel/)

### Drift Detection & Cloud Compliance
- **driftctl (Snyk)**
  - Source Code: [https://github.com/snyk/driftctl](https://github.com/snyk/driftctl)
- **Cloud Custodian**
  - Documentation: [https://cloudcustodian.io/](https://cloudcustodian.io/)
  - Source Code: [https://github.com/cloud-custodian/cloud-custodian](https://github.com/cloud-custodian/cloud-custodian)

---

## 📖 Official IaC Engine & Cloud Provider Documentation

### HashiCorp Terraform
- [Terraform Standard Module Structure & Security](https://developer.hashicorp.com/terraform/language/modules/develop/structure)
- [Terraform Backend S3 Configuration](https://developer.hashicorp.com/terraform/language/settings/backends/s3)
- [Terraform Cloud Workspaces & OIDC Identity Provider](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/settings/dynamic-credentials)

### AWS CloudFormation
- [AWS CloudFormation Security Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/security-best-practices.html)
- [AWS Secrets Manager & SSM Dynamic References](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html)
- [AWS CloudFormation Guard Rules Engine](https://github.com/aws-cloudformation/cloudformation-guard)

### Azure Bicep & ARM
- [Azure Bicep Security Best Practices](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/security)
- [Bicep @secure Parameter Decorator](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/parameters#secure-parameters)
- [Azure Key Vault Integration in Bicep](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/key-vault-parameter)

---

## 🔬 Academic & Technical Literature

- **A Analysis of Infrastructure as Code Misconfigurations in Cloud Ecosystems** (IEEE Transactions on Software Engineering, 2022)
- **Automated Verification of Static Security Policies in Declarative Infrastructure Templates** (ACM Symposium on Cloud Computing)
- **Shifting Cloud Infrastructure Security Left: Empirical Evaluation of Static Analysis Tools on Production Terraform Code** (Journal of Cybersecurity and Privacy)

---

> [!NOTE]
> **Continuous Learning**: Security rules and cloud provider capabilities evolve rapidly. Regularly update local SAST scanners (Checkov, tfsec) and policy libraries to ensure protection against emerging cloud vulnerability vectors.
