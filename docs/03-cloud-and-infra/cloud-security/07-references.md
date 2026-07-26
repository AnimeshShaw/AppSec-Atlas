---
title: 07 - References & Cloud Security Resources
description: 'Comprehensive reference library for cloud security: CIS Benchmarks,
  NIST standards, high-profile breach analyses, open-source security tools, and CTF
  labs.'
keywords:
- Cloud
- Security
- Frameworks
- CIS
- Benchmarks
- NIST
- SP
- 800-53
- Prowler
- Scout
- Suite
- CloudGoat
- Cloud
- CTF
- AppSec
slug: /cloud-and-infra/cloud-security/references
---


# 07 - References & Cloud Security Resources

To expand your technical expertise in cloud security architecture, audit compliance, and incident response, consult the following curated security frameworks, incident case studies, and open-source tools.

---

## 1. Industry Standards & Governance Frameworks

- **Center for Internet Security (CIS) Benchmarks:** Consensus-based technical guidelines for securing multi-cloud environments.
  - [CIS Amazon Web Services Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/)
  - [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure/)
  - [CIS Google Cloud Platform Foundations Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)
- **National Institute of Standards and Technology (NIST):**
  - [NIST SP 800-145: The NIST Definition of Cloud Computing](https://csrc.nist.gov/publications/detail/sp/800-145/final)
  - [NIST SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
  - [NIST SP 800-210: General Access Control Guidance for Cloud Infrastructure as a Service](https://csrc.nist.gov/publications/detail/sp/800-210/final)
- **Cloud Security Alliance (CSA):**
  - [CSA Cloud Controls Matrix (CCM v4)](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
  - [CSA Security Guidance for Critical Areas of Focus in Cloud Computing v4](https://cloudsecurityalliance.org/research/guidance/)
- **OWASP Foundation:**
  - [OWASP Top 10 Proactive Controls](https://owasp.org/www-project-proactive-controls/)
  - [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)

---

## 2. High-Profile Cloud Breach Case Studies

Analyzing real-world cloud breaches provides invaluable lessons in systemic failure modes and threat actor TTPs.

| Breach Incident | Core Technical Root Cause | Vector & Impact |
| :--- | :--- | :--- |
| **Capital One (2019)** | WAF SSRF + IMDSv1 + Overprivileged IAM Role | Attacker queried IMDSv1 via SSRF, retrieved temporary IAM credentials for a role with `s3:ListBucket` and `s3:GetObject` on 700+ buckets, exfiltrating 100M+ customer records. |
| **Imperva (2018)** | Internal Compute Key Exposure + Snapshot Theft | AWS API key exposed via compromised internal compute instance allowed unauthorized access to an unencrypted AWS EBS volume snapshot containing database API keys. |
| **Ubiquiti (2021)** | AWS IAM Access Key Theft | Insider / Attacker stole developer AWS IAM credentials from LastPass, gaining root-level access to AWS accounts and S3 data stores. |
| **CircleCI (2023)** | Malware on Engineer Workstation + Session Theft | Engineer workstation infected with malware allowed extraction of active 2FA-backed session tokens, allowing attackers to pivot into CircleCI internal AWS infrastructure. |

---

## 3. Open-Source Cloud Security Tooling

### Cloud Security Posture Management & Auditing
- **Prowler:** Open-source security assessment tool for AWS, Azure, GCP, and Kubernetes.
  - [Prowler GitHub Repository](https://github.com/prowler-cloud/prowler)
- **Scout Suite:** Multi-cloud security auditing tool producing interactive HTML reports.
  - [Scout Suite GitHub Repository](https://github.com/nccgroup/ScoutSuite)
- **CloudFox:** Automated command-line tool for discovering attack paths in cloud environments.
  - [CloudFox GitHub Repository](https://github.com/BishopFox/cloudfox)
- **Steampipe:** SQL-based query engine for cloud infrastructure security and compliance.
  - [Steampipe GitHub Repository](https://github.com/turbot/steampipe)

### Offensive Cloud CTFs & Vulnerability Simulators
- **CloudGoat:** Vulnerable-by-design AWS deployment tool by Rhino Security Labs for practicing cloud offensive/defensive tactics.
  - [CloudGoat GitHub Repository](https://github.com/RhinoSecurityLabs/cloudgoat)
- **Pacu:** Open-source AWS exploitation framework designed for offensive security testing.
  - [Pacu GitHub Repository](https://github.com/RhinoSecurityLabs/pacu)
- **Flaws.cloud & Flaws2.cloud:** Interactive challenge platforms for learning AWS security mechanics through real-world scenarios.
  - [flaws.cloud](http://flaws.cloud/)
  - [flaws2.cloud](http://flaws2.cloud/)

---

## 4. Official Cloud Provider Documentation

- **Amazon Web Services (AWS):**
  - [AWS IAM Best Practices & Security Guidelines](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices-iam.html)
  - [Amazon S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
  - [AWS Security Pillar - Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- **Microsoft Azure:**
  - [Azure Security Benchmark (v3)](https://learn.microsoft.com/en-us/azure/security/benchmarks/overview)
  - [Microsoft Entra ID Security Operations Guide](https://learn.microsoft.com/en-us/entra/architecture/security-operations-introduction)
- **Google Cloud Platform (GCP):**
  - [GCP Security Foundations Guide](https://cloud.google.com/architecture/security-foundations)
  - [GCP Service Account Best Practices](https://cloud.google.com/iam/docs/best-practices-service-accounts)
