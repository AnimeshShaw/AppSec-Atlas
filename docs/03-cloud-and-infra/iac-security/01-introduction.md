# 01 - Introduction to IaC Security

Infrastructure as Code (IaC) is the process of managing and provisioning computing infrastructure through machine-readable definition files, rather than physical hardware configuration or interactive configuration tools.

## 🌪️ The Threat Landscape

With IaC, a single misconfiguration can be replicated across hundreds of servers or cloud resources in seconds. 

### Common IaC Security Risks
1. **Hardcoded Secrets**: Embedding AWS keys, database passwords, or API tokens directly into IaC files.
2. **Overly Permissive Access**: Creating IAM roles with `AdministratorAccess` or security groups open to `0.0.0.0/0`.
3. **Unencrypted Data Stores**: Provisioning S3 buckets, RDS instances, or EBS volumes without encryption at rest.
4. **Public Exposure**: Accidentally exposing private subnets, databases, or storage buckets to the public internet.
5. **Insecure State Storage**: Leaving Terraform state files (which often contain secrets in plaintext) in public or unencrypted buckets.

## 🏗️ Immutable Infrastructure

Immutable infrastructure is a paradigm where servers are never modified after they're deployed. If an update or fix is needed, a new server built from a common image replaces the old one.

**Security Benefits:**
- **Reduced Attack Surface**: No SSH access or ad-hoc changes reduce the risk of tampering.
- **Predictability**: You always know exactly what software is running in production.
- **Easy Rollbacks**: If a vulnerability is found, you can easily roll back to a known-secure image.

## 🛡️ Security as Code Principles

Security as Code (SaC) is the integration of security policies and tests directly into the CI/CD pipeline, often expressed as code.

### Core Principles:
- **Shift Left**: Catch misconfigurations during the pull request phase, before infrastructure is provisioned.
- **Automated Scanning**: Use SAST tools (like Checkov or tfsec) to scan IaC files automatically.
- **Policy as Code**: Define security constraints (e.g., "all S3 buckets must be private") using languages like Rego (Open Policy Agent).
- **Continuous Monitoring**: Detect drift between the deployed infrastructure and the defined IaC code.

---
**Next:** [Terraform Hardening](02-terraform-hardening.md)
