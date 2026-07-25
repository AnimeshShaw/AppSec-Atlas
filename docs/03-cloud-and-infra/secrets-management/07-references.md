---
title: "07. References, Compliance Standards & Tooling"
description: "Authoritative references, NIST SP 800-57 guidelines, PCI DSS v4.0 requirements, CIS Kubernetes benchmarks, CWE taxonomy, and open-source tooling catalog."
keywords: ["nist sp 800-57", "pci dss v4.0", "cis benchmark", "cwe-798", "secrets management standards", "appsec references"]
sidebar_label: "07. References & Standards"
sidebar_position: 8
---

# 07. References, Compliance Standards & Tooling

---

## 1. Industry Standards & Regulatory Frameworks

Secrets management is explicitly mandated by regulatory standards and security benchmarks worldwide.

```
+-------------------------------------------------------------------------------+
|                      REGULATORY & COMPLIANCE FRAMEWORKS                       |
+-------------------+-----------------------------------------------------------+
| STANDARD          | MANDATED REQUIREMENT                                      |
+-------------------+-----------------------------------------------------------+
| **NIST SP 800-57**| Recommendation for Key Management. Mandates cryptographically |
|                   | separate Key Encryption Keys (KEK) and Data Encryption     |
|                   | Keys (DEK), short cryptoperiods, and emergency key        |
|                   | revocation procedures.                                    |
+-------------------+-----------------------------------------------------------+
| **PCI DSS v4.0**  | - Requirement 3.5: Protect cryptographic keys against    |
|                   |   disclosure and modification.                            |
|                   | - Requirement 7.2: Target access controls based on        |
|                   |   least privilege and job function.                       |
|                   | - Requirement 8.6: Protect system accounts and machine   |
|                   |   authenticators.                                         |
+-------------------+-----------------------------------------------------------+
| **CIS Kubernetes**| - Benchmark 1.1.13: Ensure encryption-provider-config is |
| **Benchmark**     |   configured on api-server.                               |
|                   | - Benchmark 5.1.2: Minimize access to Secret objects.     |
+-------------------+-----------------------------------------------------------+
| **SOC 2 Type II** | Trust Services Criteria CC6.1 & CC6.3: Enforce logical    |
|                   | access security over credentials and prevent secret       |
|                   | exposure in configuration stores.                         |
+-------------------+-----------------------------------------------------------+
```

---

## 2. Common Weakness Enumeration (CWE) & CVE Catalog

### CWE Taxonomy

- **[CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)**: Hardcoding passwords, secret keys, or tokens in source code or binaries.
- **[CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)**: Storing unencrypted secrets in files, databases, or `etcd`.
- **[CWE-522: Insufficient Credentials Protection](https://cwe.mitre.org/data/definitions/522.html)**: Transmitting or storing credentials without strong encryption.
- **[CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)**: Printing API keys or tokens into stdout, stderr, or APM log files.
- **[CWE-256: Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)**: Storing passwords in unprotected environment variables.

### Notable Secret Exposure CVEs

- **CVE-2023-28432 (MinIO)**: Information disclosure vulnerability exposing admin secret keys via diagnostic endpoints.
- **CVE-2022-24765 (Git)**: Multi-user Git environment issue leading to secret execution context hijacking.
- **CVE-2021-44228 (Log4j / Log4Shell)**: Unsanitized logging allowed arbitrary remote code execution, triggering massive environment secret dumping across Java ecosystems.

---

## 3. Open Source Security Tooling & Libraries

### Secret Detection & Prevention
- **[Gitleaks](https://github.com/gitleaks/gitleaks)**: Fast, SAST-based secret scanner for developer workstations and CI/CD pipelines.
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)**: Active API verification engine for detecting and verifying leaked keys.
- **[pre-commit](https://pre-commit.com/)**: Multi-language pre-commit hook framework for enforcing client-side guardrails.

### Git History Cleanup
- **[git-filter-repo](https://github.com/newren/git-filter-repo)**: Official recommended tool for rewriting Git commit history and purging leaked keys.
- **[BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)**: High-performance alternative for purging large files and credentials from Git repositories.

### Orchestration & Kubernetes Add-ons
- **[External Secrets Operator (ESO)](https://external-secrets.io/)**: Kubernetes operator syncing secrets from external vaults to standard K8s secrets.
- **[Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)**: Mounts vault secrets as temporary in-memory files (`tmpfs`).
- **[Bitnami Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)**: One-way asymmetric encryption for GitOps secrets.
- **[Mozilla SOPS](https://github.com/getsops/sops)**: Editor for encrypted files supporting AWS KMS, GCP KMS, Azure Key Vault, and Age.

### Multi-Language SDKs
- **Python**: [`hvac`](https://hvac.readthedocs.io/), [`boto3`](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- **Node.js**: [`node-vault`](https://github.com/krishnasrinivas/node-vault), [`@google-cloud/secret-manager`](https://cloud.google.com/nodejs/docs/reference/secret-manager/latest)
- **Go**: [`hashicorp/vault/api`](https://pkg.go.dev/github.com/hashicorp/vault/api), [`azsecrets`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets)
- **Java**: [`spring-vault-core`](https://spring.io/projects/spring-vault), [`azure-security-keyvault-secrets`](https://central.sonatype.com/artifact/com.azure/azure-security-keyvault-secrets)

---

## 4. Official Documentation & Further Reading

### HashiCorp Vault
- [Vault Production Hardening Guide](https://developer.hashicorp.com/vault/docs/concepts/production-hardening)
- [Vault AppRole Authentication Engine](https://developer.hashicorp.com/vault/docs/auth/approle)
- [Vault Transit Engine & Envelope Encryption](https://developer.hashicorp.com/vault/docs/secrets/transit)

### Cloud Provider Documentation
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [Google Cloud Secret Manager Architecture](https://cloud.google.com/secret-manager/docs/overview)
- [Azure Key Vault Developer's Guide](https://learn.microsoft.com/en-us/azure/key-vault/general/developers-guide)

### OWASP & Kubernetes Security
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Kubernetes Hardening: Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
