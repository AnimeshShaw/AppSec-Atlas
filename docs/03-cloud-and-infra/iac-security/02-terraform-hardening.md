---
title: "02 - Terraform Hardening"
description: "Terraform is a powerful tool, but its defaults and common practices can sometimes lead to security vulnerabilities. This chapter covers essential tech..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Iac Security", "02 Terraform Hardening.Md"]
---

# 02 - Terraform Hardening

Terraform is a powerful tool, but its defaults and common practices can sometimes lead to security vulnerabilities. This chapter covers essential techniques for securing your Terraform deployments.

## 🔒 Secure State File Storage

Terraform state files (`terraform.tfstate`) map your real-world resources to your configuration. They often contain sensitive data, including passwords, tokens, and private keys in plaintext.

### Best Practices for Remote State
Never store state files in version control. Use a secure remote backend (like AWS S3) with state locking (via DynamoDB) to prevent concurrent modifications and ensure encryption.

**Secure S3 Backend Configuration (AWS):**

```hcl
terraform {
  backend "s3" {
    bucket         = "my-secure-terraform-state-bucket"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
  }
}
```

### Bucket Hardening
Ensure the state bucket itself is highly secure:
- Enable Versioning.
- Block all public access.
- Restrict access via strict IAM policies.

## 🛑 Preventing Cleartext Secrets

Never hardcode secrets in your `.tf` files. Use external secret managers (like AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault) and fetch them at runtime.

**❌ Vulnerable Pattern (Hardcoded Secret):**
```hcl
resource "aws_db_instance" "default" {
  engine   = "mysql"
  password = "SuperSecretPassword123!" # DANGER!
}
```

**✅ Secure Pattern (AWS Secrets Manager):**
```hcl
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/db/password"
}

resource "aws_db_instance" "default" {
  engine   = "mysql"
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```

## ☁️ Terraform Cloud Security

If using Terraform Cloud/Enterprise:
- Use **Workspace Variable Security**: Mark sensitive variables as "Sensitive" so they are redacted in UI and logs.
- Utilize **Sentinel or OPA**: Enforce Policy as Code directly within the Terraform Cloud workflow.
- **Dynamic Credentials**: Use OIDC (OpenID Connect) to authenticate to cloud providers (AWS/Azure/GCP) instead of long-lived static credentials.

## 🛡️ General Code Hardening

- **Use Modules Carefully**: Pin module versions to prevent supply chain attacks (e.g., `version = "1.2.0"`).
- **Least Privilege**: Always assign the minimum required IAM permissions to resources created by Terraform.

---
**Next:** [CloudFormation & Bicep](03-cloudformation-and-bicep.md)
