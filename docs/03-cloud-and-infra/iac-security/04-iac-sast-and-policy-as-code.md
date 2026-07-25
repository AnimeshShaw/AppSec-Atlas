---
title: "04 - IaC SAST and Policy as Code"
description: "To prevent vulnerable infrastructure from reaching production, you must implement automated security scanning in your CI/CD pipelines."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Iac Security", "04 Iac Sast And Policy As Code.Md"]
---

# 04 - IaC SAST and Policy as Code

To prevent vulnerable infrastructure from reaching production, you must implement automated security scanning in your CI/CD pipelines.

## 🔍 Static Application Security Testing (SAST) for IaC

IaC SAST tools analyze your Terraform, CloudFormation, Kubernetes, or Docker files for known misconfigurations before deployment.

### Popular Tools:
1. **Checkov**: (By Prisma Cloud) Scans Terraform, CloudFormation, K8s, etc. Excellent coverage and custom policy support.
2. **tfsec**: (By Aqua Security) specifically built for Terraform. Fast and easy to integrate.
3. **Terrascan**: (By Tenable) Extensive ruleset for multiple IaC formats.

### Example: Running Checkov locally
```bash
# Install checkov
pip install checkov

# Scan a directory containing Terraform files
checkov -d ./terraform-prod/
```

## 📜 Policy as Code (PaC)

Policy as Code involves writing rules in a high-level language to enforce security and compliance constraints. The **Open Policy Agent (OPA)** and its language, **Rego**, are the industry standard.

### Writing Rego Policies for Terraform

When using OPA, you typically convert Terraform plans to JSON and evaluate them against Rego policies.

**✅ Example Rego Policy: Deny Public S3 Buckets**

```rego
package terraform.s3_security

import input as tfplan

# Deny if an aws_s3_bucket has an acl set to "public-read" or "public-read-write"
deny[msg] {
    resource := tfplan.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    # Check the planned attributes
    acl := resource.change.after.acl
    is_public(acl)
    
    msg := sprintf("S3 Bucket '%v' must not have public ACL. Found: %v", [resource.name, acl])
}

is_public("public-read")
is_public("public-read-write")
```

### Enforcing in CI/CD

Integrate these tools into GitHub Actions, GitLab CI, or Jenkins. If a scan fails (e.g., an S3 bucket is public), the pipeline fails, preventing the deployment.

**GitHub Actions Example:**
```yaml
jobs:
  iac-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: ./terraform
          framework: terraform
```

---
**Next:** [Drift Detection & Compliance](05-drift-detection-and-compliance.md)
