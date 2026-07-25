---
title: "03 - Policy as Code & Compliance Automation"
description: "Comprehensive guide and best practices for 03 - Policy as Code & Compliance Automation in the devsecops-handbook section of AppSec Atlas. Learn how to secure yo"
keywords: ['devsecops-handbook', '03---policy-as-code-&-compliance-automation', 'appsec', 'security', 'compliance']
---
# 03 - Policy as Code & Compliance Automation

Policy as Code (PaC) involves writing rules in a high-level programming language to manage and automate policies. This ensures that infrastructure, deployments, and configurations are secure and compliant before they are provisioned.

## Why Policy as Code?
Manual compliance checks are slow and error-prone. PaC allows you to:
- **Automate Guardrails:** Prevent misconfigurations from being deployed.
- **Version Control Policies:** Treat compliance rules just like source code (GitOps).
- **Map to Frameworks:** Automatically map technical rules to compliance controls (SOC 2, ISO 27001, NIST CSF).

## 🛠️ Open Policy Agent (OPA) & Conftest
**OPA** is a CNCF graduated project providing a unified toolset and framework for policy across the cloud-native stack. **Conftest** is a utility to write tests against structured configuration data (YAML, JSON) using OPA's Rego language.

### Example: Enforcing Terraform Security with Rego
Suppose you want to enforce a SOC 2 requirement that all AWS S3 buckets must have server-side encryption enabled.

**`s3_encryption.rego`**
```rego
package main

# Deny if the resource is an aws_s3_bucket and does not have server_side_encryption_configuration
deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration

    msg := sprintf("SOC2-CC6.1: S3 bucket '%v' must have server-side encryption enabled", [name])
}
```

**Running Conftest in CI/CD:**
```bash
conftest test terraform.tfstate -p s3_encryption.rego
```

## ☸️ Kubernetes Admission Control with Kyverno
While OPA Gatekeeper is popular, **Kyverno** is explicitly built for Kubernetes. It validates, mutates, and generates configurations using Kubernetes resources rather than a custom language like Rego.

### Example: Forbidding the `latest` tag in Pods
Running the `latest` tag is a bad practice (NIST SP 800-190). Here is a Kyverno ClusterPolicy to block it.

**`block-latest-tag.yaml`**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-tags
  annotations:
    policies.kyverno.io/title: Require Image Tags
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/description: >-
      Images should be configured with a specific tag. Using `latest` can lead to unpredictable behavior.
spec:
  validationFailureAction: Enforce
  rules:
  - name: validate-image-tag
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Using the 'latest' image tag is strictly forbidden."
      pattern:
        spec:
          containers:
          - image: "!*:latest"
```

## Mapping to Compliance Frameworks
By organizing your policies by framework, you can automatically generate compliance reports.
- **SOC 2 CC6.1:** Access controls (e.g., Block public S3 buckets, enforce IAM MFA).
- **ISO 27001 A.14.2.5:** Secure system engineering principles (e.g., Enforce container immutability, vulnerability scanning in CI/CD).
- **NIST CSF PR.DS-1:** Data-at-rest is protected (e.g., Enforce RDS encryption, S3 encryption).


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
