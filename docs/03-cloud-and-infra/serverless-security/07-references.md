---
title: 07 - References & Standards
description: Comprehensive reference library for Serverless Security, including CVEs,
  OWASP frameworks, NIST standards, CIS benchmarks, and security tooling resources.
keywords:
- Serverless
- Security
- References
- OWASP
- Serverless
- Top
- '10'
- NIST
- SP
- 800-207
- CIS
- AWS
- Foundations
- CVEs
- Cloud
- Security
- Standards
sidebar_label: 07 - References
slug: /cloud-and-infra/serverless-security/references
---


# 07 - References & Standards

This reference module aggregates industry security standards, vulnerability databases (CVEs), regulatory compliance controls, cloud provider documentation, and open-source security tools for serverless architectures.

---

## 🛑 Real-World CVEs & Serverless Vulnerabilities

| CVE / Identifier | Affected Target | Vulnerability Class | Description / Impact |
| :--- | :--- | :--- | :--- |
| **CVE-2022-22965** | Spring Framework (Spring Cloud Function) | Remote Code Execution (Spring4Shell) | ClassLoader manipulation flaw in Spring Cloud Function serverless deployments allowing remote code execution via HTTP requests. |
| **CVE-2021-44228** | Log4j2 Java Library | Remote Code Execution (Log4Shell) | Impacted Java-based AWS Lambda and Azure Functions utilizing vulnerable Log4j2 logging frameworks via unvalidated event string logging. |
| **CVE-2019-11358** | jQuery / Serverless Node.js dependencies | Prototype Pollution | Prototype pollution in serverless Node.js handlers resulting in global property injection and execution context hijacking across warm starts. |
| **AWS-2023-001** | AWS EventBridge / Lambda Triggers | Event Injection | Unsanitized event mapping payload flaws allowing parameter tampering in downstream FaaS execution pipelines. |
| **CVE-2020-11022** | Unsanitized Lambda Layers | Supply Chain Hijacking | Vulnerable third-party dependencies packaged in public AWS Lambda Layers enabling cross-account code execution. |

---

## 🏛️ Industry Frameworks & Compliance Scopes

### 1. OWASP Serverless Top 10 Mapping Table

| OWASP Risk ID | Vulnerability Title | Primary Mitigation Strategy |
| :--- | :--- | :--- |
| **SAS-01** | Injection (Event Data Injection) | Schema validation (Zod, Pydantic), safe `subprocess` arrays, parameterized database queries. |
| **SAS-02** | Broken Authentication | Enforce API Gateway JWT/Cognito authorizers, mutual TLS (mTLS), and IAM authentication. |
| **SAS-03** | Insecure Deployment Configuration | Harden CORS policies, enforce HTTPS transport, block public S3 event triggers. |
| **SAS-04** | Over-Privileged Execution Roles | Enforce per-function IAM execution roles, eliminate wildcard (`*`) resources, use IAM boundaries. |
| **SAS-05** | Inadequate Function Monitoring | Centralize structured JSON logging, forward logs to CloudWatch/SIEM, audit CloudTrail events. |
| **SAS-06** | Shared Secrets Insecurity | Fetch credentials dynamically from AWS Secrets Manager / Parameter Store with in-memory TTL cache. |
| **SAS-07** | Denial of Wallet (DoW) | Configure API Gateway rate limits, set strict function execution timeouts, enforce concurrency caps. |
| **SAS-08** | Insecure Third-Party Dependencies | Scan Lambda Layers and npm/pip packages using Snyk, Trivy, and `pip-audit` in CI/CD pipelines. |
| **SAS-09** | Improper Exception Handling | Sanitize error responses, strip stack traces and AWS internal request IDs from user HTTP outputs. |
| **SAS-10** | Insecure State & Storage | Encrypt `/tmp` disk storage, purge temporary files in `finally` handlers, enforce KMS CMK encryption. |

---

### 2. NIST SP 800-53 Control Mapping

| Control ID | Control Name | Serverless Implementation Requirement |
| :--- | :--- | :--- |
| **AC-2** | Account Management | Enforce automated lifecycle management for serverless IAM execution roles. |
| **AC-6** | Least Privilege | Isolate execution roles per function; enforce resource-scoped IAM condition keys. |
| **AU-2** | Event Logging | Enable CloudTrail Data Events for Lambda `Invoke` and API Gateway execution logs. |
| **SC-7** | Boundary Protection | Deploy Lambda functions inside private VPC subnets with NAT Gateway / VPC Endpoints. |
| **SC-28** | Protection of Information at Rest | Enforce KMS Customer Managed Keys (CMK) for Secrets Manager, SSM, DynamoDB, and S3. |
| **IA-2** | Identification and Authentication | Implement OAuth2/OIDC claims validation at the API Gateway authorizer layer. |

---

### 3. CIS Amazon Web Services Foundations Benchmark (v2.0.0)

- **Section 3.1:** Ensure CloudTrail is enabled in all regions for Lambda data events.
- **Section 4.1.1:** Ensure no IAM policies grant wildcard `*` administrative rights to Lambda functions.
- **Section 5.1:** Ensure API Gateway endpoints enforce TLS 1.2+ encryption in transit.

---

## ☁️ Official Cloud Provider Documentation

### AWS (Amazon Web Services)
- [AWS Lambda Security Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/security-overview-aws-lambda/security-overview-aws-lambda.html)
- [AWS Well-Architected Framework - Serverless Applications Lens](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security.html)
- [AWS SAM Security Policy Templates Documentation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-policy-templates.html)

### Microsoft Azure
- [Securing Azure Functions Guide](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
- [Azure Security Baseline for Azure Functions](https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-functions-security-baseline)

### Google Cloud Platform (GCP)
- [Securing Google Cloud Functions](https://cloud.google.com/functions/docs/securing)
- [GCP Cloud Functions IAM Roles & Permissions](https://cloud.google.com/functions/docs/concepts/iam)

---

## 🛠️ Security Tooling & Open-Source Repositories

### Static Security Analysis (SAST) & IaC Scanners
- **Checkov:** Static analysis tool for Infrastructure-as-Code (Terraform, CloudFormation, SAM, Serverless Framework).  
  *Repo:* `https://github.com/bridgecrewio/checkov`
- **Semgrep:** Lightweight static analysis engine with custom serverless rule support.  
  *Repo:* `https://github.com/returntocorp/semgrep`
- **Tfsec:** Terraform static security scanner.  
  *Repo:* `https://github.com/aquasecurity/tfsec`

### IAM Audit & Privilege Analysis
- **Prowler:** Open-source AWS, Azure, and GCP security assessment and compliance tool.  
  *Repo:* `https://github.com/prowler-cloud/prowler`
- **CloudSplaining:** AWS IAM policy assessment tool for identifying over-privileged permissions.  
  *Repo:* `https://github.com/salesforce/cloudsplaining`
- **Policy Sentry:** IAM least-privilege policy generator.  
  *Repo:* `https://github.com/salesforce/policy_sentry`

### Serverless Plugins
- **serverless-iam-roles-per-function:** Serverless Framework plugin for per-function role creation.  
  *Repo:* `https://github.com/functionalone/serverless-iam-roles-per-function`
