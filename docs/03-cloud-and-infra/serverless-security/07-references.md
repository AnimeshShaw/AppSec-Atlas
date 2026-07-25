---
title: "07 - References and Further Reading"
description: "To deepen your understanding of Serverless Security and stay updated with the latest threats and mitigation strategies, refer to the following industr..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Serverless Security", "07 References.Md"]
---

# 07 - References and Further Reading

To deepen your understanding of Serverless Security and stay updated with the latest threats and mitigation strategies, refer to the following industry standards, guidelines, and documentation.

## 📚 OWASP Resources

*   **OWASP Serverless Top 10:** The authoritative guide on the most critical security risks for serverless applications.
    *   [OWASP Serverless Top 10 Project](https://owasp.org/www-project-serverless-top-10/)
    *   *Key topics covered:* Injection, Broken Authentication, Over-Privileged Functions, Insecure Serverless Deployment.

## ☁️ Cloud Provider Security Guidelines

### AWS (Amazon Web Services)
*   **Security Overview of AWS Lambda:** Comprehensive whitepaper detailing the shared responsibility model, Lambda architecture, and isolation mechanisms.
    *   [AWS Lambda Security Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/security-overview-aws-lambda/security-overview-aws-lambda.html)
*   **AWS Well-Architected Framework - Serverless Applications Lens:** Best practices for designing, deploying, and maintaining secure serverless architectures on AWS.
    *   [Serverless Application Lens](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security.html)

### Azure
*   **Azure Functions Security:** Guidance on securing serverless environments in Azure.
    *   [Securing Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)

### Google Cloud (GCP)
*   **Google Cloud Functions Security:** Overview of IAM, network egress controls, and secret management in GCP.
    *   [Securing Cloud Functions](https://cloud.google.com/functions/docs/securing)

## 🛠️ Frameworks and Tooling Documentation

*   **Serverless Framework Security:** Guidelines for implementing secure configurations and IAM roles within the `serverless.yml` file.
    *   [Serverless Framework Documentation](https://www.serverless.com/framework/docs/)
    *   *Plugin:* [serverless-iam-roles-per-function](https://github.com/functionalone/serverless-iam-roles-per-function)
*   **AWS Serverless Application Model (SAM):** Policy templates for applying least privilege easily in SAM templates.
    *   [AWS SAM Policy Templates](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-policy-templates.html)

## 📖 Recommended Articles & Research

*   **"Serverless Security: What are the risks and how to mitigate them?"** - General overview of the paradigm shift in application security.
*   **Datadog Security Labs:** Research and articles on attacking and defending serverless infrastructure.
*   **Rhino Security Labs - AWS IAM Privilege Escalation:** Deep dives into how over-privileged IAM roles can be abused to escalate privileges in an AWS account.
    *   [AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
