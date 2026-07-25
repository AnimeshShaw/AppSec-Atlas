---
title: "Zero Trust Cloud Architecture"
description: "Implement Zero Trust natively using cloud services:"
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Zero Trust", "05 Zero Trust Cloud Architecture.Md"]
---

# Zero Trust Cloud Architecture

## Cloud Service Providers
Implement Zero Trust natively using cloud services:
- **AWS**: Use IAM Policies with condition keys (e.g., `aws:SourceIp`, `aws:MultiFactorAuthPresent`), VPC Endpoints, and AWS Verified Access.
- **Azure**: Conditional Access policies, Azure AD Identity Protection, Private Link.
- **GCP**: BeyondCorp Enterprise, Identity-Aware Proxy (IAP), VPC Service Controls.

## Identity-Aware Proxies (IAP)
IAPs broker access to internal applications without a VPN. Users authenticate to the proxy (e.g., Cloudflare Access, Tailscale), which evaluates device and identity context before granting access to the internal app.
