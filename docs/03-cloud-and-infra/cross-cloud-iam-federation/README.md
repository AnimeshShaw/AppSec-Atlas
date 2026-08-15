---
sidebar_position: 1
title: Cross-Cloud IAM Federation
description: Master Workload Identity Federation (WIF) and OIDC Trust across AWS, GCP, Azure, and CI/CD pipelines.
---

# Cross-Cloud IAM Federation Masterclass

Welcome to the Cross-Cloud IAM Federation guide. This module covers the elimination of static service account keys in favor of short-lived, cryptographically verified tokens via OpenID Connect (OIDC). 

In modern infrastructure, hardcoding cloud credentials (AWS Access Keys, GCP JSON keys, Azure Client Secrets) in CI/CD pipelines or cross-cloud workloads is a critical anti-pattern. This guide teaches you how to establish secure, keyless trust between diverse environments.

## What You Will Learn

- **The Concept**: Why static keys are a liability and how OIDC solves the secret-zero problem.
- **The Visual**: Architectural diagrams detailing the token exchange flow.
- **The Code**: Implementing secure keyless authentication in Go, Python, and TypeScript.
- **The Guardrail**: Enforcing keyless policies using Terraform and Rego.

## Chapters

1. **[The Perils of Static Credentials](./01-the-perils-of-static-credentials.md)**
2. **[Understanding OIDC Trust](./02-understanding-oidc-trust.md)**
3. **[AWS OIDC Federation](./03-aws-iam-roles-anywhere-and-oidc.md)**
4. **[GCP Workload Identity Federation](./04-gcp-workload-identity-federation.md)**
5. **[Azure AD Workload Identity](./05-azure-ad-workload-identity.md)**
6. **[GitHub Actions to Cloud Trust](./06-github-actions-to-cloud-trust.md)**
7. **[Cross-Cloud Mesh Trust](./07-cross-cloud-mesh-trust.md)**

Dive in to secure your multi-cloud architecture and CI/CD pipelines!
