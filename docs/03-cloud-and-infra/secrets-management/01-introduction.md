---
title: "Introduction to Secrets Management"
description: "Understand the secrets lifecycle, the risks of hardcoded credentials, and the threat of secret sprawl across source code, CI/CD, and configurations."
keywords: ["secret sprawl", "hardcoded secrets", "secrets lifecycle", "appsec"]
---
# 01. Introduction to Secrets Management

## The Threat Landscape: Secret Sprawl
Modern applications rely heavily on external services, APIs, databases, and third-party tools. To access these, applications need credentials—commonly referred to as "secrets". 

When secrets are not managed centrally, they tend to proliferate across the ecosystem. This phenomenon is known as **Secret Sprawl**. 

Secrets can be inadvertently exposed in:
- Source code repositories (hardcoded credentials).
- Configuration files (`.env`, `config.yml`) checked into version control.
- Dockerfiles (e.g., passing secrets as `ENV` or `ARG` instead of build secrets).
- CI/CD logs.
- Developer workstations.
- Kubernetes ConfigMaps or standard, unencrypted Kubernetes Secrets.

## The Risks of Hardcoding Secrets

> [!WARNING]
> Hardcoding secrets in source code is a critical vulnerability (CWE-798: Use of Hard-coded Credentials).

- **Easy Extraction**: Attackers who gain access to the source code (via LFI, SSRF, open source, or insider threat) immediately obtain valid credentials.
- **Difficult to Rotate**: If a secret is compromised, rotating it requires a full code deployment and coordinating across environments.
- **No Auditing**: It's impossible to track which component or user actually used the secret, making incident response exceedingly difficult.

## The Secrets Lifecycle
Proper secret management involves handling secrets throughout their entire lifecycle:

### 1. Generation
Secrets should be strong, random, and ideally generated dynamically. 
- *Dynamic Secrets*: Created on-the-fly when requested and automatically revoked when their Time-To-Live (TTL) expires.

### 2. Storage & Distribution
Secrets must be stored in a centralized, encrypted, and access-controlled system (e.g., HashiCorp Vault, AWS Secrets Manager). They should be delivered to the application securely, typically via:
- Memory injection at runtime.
- Secure environment variables (provided by orchestrators like Kubernetes).
- Volume mounts (tmpfs, backed by memory).

> [!TIP]
> Avoid passing secrets via command-line arguments (e.g., `--password=SECRET`), as they can be easily captured by other users on the same machine using `ps` or viewed in shell histories.

### 3. Usage & Auditing
Every time a secret is accessed, the action must be authenticated, authorized, and logged. Audit logs should contain:
- Who accessed the secret.
- When it was accessed.
- From where it was accessed.

### 4. Rotation
Secrets should have a limited lifespan. Regular rotation limits the window of opportunity for an attacker if a secret is compromised.
- *Proactive Rotation*: Scheduled rotation every X days.
- *Reactive Rotation*: Immediate rotation triggered by a suspected breach.

### 5. Revocation
When a secret is no longer needed or if it has been compromised, it must be revoked instantly to prevent further access.

---
**Next Step**: Learn how to implement these lifecycle principles using [HashiCorp Vault](./02-hashicorp-vault.md).
