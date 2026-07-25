---
title: "03. Secrets, Dependencies & Artifact Signing"
description: "Preventing secret leaks, blocking malicious dependencies, and verifying software builds are key operational requirements for software supply chain def..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Cicd Pipeline Security", "03 Secrets And Dependency Confusion.Md"]
---

# 03. Secrets, Dependencies & Artifact Signing

Preventing secret leaks, blocking malicious dependencies, and verifying software builds are key operational requirements for software supply chain defense.

---

## 1. Dependency Confusion Attacks

Dependency Confusion occurs when an internal private package name (e.g., `@techcorp/internal-utils`) is registered on a public package repository (npm/PyPI). Package managers configured without explicit scope mapping may prioritize the higher version number published by an attacker on the public registry.

```
Attacker publishes public npm package: @techcorp/internal-utils (version 99.0.0)
                               │
Internal CI Build ─────────────┴──► Downloads higher version (99.0.0) from public npm!
                                             │
                                             ▼
                                  Executes Malicious Payload!
```

### ✅ Mitigation: Scope Configuration (`.npmrc`)
```text
# .npmrc
# Route internal scope exclusively to private registry
@techcorp:registry=https://pkgs.dev.azure.com/techcorp/_packaging/private/npm/registry/
always-auth=true
```

---

## 2. Cryptographic Container Image Signing (Sigstore / Cosign)

Signing container images ensures that Kubernetes clusters deploy ONLY images built by authorized CI/CD pipelines.

```bash
# Generate Cosign keypair
cosign generate-key-pair

# Sign container image in CI/CD pipeline
cosign sign --key env://COSIGN_PRIVATE_KEY myregistry.azurecr.io/appsec-atlas/api:v1.0.0

# Verify container image before deployment in K8s
cosign verify --key cosign.pub myregistry.azurecr.io/appsec-atlas/api:v1.0.0
```

---

*Next Chapter: [04. Pipeline Security Gates & Branch Protection →](04-defenses-and-pipeline-rules.md)*
