---
sidebar_position: 1
title: Modern API Identity (OIDC, FIDO2, Passkeys)
---

# Modern API Identity (OIDC, FIDO2, Passkeys)

Welcome to the Modern API Identity masterclass. In an era where APIs are the backbone of modern digital ecosystems, protecting API access is paramount. Legacy methods like basic authentication and static API keys are no longer sufficient against advanced adversaries. This guide covers the cutting-edge of identity verification, from OpenID Connect (OIDC) to hardware-backed FIDO2 and synchronizable Passkeys, as well as sender-constrained tokens via DPoP and mTLS.

## Masterclass Chapters

1. **[OAuth2 & OIDC Fundamentals](./01-oauth2-oidc-fundamentals.md)**: The bedrock of modern identity.
2. **[JWT Security Masterclass](./02-jwt-security-best-practices.md)**: How to not mess up JSON Web Tokens.
3. **[DPoP (Demonstrating Proof-of-Possession)](./03-dpop-proof-of-possession.md)**: Sender-constrained tokens at the application layer.
4. **[Mutual TLS (mTLS)](./04-mtls-client-certificates.md)**: Sender-constrained tokens at the transport layer.
5. **[WebAuthn & FIDO2](./05-webauthn-and-fido2.md)**: Unphishable hardware authentication.
6. **[Passkeys](./06-passkeys-implementation.md)**: The passwordless future, synchronized.
7. **[Token Rotation & Lifecycle](./07-token-binding-and-rotation.md)**: Keeping sessions secure over time.

Each chapter follows our rigorous **4-Layer Pattern**:
1. **The Concept (ELI5)**: Explain it like I'm 5.
2. **The Visual**: Architectural blueprints via Mermaid.js.
3. **The Code**: ❌ Vulnerable vs ✅ Secure code in Go, Python, and TypeScript.
4. **The Guardrail**: CI/CD security constraints via Terraform, Semgrep, or Rego.
