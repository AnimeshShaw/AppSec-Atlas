---
title: "05 - Secure Software Publishing"
description: "Once your software is built securely, you must ensure it remains secure when delivered to your users."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Supply Chain Security", "05 Secure Software Publishing.Md"]
---

# 05 - Secure Software Publishing

Once your software is built securely, you must ensure it remains secure when delivered to your users.

## Publishing Signed Artifacts

If you publish packages to registries like npm or PyPI, or if you release binaries on GitHub, you need to prove that the artifact originated from you and wasn't tampered with.

### OIDC Integration for npm and PyPI
Historically, publishing packages required generating long-lived API tokens and storing them as secrets in GitHub Actions. If these tokens leaked, attackers could publish malicious versions of your packages.

Modern registries support **OpenID Connect (OIDC)**. Instead of long-lived passwords, GitHub Actions can request a short-lived token from the registry directly, cryptographically proving it is running a specific workflow on a specific repository.

**Example: PyPI Trusted Publishing via OIDC**
In your GitHub Actions workflow:
```yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write # Required for OIDC
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
```
*No hardcoded PyPI passwords required!*

## Sigstore / Cosign
[Sigstore](https://www.sigstore.dev/) is an open-source project that makes it easy for developers to sign software. It uses ephemeral keys tied to OIDC identities (like your GitHub or Google login) and logs all signatures to a public transparency log (Rekor).

**Cosign** is a tool within the Sigstore ecosystem for signing and verifying container images and other artifacts.

**Signing a container image with Cosign:**
```bash
cosign sign --key cosign.key my-repo/my-image:latest
```

**Keyless Signing (using OIDC in GitHub Actions):**
```bash
COSIGN_EXPERIMENTAL=1 cosign sign my-repo/my-image:latest
```
This binds the signature to the specific GitHub Action workflow that built the image, providing strong, verifiable provenance.

## GitHub Releases Security
When distributing binaries via GitHub Releases:
1. Generate an SBOM using Syft.
2. Generate provenance metadata using SLSA generators.
3. Sign the binaries using Cosign or GPG.
4. Upload the binaries, the SBOM, the provenance, and the signatures to the Release.

Users can then download the binary and verify its integrity against the signature and provenance before running it.
