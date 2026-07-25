---
title: "03 - Dependency Pinning and Provenance"
description: "A critical practice in securing your software supply chain is ensuring that builds are reproducible. If `npm install` installs different sub-dependenc..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Supply Chain Security", "03 Dependency Pinning And Provenance.Md"]
---

# 03 - Dependency Pinning and Provenance

## Lockfile Hardening

A critical practice in securing your software supply chain is ensuring that builds are reproducible. If `npm install` installs different sub-dependencies today than it did yesterday, your application's behavior and security posture are unpredictable.

Lockfiles (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `Cargo.lock`) store the exact versions and integrity hashes of all installed dependencies.

### Best Practices for Lockfiles:
1. **Always commit lockfiles to version control.**
2. **Enforce deterministic builds.** In CI/CD pipelines, ensure the package manager fails if the lockfile is out of sync with the manifest, and doesn't update the lockfile automatically.

**NPM:**
Use `npm ci` (clean install) instead of `npm install` in your CI pipelines. `npm ci` bypasses `package.json` to install modules directly from the lockfile and throws an error if they are out of sync.
```bash
# Good CI practice
npm ci
```

**Python (pip):**
Use `pip-tools` or `Poetry` to manage lockfiles.
```bash
# Using pip-tools to generate requirements.txt with hashes
pip-compile --generate-hashes
pip install --require-hashes -r requirements.txt
```

**Rust (Cargo):**
Cargo always uses `Cargo.lock` by default. In CI, you can enforce that the lockfile is up-to-date:
```bash
cargo build --locked
```

## In-Toto Provenance Attestations

Provenance answers the question: *How was this software built, and what inputs were used?*

[in-toto](https://in-toto.io/) is a framework to secure the integrity of software supply chains. It allows you to create attestations—cryptographically signed metadata about the steps performed in the software supply chain.

An in-toto attestation consists of a statement with a `predicateType` (like SLSA Provenance).

**Example SLSA Provenance Payload:**
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{"name": "my-app.tar.gz", "digest": {"sha256": "..."}}],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": { "id": "https://github.com/Attestations/GitHubActions" },
    "buildType": "https://github.com/Attestations/GitHubActionsWorkflow",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/my-org/my-repo@refs/heads/main",
        "digest": {"sha1": "..."}
      }
    }
  }
}
```
Consumers can use tools to verify this attestation before running the software.
