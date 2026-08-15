---
sidebar_position: 1
title: "Supply Chain Security & SLSA"
---

# Software Supply Chain Security Masterclass

Welcome to the Software Supply Chain Security guide. In an era where attackers target the build pipelines, dependencies, and deployment mechanisms rather than the application itself, securing the software supply chain is paramount.

This sub-guide focuses on the **Supply-chain Levels for Software Artifacts (SLSA)** framework, specifically version 1.0, and practical implementations using tools like Sigstore, Cosign, and in-toto provenance.

## The Scope of the Problem
Modern software is rarely written from scratch. It is assembled from hundreds or thousands of open-source components, built in distributed CI/CD pipelines, and deployed across complex cloud environments. A compromise at any point—a hijacked npm package, a compromised CI runner, or an unauthenticated artifact registry—can lead to devastating consequences (e.g., SolarWinds, log4j).

## What We Will Cover
This masterclass is divided into 7 core chapters, each following our strict "4-Layer Pattern" (Concept, Visual, Code, Guardrail):

1. **Chapter 1: Understanding SLSA v1.0 Foundation** - Core principles of SLSA and why build integrity matters.
2. **Chapter 2: Dependency Confusion & Substitution Attacks** - Preventing attackers from hijacking private packages.
3. **Chapter 3: Typosquatting & Malicious Dependencies** - Defending against rogue open-source packages.
4. **Chapter 4: Build Integrity & Provenance (in-toto)** - Generating and verifying unforgeable build records.
5. **Chapter 5: Artifact Signing with Sigstore & Cosign** - Keyless signing and verifying container images and binaries.
6. **Chapter 6: Securing CI/CD Pipelines** - Hardening GitHub Actions, GitLab CI, and Jenkins.
7. **Chapter 7: SBOM Generation & Validation** - Creating, managing, and utilizing Software Bills of Materials.

Let's dive into Chapter 1 and start building an unbreakable software supply chain.
