---
sidebar_position: 1
title: Confidential Computing
---

# Confidential Computing Masterclass

Welcome to the definitive, engineering-focused guide to **Confidential Computing**. 

Traditionally, security models have focused on data in two states:
1. **Data at Rest**: Encrypted on disks, databases, and buckets.
2. **Data in Transit**: Encrypted over the network using TLS/mTLS.

But what happens when data is actively being processed in CPU and memory? Historically, **Data in Use** was left unprotected from the underlying infrastructure. If a threat actor (or a malicious cloud administrator) compromised the host OS or hypervisor, they could dump the RAM and extract plaintext PII, encryption keys, and proprietary algorithms.

Confidential Computing solves this by leveraging hardware-based **Trusted Execution Environments (TEEs)**. 

## The Masterclass Roadmap

This guide is structured into 7 deep-dive chapters, strictly following the **4-Layer Pattern** (Concept, Visual, Code, Guardrail):

- **01: Introduction to TEEs**: The foundational concepts, boundaries, and mechanics of Secure Enclaves.
- **02: AWS Nitro Enclaves**: Deep dive into Amazon's EC2-based TEEs, vsock communication, and KMS integrations.
- **03: Intel TDX (Trust Domain Extensions)**: Exploring Intel's VM-level isolation and hardware-backed memory encryption.
- **04: AMD SEV-SNP**: Understanding Secure Encrypted Virtualization and Secure Nested Paging for full VM memory encryption.
- **05: Cryptographic Attestation**: The exact cryptographic mechanisms used to prove to a third party that your enclave is genuine, untampered, and running the correct code.
- **06: Secure Multi-Party Computation (SMPC)**: How to process joint datasets from zero-trust parties without exposing the raw data to either side.
- **07: Threat Modeling and Side-Channels**: Real-world limitations of TEEs, side-channel attacks (like CPU cache timing), and how to build defense-in-depth.

Prepare to dive into hardware-level security, cryptographic proofs, and production-ready code.
