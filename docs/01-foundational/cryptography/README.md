---
title: Cryptography for Developers
description: Master foundational and advanced cryptography for modern application
  security. Learn AEAD encryption, secure digital signatures, password hashing KDFs,
  and Post-Quantum Cryptography transition.
keywords:
- AppSec
- Cybersecurity
- Cryptography
- AES-GCM
- Argon2
- Ed25519
- Post-Quantum
- Cryptography
- AEAD
- Key
- Derivation
- TLS
- '1'
- '3'
slug: /foundational/cryptography
---


# Cryptography for Developers

Welcome to the **AppSec Atlas Cryptography for Developers** reference guide. Cryptography is the core mathematical foundation of application security. When implemented correctly, it protects confidentiality, guarantees data integrity, proves authenticity, and provides non-repudiation. However, cryptographic flaws are often catastrophic, subtle, and irreversible once exploited.

This guide bridges the gap between theoretical cryptanalysis and practical engineering, providing production-ready code, explicit implementation patterns, failure mode analyses, and step-by-step remediation labs.

---

## 🗺️ Cryptography Architecture & Flow

```
                      +-------------------------------------------------------+
                      |               APPLICATION DATA PIPELINE               |
                      +-------------------------------------------------------+
                                                  |
           +--------------------------------------+--------------------------------------+
           |                                      |                                      |
           v                                      v                                      v
  +------------------+                   +------------------+                   +------------------+
  | Data In Transit  |                   |   Data At Rest   |                   | Identity & Auth  |
  +------------------+                   +------------------+                   +------------------+
  | - TLS 1.3        |                   | - AES-256-GCM    |                   | - Argon2id (KDF) |
  | - ECDHE Exchange |                   | - ChaCha20-Poly  |                   | - Ed25519 Sign   |
  | - Hybrid PQC     |                   | - Envelope Key   |                   | - HKDF Key Deriv |
  +------------------+                   +------------------+                   +------------------+
```

---

## 📚 Guide Map & Topics Covered

| Chapter | Title | Primary Focus | Key Algorithms & Protocols | Threat Vectors Addressed |
| :--- | :--- | :--- | :--- | :--- |
| **01** | [Introduction to Cryptography](01-introduction.md) | CIA+N Triad, Encoding vs Hashing vs Encryption | Base64, SHA-256, AES, RSA, Ed25519 | Misconception of Base64 security, PRNG predictability |
| **02** | [Symmetric Encryption](02-symmetric-encryption.md) | AEAD Modes, AAD binding, Nonce uniqueness | AES-256-GCM, ChaCha20-Poly1305 | ECB pattern leakage, Padding Oracles, Nonce reuse |
| **03** | [Asymmetric Crypto & Signatures](03-asymmetric-encryption-and-signatures.md) | Public-key math, Signatures, Key Exchange | RSA-4096, Ed25519, ECDHE (X25519), TLS 1.3 | RSA PKCS#1 v1.5 malleability, ECDSA nonce leaks |
| **04** | [Password Hashing & KDFs](04-password-hashing-and-kdf.md) | Slow memory-hard hashing, Key derivation | Argon2id, bcrypt, PBKDF2-HMAC-SHA256, HKDF | GPU/ASIC brute-force, Rainbow tables, Side-channels |
| **05** | [Post-Quantum Cryptography](05-post-quantum-cryptography.md) | Quantum threat models, NIST standards | ML-KEM (FIPS 203), ML-DSA (FIPS 204), Hybrid | Shor's Algorithm (RSA break), Grover's Algorithm (AES decay), HNDL |
| **06** | [Hands-On Vulnerability Lab](06-hands-on-lab.md) | Practical exploit execution & remediation | MD5 vs Argon2id, AES-ECB vs AES-GCM | Padding Oracle, ECB pattern leakage, Hash cracking |
| **07** | [References & Security Standards](07-references.md) | NIST, OWASP, FIPS & CVE Knowledge Base | FIPS 140-3, NIST SP 800-57, RFC 8446 | Historical vulnerabilities (Heartbleed, POODLE, CurveBall) |

---

## 🎯 Learning Objectives

By working through this guide, software engineers and application security specialists will be able to:

1. **Differentiate Fundamentals**: Distinguish between data encoding, cryptographic hashing, symmetric encryption, and asymmetric signatures.
2. **Implement AEAD Encryption**: Construct robust AES-GCM and ChaCha20-Poly1305 encryption routines with random Nonce generation and Associated Authenticated Data (AAD) across Python, Node.js, Go, and Java.
3. **Master Key Derivation**: Configure memory-hard Password Hashing Functions (Argon2id) with optimal time, memory, and parallelism parameters, and derive session keys using HKDF.
4. **Deploy Asymmetric Authentication**: Generate Ed25519 key pairs, produce/verify digital signatures, and execute ECDHE key exchanges with forward secrecy.
5. **Prepare for Post-Quantum Cryptography (PQC)**: Understand the mechanics of Shor's and Grover's algorithms, evaluate NIST FIPS 203/204/205 standards, and design hybrid classical-quantum key exchange mechanisms.
6. **Detect & Fix Cryptographic Vulnerabilities**: Audit source code for insecure primitives (MD5, SHA1, DES, ECB mode, weak CSPRNGs) and execute hands-on exploits against broken implementations.

---

## 📋 Prerequisites

To get the maximum value from this guide, developers should possess:

- **Programming Experience**: Working knowledge of at least one major language (Python 3.10+, Node.js 18+, Go 1.20+, or Java 17+).
- **Basic Data Representation**: Understanding of binary byte arrays, Hexadecimal encoding, and Base64 string representations.
- **CLI & Security Tools**: Access to a Unix/Windows command line with Python 3, `pip`, OpenSSL, and basic Git utilities installed.

---

> [!IMPORTANT]
> **Golden Rule of Cryptography:** *Never design or implement your own custom cryptographic algorithms or protocols ("Don't Roll Your Own Crypto"). Always rely on standard, peer-reviewed, high-level cryptography libraries like PyCA Cryptography, Node `crypto` / Web Crypto API, Go `crypto/*`, or libsodium.*

---

## 🔗 Chapter Navigation

1. 📖 **[01 - Introduction to Cryptography](01-introduction.md)**
2. 🔒 **[02 - Symmetric Encryption](02-symmetric-encryption.md)**
3. 🔑 **[03 - Asymmetric Encryption and Signatures](03-asymmetric-encryption-and-signatures.md)**
4. 🛡️ **[04 - Password Hashing and KDF](04-password-hashing-and-kdf.md)**
5. ⚛️ **[05 - Post-Quantum Cryptography](05-post-quantum-cryptography.md)**
6. 🧪 **[06 - Hands-On Vulnerability Lab](06-hands-on-lab.md)**
7. 📚 **[07 - References and Security Standards](07-references.md)**

