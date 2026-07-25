---
title: "01 - Introduction to Cryptography"
description: "Cryptography is the mathematical foundation of secure communication. In application security, developers use cryptography to ensure Confidentiality, I..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Cryptography", "01 Introduction.Md"]
---

# 01 - Introduction to Cryptography

Cryptography is the mathematical foundation of secure communication. In application security, developers use cryptography to ensure Confidentiality, Integrity, Authentication, and Non-repudiation (CIA+N).

> [!TIP]
> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.

## The Big Three: Encoding vs Hashing vs Encryption

One of the most common pitfalls is confusing these three distinct concepts:

### 1. Encoding
- **Purpose**: Transforms data into a new format for usability (e.g., transmitting binary over text-based protocols).
- **Security**: **NONE**. Reversible by anyone.
- **Examples**: Base64, URL Encoding, Hex (Base16).
- **Rule**: Never use encoding to protect sensitive data.

### 2. Hashing
- **Purpose**: One-way transformation of data to a fixed-size string. Validates integrity.
- **Security**: Irreversible (computationally infeasible to reverse).
- **Examples**: SHA-256, SHA-3, Argon2 (for passwords).
- **Rule**: Use for passwords (with salts/KDFs) and data integrity checks.

### 3. Encryption
- **Purpose**: Two-way transformation of data to maintain confidentiality. Requires a key.
- **Security**: Reversible only by those with the correct key.
- **Examples**: AES, ChaCha20, RSA.
- **Rule**: Use for data in transit and data at rest.

## Symmetric vs Asymmetric Cryptography

### Symmetric Cryptography
- **Mechanism**: The same key is used for both encryption and decryption.
- **Speed**: Very fast.
- **Use Case**: Encrypting large amounts of data (e.g., files, database records, streaming video).
- **Algorithms**: AES-256-GCM, ChaCha20-Poly1305.

### Asymmetric Cryptography
- **Mechanism**: Uses a key pair (Public Key for encryption/verification, Private Key for decryption/signing).
- **Speed**: Slow and computationally expensive.
- **Use Case**: Key exchange, digital signatures, identity verification (TLS).
- **Algorithms**: RSA, ECDSA, Ed25519.

## Common Cryptographic Pitfalls
1. **Rolling Your Own Crypto**: Never design your own cryptographic algorithms or protocols. Always use established, peer-reviewed libraries.
2. **Hardcoding Keys**: Keys must never be stored in source code. Use environment variables or Key Management Systems (KMS).
3. **Using Deprecated Algorithms**: MD5, SHA-1, DES, and 3DES are broken. Do not use them.
4. **Ignoring Initialization Vectors (IVs)**: Reusing IVs with stream ciphers (like ChaCha20) or counter modes (AES-CTR/GCM) completely destroys security.
5. **Lack of Authenticated Encryption**: Encrypting data without a Message Authentication Code (MAC) makes it vulnerable to tampering (e.g., Padding Oracle Attacks). Always use AEAD (Authenticated Encryption with Associated Data) like AES-GCM.
