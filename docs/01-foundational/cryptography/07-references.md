---
title: "07 - References and Security Standards"
description: "Authoritative references, RFC specifications, NIST/FIPS standards, CVE knowledge base of classic cryptographic vulnerabilities, recommended libraries, and SAST scanner rules."
keywords: ["AppSec", "Cryptography", "Security Standards", "NIST", "FIPS 203", "OWASP", "CVE Knowledge Base", "RFC 8446", "Semgrep"]
---

# 07 - References and Security Standards

This chapter provides a curated catalog of authoritative standards, RFC specifications, real-world CVE failure modes, production-grade cryptographic libraries, and automated security testing tooling.

---

## 📜 Key Standards & RFC Specifications

| Standard / RFC | Title / Subject | Focus Area |
| :--- | :--- | :--- |
| **NIST SP 800-57 Part 1** | Recommendation for Key Management | Key lifecycles, key storage, and key transition timelines |
| **NIST SP 800-63B** | Digital Identity Guidelines: Authentication | Password guidelines, KDF iteration thresholds |
| **FIPS 140-3** | Security Requirements for Cryptographic Modules | Hardware (HSM) and software cryptographic module validation |
| **FIPS 197** | Advanced Encryption Standard (AES) | Specification of the AES block cipher |
| **FIPS 203 / 204 / 205** | Post-Quantum Cryptography Standards | Official specifications for ML-KEM, ML-DSA, and SLH-DSA |
| **RFC 5869** | HMAC-based Extract-and-Expand Key Derivation (HKDF) | Standard protocol for session key derivation |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (EdDSA) | Specification of Ed25519 and Ed448 signature schemes |
| **RFC 8439** | ChaCha20 and Poly1305 for IETF Protocols | Specification of ChaCha20-Poly1305 AEAD |
| **RFC 8446** | The Transport Layer Security (TLS) Protocol Version 1.3 | Modern secure network transport specification |
| **OWASP Top 10 A02** | Cryptographic Failures | Primary web application cryptographic risk guidelines |

---

## ⚠️ CVE Knowledge Base: Notable Cryptographic Failures

Analyzing historical vulnerabilities highlights why protocol design and low-level code implementation require extreme caution:

| CVE / Event | Common Name | Vulnerability Type | Root Cause Analysis |
| :--- | :--- | :--- | :--- |
| **CVE-2014-0160** | **Heartbleed** | Memory Disclosure | Missing bounds check in OpenSSL TLS Heartbeat extension allowed remote attackers to read 64KB of server memory (leaking private keys and passwords). |
| **CVE-2014-3566** | **POODLE** | Padding Oracle Attack | SSL 3.0 fallback permitted adversaries to exploit CBC mode padding validation errors to decrypt HTTPS session cookies byte-by-byte. |
| **CVE-2020-0601** | **CurveBall** | Cert Validation Bypass | Windows `Crypt32.dll` failed to verify generator point parameters in ECC certificates, allowing attackers to forge arbitrary TLS certificate chains. |
| **CVE-2022-0778** | **OpenSSL DoS** | Infinite Loop | Parsing invalid explicit prime curve parameters in `BN_mod_sqrt()` triggered an infinite loop, allowing remote Denial of Service. |
| **2010 PS3 Leak** | **Sony PS3 Exploit** | Nonce Reuse | ECDSA signature implementation reused a fixed nonce `$k$`, allowing full algebraic derivation of Sony's master private key. |

---

## 🛠️ Production Cryptographic Libraries Matrix

| Language / Ecosystem | Standard Library / Approved Packages | Features & Recommendations |
| :--- | :--- | :--- |
| **Python** | `cryptography` (PyCA) | High-level `hazmat` primitives, AESGCM, Ed25519, HKDF. Avoid `PyCrypto` (abandoned). |
| **Node.js** | `crypto` (Built-in) / `sodium-native` | Native OpenSSL bindings, Web Crypto API support, Argon2 module. |
| **Go** | `crypto/*` (`crypto/cipher`, `crypto/ed25519`) | Robust standard library, constant-time assembly routines, `golang.org/x/crypto`. |
| **Java** | JCA (`javax.crypto`) / **BouncyCastle** | Native Ed25519 (Java 15+), BouncyCastle for FIPS 140-3 compliance & PQC support. |
| **Rust** | `ring` / `rustls` / `subtle` | Memory-safe cryptography, constant-time operations, panic-free parsing. |
| **C / C++** | **libsodium** / OpenSSL 3.x | High-level misuse-resistant libsodium (`crypto_secretbox`). Avoid raw cipher implementations. |

---

## 🔍 Automated Security Testing & SAST Tools

Integrating static analysis and secret scanning into CI/CD pipelines catches cryptographic flaws prior to production deployment:

### 1. Static Application Security Testing (SAST)
- **Semgrep Cryptography Ruleset**: Scans codebases for ECB mode usage, weak PRNGs (`random.random()`), broken hashes (MD5, SHA1), and hardcoded secrets.
  ```bash
  semgrep --config "p/security-audit" --config "p/ci"
  ```
- **Bandit (Python)**: Identifies insecure cryptographic imports (`import md5`, `random`) and low-bit RSA key generation.
  ```bash
  bandit -r ./src -sk B303,B304,B311
  ```

### 2. Secret & Key Scanning
- **TruffleHog**: Deep history scanner detecting high-entropy private keys, API tokens, and certificate keys in Git repositories.
  ```bash
  trufflehog git file://. --only-verified
  ```
- **Gitleaks**: Lightweight CI tool preventing key commits via pre-commit hooks.

### 3. TLS Transport Scanners
- **testssl.sh**: Command-line tool testing TLS endpoints for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), weak ciphers, and PFS support.
  ```bash
  ./testssl.sh --severity HIGH https://api.yourdomain.com
  ```
- **SSL Labs Server Test**: Automated evaluation of web gateway TLS configuration posture.

