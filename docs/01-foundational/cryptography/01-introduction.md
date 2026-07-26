---
title: 01 - Introduction to Cryptography
description: 'Master the foundational pillars of cryptography: CIA+N triad, Encoding
  vs Hashing vs Encryption comparison matrix, Symmetric vs Asymmetric primitives,
  and critical implementation anti-patterns.'
keywords:
- AppSec
- Cryptography
- CIA
- Triad
- Encoding
- vs
- Hashing
- vs
- Encryption
- CSPRNG
- Entropy
- Security
- Guarantees
slug: /foundational/cryptography/introduction
---


# 01 - Introduction to Cryptography

Cryptography is the mathematical foundation of digital trust. In modern software engineering, developers apply cryptographic mechanisms to guarantee four fundamental security properties, collectively known as **CIA+N**:

- **Confidentiality**: Ensuring that data remains unreadable to unauthorized observers during transit or storage.
- **Integrity**: Guaranteeing that data has not been modified, corrupted, or tampered with by adversaries.
- **Authentication**: Verifying the true identity of a communicating entity or the origin of a message.
- **Non-repudiation**: Preventing an author or sender from falsely denying the origination or contents of a signed message.

> [!TIP]
> **Developer Cryptography Toolkit:** Need an interactive online platform to test, verify, and experiment with encoding (Base64, Hex), ciphers (AES-256, RSA), password hashing (Argon2id, bcrypt), and key generation? Check out our developer security platform: [devcipher.dev](https://devcipher.dev/) · [GitHub Repo](https://github.com/AnimeshShaw/DevCipher).
>
> **Industry Standard:** Modern security frameworks (such as NIST SP 800-175B, OWASP Top 10 A02:2021 - Cryptographic Failures, and CIS Controls) mandate that cryptographic controls must be selected based on evaluated threat models and standardized primitives rather than custom implementations.

---

## 📊 The Core Taxonomy: Encoding vs Hashing vs Encryption vs Signatures

One of the most frequent anti-patterns in application engineering is conflating data representation with cryptographic protection. The table below provides an exact breakdown of these primitives:

| Category | Input / Output | Key Required? | Reversibility | Primary Security Goal | Standard Algorithms | Typical Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Encoding** | Data `\rightarrow` Formatted Data | ❌ No | ✅ Reversible (No secret) | Interoperability & Transport | Base64, Hex, URL-Encoding | Transmitting binary payloads over HTTP/JSON |
| **Cryptographic Hashing** | Arbitrary Data `\rightarrow` Fixed-Size Digest | ❌ No | ❌ One-Way (Irreversible) | Integrity Verification | SHA-256, SHA-3, BLAKE3 | File checksums, digital signatures |
| **Password Hashing (KDF)** | Password + Salt `\rightarrow` Slow Hash | ❌ No (Uses Salt) | ❌ One-Way (Computationally Hard) | Credential Protection | Argon2id, bcrypt, PBKDF2 | Storing user passwords securely |
| **Symmetric Encryption** | Plaintext `\leftrightarrow` Ciphertext | 🔑 Single Secret Key | ✅ Reversible with Key | Bulk Data Confidentiality | AES-256-GCM, ChaCha20-Poly1305 | Database column encryption, TLS payload |
| **Asymmetric Encryption** | Plaintext `\leftrightarrow` Ciphertext | 🔑 Public/Private Pair | ✅ Reversible with Private Key | Secret Key Distribution | RSA-OAEP, ECIES | Key encapsulation, secure boot |
| **Digital Signatures** | Message + Private Key `\rightarrow` Signature | 🔑 Public/Private Pair | ❌ One-Way Verification | Authenticity & Non-repudiation | Ed25519, RSA-PSS, ECDSA | JWT signing, software update verification |

---

## 🔄 Mechanism Visualizations

### 1. Data Encoding (No Security)
```
  [ Raw Data: 0x48656c6c6f ]  ====== Base64 Encode ======>  [ String: "SGVsbG8=" ]
  [ String: "SGVsbG8=" ]        ====== Base64 Decode ======>  [ Raw Data: 0x48656c6c6f ]
```

### 2. Cryptographic Hashing (Integrity)
```
  [ Document V1 ]  ====== SHA-256 ======>  [ Digest: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e ]
  [ Document V2 ]  ====== SHA-256 ======>  [ Digest: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069 ]
```

### 3. Symmetric AEAD Encryption (Confidentiality + Integrity)
```
  [ Plaintext ] + [ Secret Key ] + [ Nonce ] + [ Associated Data ]
                            |
                     AES-256-GCM Encrypt
                            |
                            v
            [ Ciphertext ] + [ Authentication Tag ]
```

---

## 🔑 Symmetric vs Asymmetric Cryptography

```
+-----------------------------------------------------------------------------------------------+
|                                    SYMMETRIC CRYPTOGRAPHY                                     |
+-----------------------------------------------------------------------------------------------+
| Alice [Secret Key K] -------------- Encrypted Channel ---------------> Bob [Secret Key K]     |
| - Fast execution (Hardware AES-NI instructions).                                              |
| - Challenge: Securely sharing Secret Key K out-of-band.                                       |
+-----------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------+
|                                   ASYMMETRIC CRYPTOGRAPHY                                     |
+-----------------------------------------------------------------------------------------------+
| Alice [Bob's Public Key] -------- Encrypted Channel -----------> Bob [Bob's Private Key]      |
| - Public Key is published openly; Private Key is strictly secret.                             |
| - Slow execution (heavy modular exponentiation or elliptic curve multiplication).             |
| - Enables key exchange (ECDHE) and digital signatures without prior shared secrets.           |
+-----------------------------------------------------------------------------------------------+
```

### Security Level Equivalency Matrix

To achieve a target security level (measured in bits of computational work required for a brute-force attack), algorithm key sizes must match the required resistance:

| Target Security Level | Symmetric Cipher | Hash Function | RSA Key Size | Elliptic Curve (ECC) | Post-Quantum Equivalent |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **128 bits** (Standard) | AES-128 | SHA-256 | RSA-3072 | P-256 / Ed25519 | ML-KEM-512 / ML-DSA-44 |
| **192 bits** (High) | AES-192 | SHA-384 | RSA-7680 | P-384 | ML-KEM-768 / ML-DSA-65 |
| **256 bits** (Quantum-Safe) | AES-256 | SHA-512 / SHA-3 | RSA-15360 | P-521 | ML-KEM-1024 / ML-DSA-87 |

> [!WARNING]
> RSA keys smaller than 2048 bits are **insecure** and must be deprecated immediately. RSA-2048 provides approximately 112 bits of security and should be migrated to ECC (Ed25519 / P-256) or AES-256-GCM.

---

## ⚠️ The Threat Landscape: 5 Critical Cryptographic Anti-Patterns

### 1. Pseudo-Random Number Generator (PRNG) Predictability
Developers often use standard random number generators for security tokens, keys, or nonces. Standard functions (like Python's `random` or JavaScript's `Math.random()`) use deterministic PRNG algorithms (e.g., Mersenne Twister) whose state can be fully reconstructed after observing a small sample of outputs.

```python
# ❌ VULNERABLE: Deterministic PRNG allows token prediction
import random
session_token = hex(random.getrandbits(128))

# ✅ SECURE: Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
import secrets
secure_token = secrets.token_hex(16) # Reads from OS entropy pool (/dev/urandom or BCryptGenRandom)
```

### 2. Hardcoded Keys & Insecure Storage
Storing cryptographic keys inside application source code, configuration files, or Git repositories exposes them to leakages via version control history, reverse engineering, or container inspections.

```javascript
// ❌ VULNERABLE: Hardcoded encryption key
const key = Buffer.from("super_secret_key_1234567890123456");

// ✅ SECURE: Key loaded from environment variable or KMS hardware security module (HSM)
const keyHex = process.env.APP_ENCRYPTION_KEY;
if (!keyHex || keyHex.length !== 64) {
  throw new Error("FATAL: Invalid or missing 256-bit encryption key in environment.");
}
const key = Buffer.from(keyHex, 'hex');
```

### 3. Deprecated & Broken Algorithms
Using legacy algorithms that have known collision or cryptanalytic attacks:

- **MD5**: Broken by collision attacks (Flame malware, Rogue CA certificates). Never use for integrity or signatures.
- **SHA-1**: Broken by SHAttered (2017) and Shambles (2020) collisions.
- **DES / 3DES**: Small 64-bit block size vulnerable to Sweet32 Birthday attacks.
- **RC4**: Biased keystream outputs allow plaintext recovery in TLS.

### 4. Nonce / Initialization Vector (IV) Reuse
In stream ciphers and counter modes (AES-GCM, ChaCha20, AES-CTR), reusing an IV with the same key allows adversaries to XOR two ciphertexts to cancel out the keystream:
```math
C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2
```
This destroys confidentiality completely and allows forgery of authentication tags.

### 5. Encrypting Without Authentication (Unauthenticated Ciphertext)
Encrypting data without a Message Authentication Code (MAC) or using unauthenticated modes (AES-CBC without HMAC) leaves application endpoints vulnerable to **Padding Oracle Attacks** and **Bit-Flipping Attacks**, where an adversary modifies ciphertext bytes to alter plaintext values without knowing the key.

---

> [!CAUTION]
> **Kerckhoffs's Principle:** A cryptographic system must remain secure even if everything about the system—except the secret key—is public knowledge. Security through obscurity (hiding algorithm details or using proprietary custom encryption) always fails under scrutiny.

