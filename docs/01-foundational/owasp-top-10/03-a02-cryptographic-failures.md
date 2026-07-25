---
title: "03. A02: Cryptographic Failures"
description: "Cryptographic Failures (formerly known as *Sensitive Data Exposure*) occur when applications store or transmit sensitive data (passwords, credit cards..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Owasp Top 10", "03 A02 Cryptographic Failures.Md"]
---

# 03. A02: Cryptographic Failures

Cryptographic Failures (formerly known as *Sensitive Data Exposure*) occur when applications store or transmit sensitive data (passwords, credit cards, PII, API tokens) in plaintext or use weak cryptographic algorithms.

---

## 1. Core Vulnerabilities in Cryptography

1. **Plaintext Transmission**: Sending passwords/tokens over unencrypted HTTP instead of HTTPS/TLS 1.3.
2. **Weak Password Hashing**: Using MD5, SHA1, or unsalted SHA256 for password storage (vulnerable to rainbow table & GPU cracking).
3. **Hardcoded Encryption Keys**: Placing secret keys in source code or version control repositories.
4. **Weak Cipher Modes**: Using AES in ECB mode (Electronic Codebook) which preserves structural patterns in encrypted data.

---

## 2. Code Examples & Secure Implementations

### Password Hashing (Argon2 / bcrypt)

#### ❌ Vulnerable Code (Python)
```python
import hashlib

# VULNERABLE: Fast hashing algorithms (MD5/SHA256) without memory-hardness or proper salt
def hash_password_bad(password: str) -> str:
    # Attacker can crack millions of these per second using GPUs!
    return hashlib.sha256(password.encode()).hexdigest()
```

#### ✅ Secure Code (Python - Argon2 / bcrypt)
```python
from argon2 import PasswordHasher
from passlib.hash import argon2

ph = PasswordHasher(
    time_cost=3,       # Iteration count
    memory_cost=65536, # 64MB RAM hardness
    parallelism=4
)

# SECURE: Memory-hard Argon2id algorithm
def hash_password_secure(password: str) -> str:
    return ph.hash(password)

def verify_password_secure(hash_str: str, password: str) -> bool:
    try:
        return ph.verify(hash_str, password)
    except Exception:
        return False
```

---

### Data Encryption at Rest (AES-256-GCM)

#### ❌ Vulnerable Code (Node.js - AES ECB Mode)
```javascript
const crypto = require('crypto');

// VULNERABLE: AES ECB mode does NOT use an IV. Identical inputs yield identical outputs!
function encryptBad(text, key) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
```

#### ✅ Secure Code (Node.js - AES-256-GCM Authenticated Encryption)
```javascript
const crypto = require('crypto');

// SECURE: AES-256-GCM with unique 12-byte IV and authentication tag
function encryptSecure(plaintext, masterKeyHex) {
  const key = Buffer.from(masterKeyHex, 'hex'); // 32 bytes key
  const iv = crypto.randomBytes(12); // Unique initialization vector per message
  
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  return {
    iv: iv.toString('hex'),
    ciphertext: encrypted,
    tag: authTag
  };
}
```

---

## 3. Secret Management & Hardcoding Prevention

### ❌ Never Hardcode Secrets in Source Code
```python
# VULNERABLE
DATABASE_URL = "postgres://admin:Password123!@db.internal:5432/prod"
JWT_SECRET = "supersecretkey123"
```

### ✅ Load Secrets from Environment / Secrets Manager
```python
import os
from dotenv import load_dotenv

load_dotenv()

# SECURE: Environment variables injected at runtime
DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError("FATAL: JWT_SECRET environment variable is not set!")
```

---

*Next Chapter: [04. A03: Injection (SQLi & Command Injection) →](04-a03-injection.md)*
