---
title: 04 Reviewing Cryptography and Secrets
description: Cryptography is hard to get right. Reviewers must look for hardcoded
  secrets, weak algorithms, incorrect modes of operation, and insufficient randomne...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- 09
- Hands
- 'On'
- Code
- Review
- Guide
- '04'
- Reviewing
- Crypto
- And
- Secrets
- Md
slug: /hands-on/code-review-guide/reviewing-crypto-and-secrets
---


# 04 Reviewing Cryptography and Secrets

Cryptography is hard to get right. Reviewers must look for hardcoded secrets, weak algorithms, incorrect modes of operation, and insufficient randomness.

## 1. Hardcoded Secrets

**Context:** Passwords, API keys, and cryptographic keys should never be embedded in source code.

### Vulnerable Pattern (Python)
```python
import hmac

def verify_webhook(payload, signature):
    # BAD: Hardcoded secret key
    secret = b"super_secret_webhook_key_123"
    expected = hmac.new(secret, payload, digestmod="sha256").hexdigest()
    return hmac.compare_digest(expected, signature)
```

### Secure Pattern (Python)
```python
import hmac
import os

def verify_webhook(payload, signature):
    # GOOD: Load secret from environment variables or secret manager
    secret = os.environ.get("WEBHOOK_SECRET").encode('utf-8')
    expected = hmac.new(secret, payload, digestmod="sha256").hexdigest()
    return hmac.compare_digest(expected, signature)
```

## 2. Weak Cryptographic Modes (AES-ECB)

**Context:** Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical ciphertext blocks, revealing patterns.

### Vulnerable Pattern (Node.js)
```javascript
const crypto = require('crypto');

function encrypt(text, key) {
    // BAD: ECB mode does not use an Initialization Vector (IV) and leaks patterns
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}
```

### Secure Pattern (Node.js)
```javascript
const crypto = require('crypto');

function encrypt(text, key) {
    // GOOD: Use GCM (Galois/Counter Mode) for authenticated encryption
    const iv = crypto.randomBytes(12); // Generate a random IV
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    
    return { iv: iv.toString('hex'), ciphertext: encrypted, authTag: authTag };
}
```

## 3. Weak Random Number Generation

**Context:** Standard pseudo-random number generators (PRNGs) like Python's `random` module are predictable and must not be used for security purposes (like tokens or passwords).

### Vulnerable Pattern (Python)
```python
import random
import string

def generate_reset_token():
    # BAD: Predictable random generator
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))
```

### Secure Pattern (Python)
```python
import secrets
import string

def generate_reset_token():
    # GOOD: Cryptographically secure random generator
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(32))
```
