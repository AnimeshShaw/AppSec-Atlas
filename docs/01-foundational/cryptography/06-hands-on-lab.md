---
title: "06 - Hands-On Lab: Exploiting and Fixing Broken Crypto"
description: "In this lab, we will analyze an application that uses insecure cryptographic practices, see why it's broken, and then fix it."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Cryptography", "06 Hands On Lab.Md"]
---

# 06 - Hands-On Lab: Exploiting and Fixing Broken Crypto

In this lab, we will analyze an application that uses insecure cryptographic practices, see why it's broken, and then fix it.

## The Vulnerable Application

This snippet simulates storing a user password using a weak hash and encrypting sensitive data using AES-ECB mode.

### `vulnerable_app.py`
```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

SECRET_KEY = b'YELLOW SUBMARINE' # 16 bytes

def store_password_insecure(password: str) -> str:
    # VULNERABILITY: Using fast, unsalted MD5
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data_insecure(plaintext: str) -> bytes:
    # VULNERABILITY: Using ECB mode
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded_data = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded_data)

# Demonstration
print("Stored Hash:", store_password_insecure("password123"))

# Notice how identical blocks produce identical ciphertext
data = "A" * 16 + "A" * 16 
print("Encrypted ECB:", encrypt_data_insecure(data).hex())
```

## The Exploit / Why it Fails

1. **MD5 Hashing**: The hash `5f4dcc3b5aa765d61d8327deb882cf99` is immediately crackable via rainbow tables (it's "password123"). Lack of salt means identical passwords share the same hash.
2. **AES-ECB**: If you encrypt 32 bytes of 'A', the ciphertext output is `5a2b1f137afbc0e998e1694f2764f620 5a2b1f137afbc0e998e1694f2764f620...` (first 16 bytes exactly match the next 16). Attackers can infer plaintext structure without the key.

## The Secure Remediation

We will replace MD5 with Argon2id and replace AES-ECB with AES-GCM.

### `secure_app.py`
```python
import os
from argon2 import PasswordHasher
from Crypto.Cipher import AES

# AES-256 requires a 32-byte key
SECRET_KEY = os.urandom(32) 
ph = PasswordHasher()

def store_password_secure(password: str) -> str:
    # Secure KDF, automatically salts and uses Argon2id
    return ph.hash(password)

def encrypt_data_secure(plaintext: str) -> tuple:
    # Secure AES-GCM with a random Nonce
    cipher = AES.new(SECRET_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, tag, ciphertext

def decrypt_data_secure(nonce: bytes, tag: bytes, ciphertext: bytes) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
    try:
        # Decrypts and authenticates integrity simultaneously
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        return "Authentication Failed: Data was tampered with!"

# Demonstration
secure_hash = store_password_secure("password123")
print("Secure Hash:", secure_hash)

data = "A" * 16 + "A" * 16
nonce, tag, ciphertext = encrypt_data_secure(data)
print("Encrypted GCM:", ciphertext.hex())

# Notice the ciphertext for the two identical blocks is entirely different now.
decrypted = decrypt_data_secure(nonce, tag, ciphertext)
print("Decrypted:", decrypted)
```
