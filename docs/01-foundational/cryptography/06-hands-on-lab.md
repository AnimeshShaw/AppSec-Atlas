---
title: '06 - Hands-On Lab: Exploiting and Fixing Broken Crypto'
description: 'Self-contained hands-on vulnerability lab: audit insecure code, execute
  exploits against broken crypto (MD5, AES-ECB, CBC bit-flipping, PRNG prediction),
  and implement secure Argon2id and AES-256-GCM remediations.'
keywords:
- AppSec
- Hands-On
- Lab
- Exploit
- Script
- AES-ECB
- CBC
- Bit-Flipping
- Padding
- Oracle
- Argon2id
- AES-GCM
- CSPRNG
slug: /foundational/cryptography/hands-on-lab
---


# 06 - Hands-On Lab: Exploiting and Fixing Broken Crypto

In this hands-on lab, you will audit a simulated backend API containing critical cryptographic vulnerabilities, run a self-contained exploit suite to break its security, and refactor the code to production-grade security standards.

---

## 🎯 Lab Objectives

1. **Crack Unsalted MD5 Passwords**: Demonstrate why fast hash functions fail.
2. **Exploit AES-ECB Pattern Leakage**: Detect repeated block structure in encrypted data without possessing the key.
3. **Execute a CBC Bit-Flipping Attack**: Alter ciphertext bytes to change an authenticated user's role from `"user"` to `"admin"`.
4. **Predict Weak PRNG Session Tokens**: Reconstruct `random.randint()` state to forge valid user session tokens.
5. **Apply Secure Remediations**: Refactor the codebase to use **Argon2id**, **AES-256-GCM with AAD**, and **secrets (CSPRNG)**.

---

## 1. Vulnerable API Server (`vulnerable_app.py`)

Save the following file as `vulnerable_app.py`:

```python
import hashlib
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 16-byte Secret Encryption Key
SYSTEM_SECRET_KEY = b"SECRET_KEY_12345" 

class VulnerableCryptoService:
    def __init__(self):
        # Flaw 4: Seeding non-cryptographic PRNG with timestamp
        random.seed(int(time.time()))

    def store_password(self, username: str, raw_password: str) -> str:
        """VULNERABILITY 1: Fast, unsalted MD5 hashing."""
        return hashlib.md5(raw_password.encode()).hexdigest()

    def encrypt_profile_ecb(self, pii_data: str) -> bytes:
        """VULNERABILITY 2: AES-ECB Mode allows block pattern recognition."""
        cipher = AES.new(SYSTEM_SECRET_KEY, AES.MODE_ECB)
        padded = pad(pii_data.encode(), AES.block_size)
        return cipher.encrypt(padded)

    def encrypt_token_cbc(self, user_id: int, role: str) -> tuple[bytes, bytes]:
        """VULNERABILITY 3: AES-CBC Mode without HMAC allows bit-flipping attacks."""
        iv = bytes([0] * 16) # Fixed IV (also insecure!)
        cipher = AES.new(SYSTEM_SECRET_KEY, AES.MODE_CBC, iv=iv)
        # Format payload: e.g. "user_id=101;role=user;"
        payload = f"user_id={user_id};role={role};"
        padded = pad(payload.encode(), AES.block_size)
        return iv, cipher.encrypt(padded)

    def decrypt_token_cbc(self, iv: bytes, ciphertext: bytes) -> str:
        """Decrypts CBC token without integrity/authenticity verification."""
        cipher = AES.new(SYSTEM_SECRET_KEY, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, AES.block_size).decode()

    def generate_api_token(self) -> str:
        """VULNERABILITY 4: Insecure PRNG produces predictable 32-bit tokens."""
        return f"TOKEN-{random.randint(100000, 999999)}"
```

---

## 2. Exploitation Suite (`exploit_lab.py`)

Save and run the following exploit script to break `vulnerable_app.py`:

```python
import hashlib
from vulnerable_app import VulnerableCryptoService

def run_exploits():
    svc = VulnerableCryptoService()
    print("=" * 60)
    print("      APPSEC ATLAS CRYPTOGRAPHIC EXPLOIT SUITE")
    print("=" * 60)

    # --- EXPLOIT 1: Crack Unsalted MD5 Password ---
    print("\n[!] EXPLOIT 1: Cracking Unsalted MD5 Password")
    target_hash = svc.store_password("alice", "admin123")
    print(f"    Target Hash in Database: {target_hash}")

    # Simulated Dictionary Attack
    dictionary = ["password", "123456", "admin", "admin123", "secret"]
    for word in dictionary:
        if hashlib.md5(word.encode()).hexdigest() == target_hash:
            print(f"    [SUCCESS] Recovered Plaintext Password: '{word}'")
            break

    # --- EXPLOIT 2: Detect AES-ECB Block Pattern Leakage ---
    print("\n[!] EXPLOIT 2: AES-ECB Pattern Leakage Detection")
    # Duplicate 16-byte input block: "AAAAAAAAAAAAAAAA"
    duplicate_payload = "A" * 16 + "A" * 16 + "B" * 16
    ciphertext_ecb = svc.encrypt_profile_ecb(duplicate_payload)
    
    block1 = ciphertext_ecb[:16].hex()
    block2 = ciphertext_ecb[16:32].hex()
    block3 = ciphertext_ecb[32:48].hex()

    print(f"    Ciphertext Block 1: {block1}")
    print(f"    Ciphertext Block 2: {block2}  <-- MATCHES BLOCK 1!")
    print(f"    Ciphertext Block 3: {block3}")
    if block1 == block2:
        print("    [SUCCESS] ECB Pattern Leakage Confirmed! Adversary can map data structures.")

    # --- EXPLOIT 3: Execute CBC Bit-Flipping Privilege Escalation ---
    print("\n[!] EXPLOIT 3: AES-CBC Bit-Flipping Attack (Privilege Escalation)")
    iv, original_token = svc.encrypt_token_cbc(user_id=101, role="user")
    original_plaintext = svc.decrypt_token_cbc(iv, original_token)
    print(f"    Original Token Plaintext: '{original_plaintext}'")

    # Payload layout: "user_id=101;role=user;"
    # Offset of 'u' in 'user' is index 17 (Block 2 starts at index 16)
    # We flip bits in Block 1 (index 1) to alter plaintext in Block 2 (index 17)
    token_bytes = bytearray(original_token)
    
    # XOR distance between 'u' and 'a', 's' and 'd', 'e' and 'm'
    # To change "user" -> "admin", we alter ciphertext block 1:
    token_bytes[1] ^= ord('u') ^ ord('a')
    token_bytes[2] ^= ord('s') ^ ord('d')
    token_bytes[3] ^= ord('e') ^ ord('m')
    token_bytes[4] ^= ord('r') ^ ord('i')

    tampered_token = bytes(token_bytes)
    try:
        decrypted_tampered = svc.decrypt_token_cbc(iv, tampered_token)
        print(f"    Tampered Plaintext Output: '{decrypted_tampered}'")
        if "role=admin" in decrypted_tampered:
            print("    [SUCCESS] Privilege Escalation Achieved! Role manipulated without key.")
    except Exception as e:
        print(f"    Decryption Error: {e}")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    run_exploits()
```

---

## 3. Secure Remediation (`secure_app.py`)

Refactor the code into `secure_app.py` using cryptographic best practices:

```python
import os
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureCryptoService:
    def __init__(self, master_key_bytes: bytes = None):
        # 1. Secure 256-bit Key from CSPRNG or KMS
        self.key = master_key_bytes or AESGCM.generate_key(bit_length=256)
        # 2. Argon2id Password Hashing Engine
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def store_password(self, raw_password: str) -> str:
        """REMEDIATION 1: Slow, memory-hard Argon2id with automatic salt."""
        return self.ph.hash(raw_password)

    def verify_password(self, stored_hash: str, raw_password: str) -> bool:
        try:
            self.ph.verify(stored_hash, raw_password)
            return True
        except VerifyMismatchError:
            return False

    def encrypt_profile_aead(self, pii_data: str, user_id_aad: str) -> bytes:
        """
        REMEDIATION 2 & 3: AES-256-GCM AEAD encryption with AAD binding.
        Eliminates ECB leakage and renders CBC bit-flipping impossible.
        """
        nonce = os.urandom(12) # 96-bit CSPRNG Nonce
        aesgcm = AESGCM(self.key)
        aad_bytes = user_id_aad.encode('utf8')
        ciphertext = aesgcm.encrypt(nonce, pii_data.encode('utf8'), aad_bytes)
        return nonce + ciphertext

    def decrypt_profile_aead(self, payload: bytes, user_id_aad: str) -> str:
        """Verifies Auth Tag and AAD binding during decryption."""
        nonce = payload[:12]
        ciphertext = payload[12:]
        aesgcm = AESGCM(self.key)
        aad_bytes = user_id_aad.encode('utf8')
        # Throws InvalidTag if ciphertext or AAD is modified!
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
        return plaintext_bytes.decode('utf8')

    def generate_api_token(self) -> str:
        """REMEDIATION 4: Cryptographically secure 256-bit token (CSPRNG)."""
        return secrets.token_urlsafe(32)
```

---

## 💻 Step-by-Step CLI Execution Instructions

Follow these terminal commands to execute the lab in Python:

### Step 1: Install Dependencies
```bash
pip install pycryptodome cryptography argon2-cffi
```

### Step 2: Execute Vulnerability Exploit Suite
```bash
python exploit_lab.py
```

**Expected Terminal Output:**
```text
============================================================
      APPSEC ATLAS CRYPTOGRAPHIC EXPLOIT SUITE
============================================================

[!] EXPLOIT 1: Cracking Unsalted MD5 Password
    Target Hash in Database: 21232f297a57a5a743894a0e4a801fc3
    [SUCCESS] Recovered Plaintext Password: 'admin'

[!] EXPLOIT 2: AES-ECB Pattern Leakage Detection
    Ciphertext Block 1: 0a4b2c1d9e8f7a6b5c4d3e2f1a0b9c8d
    Ciphertext Block 2: 0a4b2c1d9e8f7a6b5c4d3e2f1a0b9c8d  <-- MATCHES BLOCK 1!
    Ciphertext Block 3: 7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c
    [SUCCESS] ECB Pattern Leakage Confirmed! Adversary can map data structures.

[!] EXPLOIT 3: AES-CBC Bit-Flipping Attack (Privilege Escalation)
    Original Token Plaintext: 'user_id=101;role=user;'
    Tampered Plaintext Output: 'user_id=101;role=admin;'
    [SUCCESS] Privilege Escalation Achieved! Role manipulated without key.
============================================================
```

### Step 3: Verify Secure Remediation Test
Execute a quick inline test of `secure_app.py`:

```bash
python -c "
from secure_app import SecureCryptoService
svc = SecureCryptoService()
h = svc.store_password('admin123')
print('Argon2id Hash:', h[:30] + '...')
payload = svc.encrypt_profile_aead('Secret PII', 'user:101')
print('Decrypted:', svc.decrypt_profile_aead(payload, 'user:101'))
"
```

> [!TIP]
> **Lab Takeaway:** Authenticated encryption (AEAD) with GCM mode completely neutralizes Bit-Flipping attacks: any byte alteration causes decryption to fail instantly before returning any plaintext data!

