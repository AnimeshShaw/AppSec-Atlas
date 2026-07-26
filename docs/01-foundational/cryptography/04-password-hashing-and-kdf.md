---
title: 04 - Password Hashing and Key Derivation Functions (KDFs)
description: Master password hashing with Argon2id, bcrypt, and PBKDF2. Learn GPU
  brute-force mechanics, Salt vs Pepper architecture, memory-hard parameters, and
  HKDF key derivation.
keywords:
- AppSec
- Cryptography
- Password
- Hashing
- Argon2id
- bcrypt
- PBKDF2
- Salt
- Pepper
- HKDF
- Key
- Derivation
- GPU
- Cracking
slug: /foundational/cryptography/password-hashing-and-kdf
---


# 04 - Password Hashing and Key Derivation Functions (KDFs)

Standard cryptographic hash functions (such as SHA-256 or SHA-512) are designed to be mathematically fast for data integrity checks. However, this speed makes them **catastrophically insecure for password storage**. 

Modern consumer GPUs (like an NVIDIA RTX 4090) can compute over **200 Billion SHA-256 hashes per second** using cracking tools like Hashcat. An attacker possessing a leaked database of SHA-256 password hashes can crack standard 8-character passwords in minutes via dictionary attacks and precomputed rainbow tables.

To securely store passwords or derive encryption keys from passphrases, applications must use **Key Derivation Functions (KDFs)** specifically engineered to be slow and memory-hard.

---

## 📊 KDF Comparison Matrix

| KDF Algorithm | Memory Hardness | GPU / ASIC Resistance | Side-Channel Resistance | OWASP / NIST Recommendation | Recommended Work Factor |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Argon2id** | **High** (Configurable RAM) | **Maximum** | **Maximum** (Hybrid mode) | **#1 Primary Choice** (OWASP 2023) | `m=64 MB`, `t=3`, `p=4` |
| **bcrypt** | Low (~4 KB) | Moderate | High | **#2 Acceptable Legacy** | Work factor / Cost >= 12 (Target ~250ms) |
| **scrypt** | High (Configurable RAM) | High | Vulnerable to Cache-Timing | Acceptable | `N=2^17, r=8, p=1` (128 MB) |
| **PBKDF2-HMAC-SHA256** | **None** (0 KB RAM) | **Poor** (ASIC vulnerable) | High | Legacy / FIPS 140-2 Mandates Only | >= 600,000 Iterations (NIST SP 800-63B) |
| **MD5 / SHA-1 / SHA-256** | None | **Zero Resistance** | N/A | ❌ **FORBIDDEN** | N/A |

---

## 🏗️ Password Security Architecture: Salt vs Pepper vs KDF

```
  User Password --------------------+
                                    |
  CSPRNG Unique Salt (per user) ----+----> [ Argon2id KDF Engine ] ----> [ Stored Hash String ]
  (Stored in Database)              |          (Memory: 64MB)                 (Database)
                                    |
  System Secret Pepper (HSM/KMS) ---+
  (NOT stored in DB)
```

### 1. Cryptographic Salt (Public, Unique Per User)
- **Purpose**: A unique 16-byte random string generated via CSPRNG for every user registration.
- **Defeats**: Precomputed Rainbow Tables and cross-user hash lookup attacks (ensuring identical passwords yield completely distinct hashes).
- **Storage**: Stored alongside the hash in the database.

### 2. Cryptographic Pepper (Secret, Server-Side)
- **Purpose**: A high-entropy 256-bit secret key managed in a KMS or HSM, applied via HMAC before or during hashing.
- **Defeats**: Offline GPU hash cracking if the database is leaked via SQL Injection, because the attacker lacks the Pepper key stored securely on the application server.

---

## ⚙️ Argon2id Tuning Parameters

Argon2 won the International Password Hashing Competition (PHC) and is specified in RFC 9106. Argon2id combines Argon2i (resistant to side-channel timing attacks) and Argon2d (resistant to GPU cracking).

- **Memory Cost (`m`)**: RAM allocated per hash calculation (e.g., `65536 KiB = 64 MB`). Higher memory forces GPU crackers to run out of VRAM.
- **Time Cost (`t`)**: Number of iterations over memory.
- **Parallelism (`p`)**: Number of concurrent threads utilized (matches CPU core count).
- **Target Hash Latency**: Tune parameters so that user login authentication takes **250 ms to 500 ms** on your production infrastructure.

---

## 💻 Production Code Implementations

### 1. Python (`argon2-cffi` + Password Re-hashing Strategy)

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

class PasswordSecurityManager:
    def __init__(self):
        # OWASP Recommended Production Defaults for Argon2id
        self.ph = PasswordHasher(
            time_cost=3,        # 3 iterations
            memory_cost=65536,  # 64 MiB
            parallelism=4,      # 4 parallel threads
            hash_len=32,        # 256-bit output hash
            salt_len=16         # 128-bit CSPRNG salt
        )

    def hash_password(self, password: str) -> str:
        """Hashes password using Argon2id with automatic salt generation."""
        return self.ph.hash(password)

    def verify_and_update(self, stored_hash: str, password: str) -> tuple[bool, str | None]:
        """
        Verifies password against stored hash.
        Returns: (is_valid, new_hash_if_rehash_needed)
        """
        try:
            # Constant-time verification
            self.ph.verify(stored_hash, password)
            
            # Check if security parameters were upgraded and rehash is needed
            if self.ph.check_needs_rehash(stored_hash):
                new_hash = self.ph.hash(password)
                return True, new_hash
                
            return True, None
        except (VerifyMismatchError, InvalidHashError):
            return False, None

# --- Usage Example ---
mgr = PasswordSecurityManager()
hashed = mgr.hash_password("SuperSecurePassword123!")
print(f"Argon2id Hash Format:\n{hashed}\n")

valid, updated_hash = mgr.verify_and_update(hashed, "SuperSecurePassword123!")
print("Verification Success:", valid)
```

### 2. Node.js (Using `argon2` module)

```javascript
const argon2 = require('argon2');

async function hashPassword(password) {
    // Options matching OWASP guidelines
    return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16, // 64 MB
        timeCost: 3,
        parallelism: 4
    });
}

async function verifyPassword(hash, password) {
    try {
        if (await argon2.verify(hash, password)) {
            // Check if parameters need upgrading
            if (argon2.needsRehash(hash, { memoryCost: 2 ** 16, timeCost: 3 })) {
                const newHash = await hashPassword(password);
                return { success: true, rehashed: newHash };
            }
            return { success: true, rehashed: null };
        }
        return { success: false };
    } catch (err) {
        return { success: false };
    }
}

// --- Usage ---
(async () => {
    const hash = await hashPassword("UserPassphrase2026!");
    console.log("Node.js Argon2id Hash:", hash);
    const result = await verifyPassword(hash, "UserPassphrase2026!");
    console.log("Result:", result);
})();
```

### 3. Go (`golang.org/x/crypto/argon2`)

```go
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultParams = &Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string, p *Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("`$argon2id$`v=%d`$m=%d,t=%d,p=%d`$%s$`%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)

	return encoded, nil
}

func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	var version int
	var memory, iterations uint32
	var parallelism uint8
	fmt.Sscanf(parts[2], "v=%d", &version)
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	targetHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(targetHash)))

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(targetHash, computedHash) == 1
}

func main() {
	hash, _ := HashPassword("GoLangSecurePass!1", DefaultParams)
	fmt.Println("Go Argon2id Encoded:", hash)
	fmt.Println("Valid:", VerifyPassword("GoLangSecurePass!1", hash))
}
```

---

## 🔑 Key Derivation for Encryption (HKDF: RFC 5869)

While password hashing functions (Argon2id) slow down passphrase cracking, **HKDF (HMAC-based Extract-and-Expand Key Derivation Function)** is used to expand high-entropy master secrets (e.g., ECDHE shared secrets) into multiple independent cryptographic keys (Encryption Key, MAC Key, IV).

```
                      +-----------------------------+
                      | Input Keying Material (IKM) |
                      +-----------------------------+
                                     |
                               HKDF-Extract
                                     |
                                     v
                       [ Pseudorandom Key (PRK) ]
                                     |
                                HKDF-Expand (with info context)
                                     |
           +-------------------------+-------------------------+
           v                                                   v
  [ AES-256 Encryption Key ]                        [ HMAC Authentication Key ]
```

### Python HKDF Example (`cryptography`)

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_session_keys(shared_secret: bytes, context_info: bytes) -> tuple[bytes, bytes]:
    """Derives a 256-bit Encryption Key and a 256-bit MAC Key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64, # 32 bytes encryption key + 32 bytes mac key
        salt=None, # Optional salt
        info=context_info,
    )
    derived = hkdf.derive(shared_secret)
    enc_key = derived[:32]
    mac_key = derived[32:]
    return enc_key, mac_key
```

