---
title: "02 - Symmetric Encryption"
description: "Symmetric encryption uses a single key to encrypt and decrypt data. It is the workhorse of cryptography, used for bulk data encryption because of its ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Cryptography", "02 Symmetric Encryption.Md"]
---

# 02 - Symmetric Encryption

Symmetric encryption uses a single key to encrypt and decrypt data. It is the workhorse of cryptography, used for bulk data encryption because of its speed and efficiency.

## The Gold Standards: AEAD
Authenticated Encryption with Associated Data (AEAD) ensures both the **confidentiality** and **integrity** of data. It prevents attackers from modifying the ciphertext without being detected.

### 1. AES-256-GCM
Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM). Hardware-accelerated on most modern CPUs, making it incredibly fast.
### 2. ChaCha20-Poly1305
A stream cipher (ChaCha20) paired with a MAC (Poly1305). Often faster than AES on devices without hardware acceleration (like mobile devices).

## Why ECB and CBC (Without HMAC) are Broken

### Electronic Codebook (ECB)
ECB mode encrypts identical plaintext blocks into identical ciphertext blocks. This reveals data patterns (e.g., the famous "ECB Penguin" image). **Never use ECB.**

### Cipher Block Chaining (CBC)
CBC mode chains blocks together, hiding patterns. However, if used without a MAC (like HMAC-SHA256), it is vulnerable to **Padding Oracle Attacks**, where an attacker can decrypt data by observing error messages related to padding.

## Initialization Vectors (IV/Nonce)
An IV (or Nonce - Number Used Once) ensures that encrypting the same plaintext multiple times yields different ciphertexts.
- **Rule**: Never reuse an IV with the same key in GCM or CTR mode. Doing so completely breaks the encryption.
- **Generation**: Always use a cryptographically secure pseudo-random number generator (CSPRNG).

## Code Examples: AES-256-GCM

### Python (using `cryptography`)
```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    # Generate a random 96-bit (12-byte) IV for GCM
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    # The IV is prepended to the ciphertext for storage
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext

def decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    # Automatically verifies the authentication tag
    return aesgcm.decrypt(iv, ciphertext, None)

# Usage
key = AESGCM.generate_key(bit_length=256)
encrypted = encrypt(key, b"Secret Message")
print(decrypt(key, encrypted))
```

### Node.js (using built-in `crypto`)
```javascript
const crypto = require('crypto');

function encrypt(key, plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let ciphertext = cipher.update(plaintext, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    
    const authTag = cipher.getAuthTag();
    // Return iv, authTag, and ciphertext concatenated
    return Buffer.concat([iv, authTag, ciphertext]);
}

function decrypt(key, encryptedData) {
    const iv = encryptedData.slice(0, 12);
    const authTag = encryptedData.slice(12, 28);
    const ciphertext = encryptedData.slice(28);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let plaintext = decipher.update(ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);
    return plaintext.toString('utf8');
}

// Usage
const key = crypto.randomBytes(32);
const encrypted = encrypt(key, "Secret Message");
console.log(decrypt(key, encrypted));
```

### Go (using `crypto/cipher`)
```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(key []byte, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	key := make([]byte, 32)
	rand.Read(key)
	
	encrypted, _ := encrypt(key, []byte("Secret Message"))
	decrypted, _ := decrypt(key, encrypted)
	fmt.Printf("%s\n", decrypted)
}
```
