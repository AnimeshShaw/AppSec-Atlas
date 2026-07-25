---
title: "02 - Symmetric Encryption"
description: "Master AEAD symmetric ciphers (AES-GCM, ChaCha20-Poly1305), Additional Authenticated Data (AAD) context binding, attack vectors against broken modes (ECB, CBC), Nonce reuse mechanics, and production implementations."
keywords: ["AppSec", "Cryptography", "Symmetric Encryption", "AES-256-GCM", "ChaCha20-Poly1305", "AEAD", "AAD", "ECB Mode", "Padding Oracle", "Nonce Reuse", "Envelope Encryption"]
---

# 02 - Symmetric Encryption

Symmetric encryption uses the same secret key to encrypt plaintext into ciphertext and decrypt ciphertext back into plaintext. It is the workhorse of application security, used for high-throughput bulk data encryption at rest (databases, S3 buckets, disk encryption) and in transit (TLS 1.3 payload encryption).

---

## 🛡️ The Gold Standard: Authenticated Encryption with Associated Data (AEAD)

Legacy ciphers provided only **confidentiality**. If an attacker modified ciphertext bytes in transit, the application would attempt to decrypt the corrupted bytes, often resulting in application errors, unhandled exceptions, or malleable plaintext injection.

Modern application security mandates **AEAD (Authenticated Encryption with Associated Data)**. AEAD simultaneously guarantees:
1. **Confidentiality**: The plaintext is unreadable without the secret key.
2. **Integrity**: Any tampering with the ciphertext causes decryption to fail instantly before any plaintext is released.
3. **Authenticity**: Proves the ciphertext was created by an entity holding the secret key.
4. **Contextual Binding (AAD)**: Authenticates plaintext metadata (e.g., User ID, Account Number, DB Row ID) that remains unencrypted alongside the ciphertext.

```
                      +-------------------------------------------------------------+
                      |                      AEAD ENCRYPTION                        |
                      +-------------------------------------------------------------+
                                                     |
  [ Plaintext ] ----+                                |
                    |---> [ Symmetric Cipher ] ------> [ Ciphertext ]
  [ Secret Key ] ---+           (AES/ChaCha20)               |
                    |                                        v
  [ Nonce/IV ] -----+                              [ MAC Generator ] ----> [ Auth Tag (16 bytes) ]
                                                     (GHASH / Poly1305)
  [ Associated ] --------------------------------------------+
    Data (AAD)
```

---

## 🔬 Core AEAD Algorithms

### 1. AES-256-GCM (Galois/Counter Mode)
- **Mechanism**: Combines AES in Counter Mode (CTR) for encryption with GHASH over a Galois field $GF(2^{128})$ for message authentication.
- **Hardware Acceleration**: Supported on nearly modern hardware via Intel/AMD **AES-NI** instructions and ARMv8 Cryptographic Extensions, delivering multi-gigabit per second performance.
- **Nonce Requirement**: Requires a 96-bit (12-byte) unique Nonce per encryption operation under the same key.

### 2. ChaCha20-Poly1305
- **Mechanism**: Combines Daniel J. Bernstein's ChaCha20 stream cipher with the Poly1305 authenticator (RFC 8439).
- **Use Case**: Performs significantly faster than AES on mobile devices (Android, iOS) and embedded hardware lacking dedicated AES-NI instructions. Immune to software AES side-channel cache-timing attacks.

---

## 🎯 Additional Authenticated Data (AAD): Preventing Context Swap Attacks

Associated Authenticated Data (AAD) is plaintext metadata that is **not encrypted**, but is fed into the AEAD MAC generator. If an attacker tampers with the AAD or swaps ciphertext into a different context, the authentication check fails.

### Threat Scenario: Database Row Substitution Attack
Suppose a multi-tenant application encrypts user credit card numbers using a single system key:
- User A (ID `1001`) has encrypted card ciphertext `C_A`.
- User B (ID `1002`) has encrypted card ciphertext `C_B`.

An attacker with direct database write access copies `C_B` into User A's row. When User A views their profile, the server decrypts `C_B` successfully because the key is identical.

**The Fix with AAD:**
By passing `tenant_id:1001` or `user_id:1001` as AAD during User A's encryption, the resulting Auth Tag is mathematically bound to User A's ID. If `C_B` is placed in User A's record, decryption immediately throws an `AuthenticationTagMismatch` error!

---

## 💣 Broken Modes & Critical Failure Vectors

### 1. Electronic Codebook (ECB) Mode: Pattern Leakage
ECB mode divides plaintext into 16-byte blocks and encrypts every identical plaintext block into the exact same ciphertext block.

```
Plaintext Blocks:  [ "TRANSFER $10,000 " ] [ "TRANSFER $10,000 " ]
ECB Ciphertext:    [ 0xa4f891b2c3d4e5f6 ] [ 0xa4f891b2c3d4e5f6 ]  <-- Identical Output!
```

> [!CAUTION]
> **The ECB Penguin:** The infamous demonstration encrypts a bitmap image of the Tux penguin using AES-ECB. Because pixels of the same color produce identical ciphertext blocks, the full outline of the penguin remains clearly visible in the encrypted output! **Never use AES-ECB.**

```
+------------------------+       +------------------------+
| Original Bitmap (Tux)  |  ===> | Encrypted AES-ECB Tux  |
| [ Distinct Shape ]     |       | [ Shape Intact/Visible]|
+------------------------+       +------------------------+
```

### 2. Cipher Block Chaining (CBC) Without HMAC: Padding Oracles & Bit-Flipping
CBC mode chains blocks by XORing each plaintext block with the previous ciphertext block:
$$C_i = E_K(P_i \oplus C_{i-1})$$

- **Bit-Flipping Attack**: Flipping bit $b$ in ciphertext block $C_{i-1}$ directly flips bit $b$ in decrypted plaintext $P_i$. An attacker can tamper with values like `"admin=0"` to `"admin=1"`.
- **Padding Oracle Attack**: If the server returns different error codes or timing responses when decryption fails PKCS#7 padding validation versus application errors, an attacker can decrypt ciphertext byte-by-byte without knowing the key (e.g., POODLE, Lucky Thirteen).

### 3. AES-GCM / ChaCha20 Nonce Reuse Catastrophe
GCM and ChaCha20 are counter-based stream ciphers. The cipher generates a pseudo-random keystream $S$ based on $(Key, Nonce)$ and XORs it with plaintext $P$:
$$C_1 = P_1 \oplus S$$

If the **same Nonce** is reused with the **same Key** for a second message $P_2$:
$$C_2 = P_2 \oplus S$$

An adversary possessing $C_1$ and $C_2$ simply XORs the ciphertexts:
$$C_1 \oplus C_2 = (P_1 \oplus S) \oplus (P_2 \oplus S) = P_1 \oplus P_2$$

> [!WARNING]
> Reusing a Nonce in GCM mode allows an attacker to compute $P_1 \oplus P_2$ to recover both plaintexts, and exposes the internal GHASH subkey $H$, allowing the attacker to forge valid authentication tags for arbitrary messages!

---

## 💻 Robust Production Code Snippets (AES-256-GCM with AAD)

Below are production-ready AEAD encryption routines incorporating CSPRNG Nonces, AAD binding, and structured payload serialization across Python, Node.js, Go, and Java.

### 1. Python (`cryptography`)

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureSymmetricCipher:
    """Production-grade AES-256-GCM encryption with AAD binding."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generates a cryptographically secure 256-bit (32-byte) key."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
        """
        Encrypts plaintext using AES-256-GCM.
        Returns: 12-byte Nonce + Ciphertext (includes 16-byte Auth Tag).
        """
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        
        # 96-bit CSPRNG Nonce for GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    @staticmethod
    def decrypt(key: bytes, encrypted_payload: bytes, aad: bytes = None) -> bytes:
        """
        Decrypts payload and authenticates ciphertext and AAD.
        Raises InvalidTag if tampered.
        """
        if len(encrypted_payload) < 28: # 12 nonce + 16 tag minimum
            raise ValueError("Invalid ciphertext length")
            
        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        
        aesgcm = AESGCM(key)
        # Decrypt automatically verifies the 16-byte GCM Auth Tag
        return aesgcm.decrypt(nonce, ciphertext, aad)

# --- Usage Example ---
if __name__ == "__main__":
    key = SecureSymmetricCipher.generate_key()
    user_id_aad = b"user_id:1001"
    secret_data = b"Sensitive Medical Record Payload"

    payload = SecureSymmetricCipher.encrypt(key, secret_data, aad=user_id_aad)
    decrypted = SecureSymmetricCipher.decrypt(key, payload, aad=user_id_aad)
    assert decrypted == secret_data
    print("Python AES-GCM Encrypt/Decrypt Successful!")
```

### 2. Node.js (Built-in `crypto`)

```javascript
const crypto = require('crypto');

class AESGCMCrypto {
    /**
     * Encrypts plaintext string using AES-256-GCM with optional AAD.
     * Output format: Nonce (12B) + AuthTag (16B) + Ciphertext
     */
    static encrypt(key, plaintext, aadString = null) {
        if (key.length !== 32) throw new Error("Key must be 32 bytes (256 bits)");

        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

        if (aadString) {
            cipher.setAAD(Buffer.from(aadString, 'utf8'));
        }

        let ciphertext = cipher.update(plaintext, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        const authTag = cipher.getAuthTag();

        return Buffer.concat([nonce, authTag, ciphertext]);
    }

    /**
     * Decrypts buffer and validates Auth Tag and AAD.
     */
    static decrypt(key, encryptedBuffer, aadString = null) {
        if (encryptedBuffer.length < 28) throw new Error("Payload too short");

        const nonce = encryptedBuffer.subarray(0, 12);
        const authTag = encryptedBuffer.subarray(12, 28);
        const ciphertext = encryptedBuffer.subarray(28);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(authTag);

        if (aadString) {
            decipher.setAAD(Buffer.from(aadString, 'utf8'));
        }

        let plaintext = decipher.update(ciphertext);
        plaintext = Buffer.concat([plaintext, decipher.final()]);
        return plaintext.toString('utf8');
    }
}

// --- Usage ---
const key = crypto.randomBytes(32);
const encrypted = AESGCMCrypto.encrypt(key, "Secret Financial Data", "tenant:acme_corp");
const decrypted = AESGCMCrypto.decrypt(key, encrypted, "tenant:acme_corp");
console.log("Node.js Decrypted:", decrypted);
```

### 3. Go (`crypto/cipher`)

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// EncryptAESGCM encrypts plaintext using AES-256-GCM with optional AAD.
func EncryptAESGCM(key []byte, plaintext []byte, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends auth tag to ciphertext and prepends nonce
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// DecryptAESGCM decrypts and authenticates ciphertext and AAD.
func DecryptAESGCM(key []byte, encryptedData []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, aad)
}

func main() {
	key := make([]byte, 32)
	rand.Read(key)

	aad := []byte("record_id:99823")
	ciphertext, _ := EncryptAESGCM(key, []byte("Top Secret Payload"), aad)
	plaintext, err := DecryptAESGCM(key, ciphertext, aad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Go Decrypted: %s\n", plaintext)
}
```

### 4. Java (JCA `javax.crypto`)

```java
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class AESGCMHandler {
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    public static byte[] encrypt(byte[] keyBytes, byte[] plaintext, byte[] aad) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);

        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend nonce to ciphertext
        ByteBuffer buffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
        buffer.put(nonce);
        buffer.put(ciphertext);
        return buffer.array();
    }

    public static byte[] decrypt(byte[] keyBytes, byte[] encryptedPayload, byte[] aad) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedPayload);
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        buffer.get(nonce);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        return cipher.doFinal(ciphertext);
    }
}
```

---

## 🔑 Envelope Encryption Architecture

Directly encrypting application data with a long-lived Master Key stored on server disks is risky: if the key leaks, all historical data is compromised.

**Envelope Encryption** decouples key management:
1. **Data Encryption Key (DEK)**: A short-lived AES-256 key generated per record to encrypt plaintext data locally.
2. **Key Encryption Key (KEK / Master Key)**: A centralized key stored inside a Hardware Security Module (HSM) or Cloud KMS (AWS KMS, GCP KMS, Vault).
3. The DEK is encrypted using the KEK (`Encrypted_DEK`) and stored side-by-side with the ciphertext payload.

```
  [ Plaintext Data ] ---- AES-GCM (DEK) ----> [ Ciphertext Payload ]
                                                     |
  [ Plain DEK ] -------- Encrypted by KEK --------> [ Encrypted DEK ]
                                                     |
  Stored in Database:  [ Encrypted DEK ] + [ Nonce ] + [ Ciphertext Payload ]
```

> [!NOTE]
> **Key Hygiene:** When decrypting DEKs or plaintexts in memory, zero out key arrays immediately after use in languages supporting explicit memory control (C, Go, Rust) to prevent key exposure via heap dumps or cold-boot attacks.

