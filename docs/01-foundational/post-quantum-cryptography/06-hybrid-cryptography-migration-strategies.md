---
sidebar_position: 7
title: 06 - Hybrid Cryptography Migration Strategies
---

# Chapter 06: Hybrid Cryptography Migration Strategies

Migrating to PQC isn't an overnight switch. Because new algorithms might have unforeseen classical flaws (as happened with SIKE during the NIST competition), the industry best practice is **Hybrid Cryptography**.

## 1. The Concept (ELI5)

Imagine you are holding up your pants. You usually use a strong leather belt (Classical Crypto like ECC). It’s worked for decades. Now, scientists tell you that soon, a "quantum laser" will easily slice your belt, dropping your pants.
They offer you a brand new, high-tech pair of suspenders (Post-Quantum Crypto). But the suspenders are so new, maybe there's a manufacturing defect we don't know about yet.
What's the safest approach? **Wear the belt AND the suspenders.** If the laser cuts the belt, the suspenders hold your pants up. If the suspenders have a defect and snap, your trusty belt is still there. 
Hybrid Cryptography combines a classical key with a quantum key. An attacker has to break BOTH to read your data.

## 2. The Visual

```mermaid
architecture-blueprint
graph TD
    Client[Client App]
    Server[Web Server]
    
    subgraph Hybrid Key Exchange
        Client -- 1. Generate ECDHE PubKey --> HKDF[Key Derivation Function HKDF]
        Client -- 2. Generate Kyber PubKey --> HKDF
        
        Server -- 3. Generate ECDHE Secret --> HKDF
        Server -- 4. Decapsulate Kyber Secret --> HKDF
        
        HKDF --> MasterSecret[Unified Master Secret]
    end
    
    MasterSecret --> AES256[AES-256-GCM Secure Channel]
```

## 3. The Code

Implementing a hybrid KEM wrapper around existing libraries.

### Go

**Vulnerable Code** ❌ (Relying solely on one algorithm)
```go
// Relying only on PQC or only on ECC is risky during the transition period.
```

**Production-Ready Secure Code** ✅ (Hybrid KEM logic)
```go
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"io"
)

// Conceptual Hybrid Combiner
func deriveHybridKey(eccSecret, pqcSecret []byte) []byte {
	combined := append(eccSecret, pqcSecret...)
	
	// HKDF combines both secrets into a single strong 32-byte key
	hkdfReader := hkdf.New(sha256.New, combined, nil, nil)
	finalKey := make([]byte, 32)
	io.ReadFull(hkdfReader, finalKey)
	return finalKey
}

func main() {
	// 1. Classical ECC
	curve := ecdh.P256()
	eccPrivate, _ := curve.GenerateKey(rand.Reader)
	
	// 2. Post-Quantum Kyber
	pqcPublic, pqcPrivate, _ := kyber768.GenerateKeyPair(nil)
	
	fmt.Println("Keys generated, ready for hybrid combination!")
    _ = eccPrivate
    _ = pqcPublic
    _ = pqcPrivate
}
```

### Python

**Vulnerable Code** ❌
```python
# Standard key derivation with just one secret
pass
```

**Production-Ready Secure Code** ✅
```python
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def hybrid_kdf(ecc_shared_secret: bytes, pqc_shared_secret: bytes) -> bytes:
    # Concatenate secrets
    combined_secret = ecc_shared_secret + pqc_shared_secret
    
    # Derive unified master key
    hkdf = HKDF(
        algorithm=hashlib.sha256(),
        length=32,
        salt=None,
        info=b"hybrid-handshake"
    )
    return hkdf.derive(combined_secret)
```

### TypeScript / Node.js

**Vulnerable Code** ❌
```typescript
// Single secret dependency
```

**Production-Ready Secure Code** ✅
```typescript
import { createHmac } from 'crypto';

function combineSecrets(eccSecret: Buffer, pqcSecret: Buffer): Buffer {
    const combined = Buffer.concat([eccSecret, pqcSecret]);
    
    // Simple HKDF-Expand concept
    const hmac = createHmac('sha256', Buffer.alloc(32)); 
    hmac.update(combined);
    return hmac.digest();
}
```

## 4. The Guardrail

**Semgrep Rule**: Enforce the use of HKDF when combining secrets, rather than just simple hashing or XORing, which can be vulnerable.

```yaml
rules:
  - id: require-hkdf-for-hybrid
    message: "When combining multiple cryptographic secrets (e.g., in a hybrid PQC scheme), always use an industry-standard KDF like HKDF."
    severity: WARNING
    languages:
      - go
    pattern: |
      append($X, $Y...)
      ...
      sha256.Sum256(...)
    fix: "Use golang.org/x/crypto/hkdf instead of raw sha256."
```
