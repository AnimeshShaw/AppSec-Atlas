---
sidebar_position: 2
title: 01 - Introduction to Post-Quantum Cryptography
---

# Chapter 01: Introduction to Post-Quantum Cryptography

The era of classical cryptography is facing a fundamental threat. Post-Quantum Cryptography (PQC) represents the evolution of cryptographic primitives to secure systems against cryptanalytic attacks originating from quantum computers.

## 1. The Concept (ELI5)

Think of standard encryption (like RSA) as hiding a secret inside the product of two gigantic prime numbers. For a normal computer, separating that massive number back into its two original prime pieces takes forever (millions of years). 

But a quantum computer doesn't play by the same rules. It uses "quantum magic" to find the pieces incredibly fast. Post-Quantum Cryptography is like switching the lock from "math with giant primes" to finding a specific point in a 500-dimensional grid of dots. Even the quantum computer gets lost trying to navigate that grid.

## 2. The Visual

```mermaid
architecture-blueprint
graph TD
    subgraph Classical Crypto
        A[RSA / ECC] --> B(Relies on Factoring / Discrete Log)
        B --> C{Quantum Threat?}
        C -- Yes --> D[Broken by Shor's Algorithm]
    end
    
    subgraph Post-Quantum Crypto
        E[Lattice / Hash / Isogeny] --> F(Relies on NP-Hard / Mathematical Grids)
        F --> G{Quantum Threat?}
        G -- No --> H[Secure against Quantum and Classical]
    end
```

## 3. The Code

How does generating a standard key compare to generating a PQC key?

### Go

**Vulnerable Code** ❌
```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func main() {
	// ECC (e.g., P-256) is vulnerable to modified Shor's algorithm
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = privateKey
}
```

**Production-Ready Secure Code** ✅
```go
package main

import (
	"fmt"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
	// Dilithium: A lattice-based post-quantum signature scheme
	pk, sk, _ := mode3.GenerateKey(nil)
	fmt.Printf("PQC Key generated. PublicKey size: %d bytes\n", len(pk.Bytes()))
	_ = sk
}
```

### Python

**Vulnerable Code** ❌
```python
from cryptography.hazmat.primitives.asymmetric import ec

# Classic ECC: Vulnerable
private_key = ec.generate_private_key(ec.SECP256R1())
```

**Production-Ready Secure Code** ✅
```python
import oqs

# PQC Signature (Dilithium)
sig = oqs.Signature("Dilithium3")
public_key = sig.generate_keypair()
print(f"PQC Public Key Length: {len(public_key)} bytes")
```

### TypeScript / Node.js

**Vulnerable Code** ❌
```typescript
import { generateKeyPairSync } from 'crypto';

// Standard ECC
const { publicKey, privateKey } = generateKeyPairSync('ec', {
  namedCurve: 'secp256k1',
});
```

**Production-Ready Secure Code** ✅
```typescript
import { Signature } from 'node-oqs';

// Using a quantum-resistant signature algorithm
const sig = new Signature('Dilithium3');
const pubKey = sig.generateKeypair();
```

## 4. The Guardrail

**Rego Rule for Infrastructure (Terraform)**:
Ensure cloud load balancers or API gateways are configured with TLS policies that enforce hybrid post-quantum key exchanges (where supported, like AWS KMS or CloudFront PQC policies).

```rego
package tf.pqc_tls

deny[msg] {
  resource := input.resource.aws_cloudfront_distribution[name]
  viewer_cert := resource.viewer_certificate[_]
  not startswith(viewer_cert.minimum_protocol_version, "TLSv1.2_2021")
  # Ideally, enforcing a policy that implies hybrid key exchange support
  msg := sprintf("CloudFront distribution '%v' must use strict TLS policies supporting modern cyphers.", [name])
}
```
