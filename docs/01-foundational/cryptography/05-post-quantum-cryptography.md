# 05 - Post-Quantum Cryptography (PQC)

Quantum computers leverage quantum mechanics to process information in ways classical computers cannot. While currently in their infancy, cryptographically relevant quantum computers (CRQCs) threaten the foundation of modern digital security.

## The Quantum Threat

### Shor's Algorithm
Shor's algorithm can efficiently factor large integers and solve discrete logarithms.
- **Impact**: Completely breaks all widely used Asymmetric Cryptography, including RSA, ECDSA, and ECDHE.
- **Timeline**: Estimates vary, but many experts predict a CRQC capable of breaking RSA-2048 could exist between 2030 and 2040.

### Grover's Algorithm
Grover's algorithm reduces the effective key space of symmetric algorithms by a square root factor.
- **Impact**: AES-128 is reduced to 64-bit security (insecure). AES-256 is reduced to 128-bit security (still secure).
- **Mitigation**: Double the key sizes for symmetric crypto. AES-256 and SHA-384 are considered quantum-resistant.

### Harvest Now, Decrypt Later (HNDL)
Adversaries are currently intercepting and storing encrypted data. Once a CRQC is built, they will decrypt this historical data. For data with long-term sensitivity (e.g., state secrets, healthcare records), the threat is immediate.

## NIST PQC Standardization

The National Institute of Standards and Technology (NIST) has standardized new algorithms resistant to quantum attacks. These algorithms rely on different mathematical foundations, primarily lattice-based cryptography.

### 1. FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **Formerly known as**: CRYSTALS-Kyber.
- **Purpose**: General encryption and Key Establishment (replacing ECDHE).

### 2. FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **Formerly known as**: CRYSTALS-Dilithium.
- **Purpose**: Digital Signatures (replacing RSA and ECDSA).

### 3. FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- **Formerly known as**: SPHINCS+.
- **Purpose**: Digital Signatures (fallback option, non-lattice based).

## Hybrid Key Exchange
Because PQC algorithms are relatively new and have not withstood decades of classical cryptanalysis, the current industry best practice is a **Hybrid Approach**.

A hybrid key exchange combines a classical algorithm (like X25519) with a PQC algorithm (like ML-KEM). 
- An attacker would need to break **both** algorithms to compromise the encryption.
- This ensures immediate protection against classical attacks while providing forward secrecy against future quantum attacks.
- Examples include `X25519Kyber768Draft00`, currently being deployed in Chrome and Cloudflare TLS 1.3 connections.
