# 03 - Asymmetric Encryption and Signatures

Asymmetric cryptography (Public-Key Cryptography) uses a mathematically linked key pair:
- **Public Key**: Shared openly. Used to encrypt data or verify signatures.
- **Private Key**: Kept secret. Used to decrypt data or create signatures.

## Core Concepts

### 1. RSA vs Elliptic Curve Cryptography (ECC)
- **RSA**: The legacy standard. Security relies on the difficulty of factoring large prime numbers. Requires large keys (e.g., RSA-4096) to remain secure against modern computing, making it slow.
- **ECC**: The modern standard (e.g., Secp256k1, Ed25519). Security relies on the algebraic structure of elliptic curves. Provides equivalent security to RSA with much smaller keys (e.g., 256-bit), making it faster and more efficient.

### 2. Digital Signatures
A digital signature proves that a message was created by a known sender (Authentication) and was not altered in transit (Integrity/Non-repudiation).
- **Modern standard**: Ed25519.

### 3. Key Exchange (ECDHE)
Elliptic-Curve Diffie-Hellman Ephemeral (ECDHE) allows two parties to establish a shared symmetric key over an insecure channel. This is the foundation of TLS 1.3 Forward Secrecy.

## Working Code: Digital Signatures with Ed25519

### Python (using `cryptography`)
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# 1. Generate Key Pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

message = b"Authorize transfer of $1M"

# 2. Sign the message
signature = private_key.sign(message)

# 3. Verify the message
try:
    public_key.verify(signature, message)
    print("Signature is valid.")
except Exception:
    print("Signature is invalid.")
```

### Node.js (using built-in `crypto`)
```javascript
const crypto = require('crypto');

// 1. Generate Key Pair
crypto.generateKeyPair('ed25519', (err, publicKey, privateKey) => {
    if (err) throw err;

    const message = Buffer.from("Authorize transfer of $1M");

    // 2. Sign the message
    const signature = crypto.sign(null, message, privateKey);

    // 3. Verify the message
    const isValid = crypto.verify(null, message, publicKey, signature);
    console.log("Signature is valid:", isValid);
});
```

## TLS 1.3 Handshake Overview
1. **Client Hello**: Client sends supported cipher suites and a key share (for ECDHE).
2. **Server Hello**: Server chooses cipher suite, sends its key share, and its X.509 Certificate (containing its public key).
3. **Authentication**: Client verifies the Server's certificate against trusted Root CAs.
4. **Key Derivation**: Both compute the same shared secret symmetric key.
5. **Secure Channel**: All subsequent communication is encrypted using AES-GCM or ChaCha20.
