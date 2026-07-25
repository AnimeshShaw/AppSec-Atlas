---
title: "03 - JWT Security Masterclass"
description: "JSON Web Tokens (JWT) are widely used for stateless authentication. However, improper implementation leads to severe vulnerabilities."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Auth And Authz", "03 Jwt Security Masterclass.Md"]
---

# 03 - JWT Security Masterclass

JSON Web Tokens (JWT) are widely used for stateless authentication. However, improper implementation leads to severe vulnerabilities.

## JWT Structure
A JWT consists of three parts separated by dots (`.`):
1. **Header:** Algorithm and token type.
2. **Payload:** Claims (user ID, roles, expiration).
3. **Signature:** Cryptographic verification.

`Base64UrlEncode(Header) . Base64UrlEncode(Payload) . Signature`

## Common Vulnerabilities & Exploits

### 1. The `alg: none` Attack
Some libraries accept tokens where the algorithm header is set to `none`, bypassing signature validation entirely.
**Exploit:**
Modify the header to `{"alg": "none", "typ": "JWT"}`. Strip the signature but leave the trailing dot.
```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```
**Defense:** Explicitly specify allowed algorithms during verification. Reject `none`.

### 2. RSA to HMAC Confusion Attack
If a server uses an asymmetric key pair (RSA) for signing, but the attacker changes the `alg` to `HS256` (HMAC), some vulnerable libraries will use the public key as the secret key for HMAC validation.
**Exploit:**
Attacker retrieves the public key, crafts a malicious token, sets `alg: HS256`, and signs it using the public key as the HMAC secret.
**Defense:** Hardcode/configure the expected algorithm (`RS256`) in the backend verifier.

## Advanced JWT Security

### Key Rotation (JWKS)
Cryptographic keys should be rotated regularly.
- **JWKS (JSON Web Key Set):** An endpoint exposing public keys used to sign tokens. The JWT header includes a `kid` (Key ID) that the server uses to fetch the correct public key from the JWKS for verification.

### Refresh Token Rotation
Access tokens should be short-lived (e.g., 15 minutes). Refresh tokens are used to get new access tokens.
- **Refresh Token Rotation:** Every time a refresh token is used, it is invalidated, and a new one is issued. This prevents attackers from reusing a stolen refresh token indefinitely.

### Secure Code Example: Validating JWT (Python / PyJWT)

```python
import jwt
from jwt.exceptions import InvalidTokenError

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"""

def verify_token(token):
    try:
        # 1. Enforce Algorithm (mitigates alg:none and confusion attacks)
        # 2. Verify Signature using public key
        # 3. Validate expiration (exp claim is checked automatically)
        decoded = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False}
        )
        return decoded
    except InvalidTokenError as e:
        print(f"Token invalid: {e}")
        return None
```
