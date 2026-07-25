---
title: "02 - Web and Crypto CTF Tactics 🕸️🔐"
description: "This chapter dives deep into the two most accessible yet conceptually profound CTF categories: Web Exploitation and Cryptography."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "05 Offensive", "Ctf Guide", "02 Web And Crypto Ctf Tactics.Md"]
---

# 02 - Web and Crypto CTF Tactics 🕸️🔐

This chapter dives deep into the two most accessible yet conceptually profound CTF categories: Web Exploitation and Cryptography.

---

## 🕸️ Web Exploitation Tactics

Web CTF challenges usually provide a URL and occasionally the source code. Your goal is to find the vulnerability and extract the flag.

### 1. Local File Inclusion (LFI)
LFI occurs when an application includes a file based on user input without proper validation.

**Vulnerable Code (PHP):**
```php
<?php
  `$page = $`_GET['page'];
  include($page);
?>
```

**Attack Payload:**
Traverse the directory structure to read sensitive files like `/etc/passwd` or the flag.
```http
GET /index.php?page=../../../../etc/passwd
```

**LFI to RCE (Log Poisoning):**
If you can include the Apache/Nginx log file via LFI, you can inject PHP code into the User-Agent header, which gets written to the log, and then executed when you include the log.

### 2. Server-Side Template Injection (SSTI)
SSTI happens when user input is unsafely embedded into a template engine (like Jinja2, Twig, or EJS), allowing attackers to execute arbitrary code.

**Attack Payload (Jinja2 / Python):**
```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read() }}
```

### 3. JWT (JSON Web Token) Bypass
JWTs are often used for authentication. In CTFs, they are frequently misconfigured.

**Common JWT Attacks:**
- **None Algorithm:** Change the header alg to `None` and strip the signature.
- **Weak Secret:** Brute-force the secret key using `hashcat` or `john`.
- **Key Confusion:** If the server uses RS256 but allows HS256, you can use the public key as the symmetric secret to forge a token.

---

## 🔐 Cryptography Tactics

Crypto challenges test your understanding of math and encryption algorithms.

### 1. The XOR Cipher
XOR (`$\oplus$`) is the foundation of many cryptographic systems.
Properties:
- `A ⊕ 0 = A`
- `A ⊕ A = 0`
- `A ⊕ B = C` implies `C ⊕ B = A`

**Python XOR Solve Script:**
If you know the flag format starts with `flag{`, you can XOR the ciphertext with the known plaintext to recover the key!

```python
def xor_strings(s1, s2):
    return bytes([a ^ b for a, b in zip(s1, s2)])

ciphertext = bytes.fromhex("1e150c0c2a1c0b02131b1c")
known_plaintext = b"flag{"

# Recover the key using the known prefix
key_prefix = xor_strings(ciphertext[:5], known_plaintext)
print(f"Recovered Key Prefix: {key_prefix}")

# Assuming the key repeats
key = (key_prefix * 10)[:len(ciphertext)]
flag = xor_strings(ciphertext, key)
print(f"Flag: {flag.decode()}")
```

### 2. RSA - Weak Keys
RSA relies on the difficulty of factoring a large number `$N`$` into its prime components `$`p`$` and `$`q`$`. If `$`N$` is too small, or poorly generated, we can break it.

**Common RSA Attacks in CTFs:**
- **Small N:** Factor N using [factordb.com](http://factordb.com/).
- **Small e (e=3) without padding:** Calculate the cube root of the ciphertext.
- **Common Modulus:** Two messages encrypted with the same N but different e.

**Python PyCryptodome RSA Decrypt Script:**
```python
from Crypto.Util.number import inverse, long_to_bytes

# Given by the challenge
N = 3233 # Factored into p=61, q=53
e = 17
c = 855

p = 61
q = 53

# 1. Calculate the totient Phi(N)
phi = (p - 1) * (q - 1)

# 2. Calculate the private key 'd' (modular inverse of e mod phi)
d = inverse(e, phi)

# 3. Decrypt the ciphertext: m = c^d mod N
m = pow(c, d, N)

print(f"Decrypted Message: {long_to_bytes(m)}")
```

### 3. Padding Oracle Attacks
Occurs in CBC (Cipher Block Chaining) mode encryption. If the server tells you whether the padding of a decrypted message is valid or invalid, you can decrypt the ciphertext byte-by-byte without knowing the key. Tool of choice: `padbuster`.
