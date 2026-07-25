# 04 - Password Hashing and Key Derivation

Hashing a password with standard hash functions like SHA-256 is insufficient. Attackers use Graphics Processing Units (GPUs) or ASICs to compute billions of SHA-256 hashes per second, allowing them to crack passwords easily using dictionary attacks or rainbow tables.

To securely store passwords, you must use a **Key Derivation Function (KDF)**.

## Key Derivation Functions (KDFs)
KDFs are designed to be intentionally slow and resource-intensive, thwarting brute-force attacks.

### 1. Argon2id (The Gold Standard)
Winner of the Password Hashing Competition. Argon2id provides resistance against both GPU cracking (by being memory-hard) and side-channel attacks.

### 2. bcrypt (The Reliable Standard)
A widely supported, time-tested algorithm. While not as memory-hard as Argon2, it remains highly secure and is the default in many frameworks.

### 3. PBKDF2 (NIST Approved, but Aging)
Uses standard hash functions (like HMAC-SHA256) repeatedly. It is computationally expensive but lacks memory hardness, making it vulnerable to custom ASIC hardware attacks.

## Core Concepts

### Salts
A salt is a unique, randomly generated string added to each password before hashing.
- **Purpose**: Prevents the use of Rainbow Tables and ensures that identical passwords yield different hashes.
- **Rule**: Generate a new, unique salt (at least 16 bytes) for every user. Salts are not secret and are stored alongside the hash.

### Work Factors / Cost Parameters
KDFs allow you to tune their difficulty.
- **Argon2**: Tunes Time (iterations), Memory, and Parallelism (threads).
- **bcrypt**: Tunes Rounds (logarithmic scale, typically 10 to 14).
- **Rule**: Tune the parameters so that hashing takes roughly 250ms - 500ms on your authentication server.

### Peppers
A pepper is a secret cryptographic key applied to the password hash (usually by HMACing the output or encrypting the hash).
- **Purpose**: If the database is compromised, the attacker still cannot crack the passwords without also compromising the application server where the pepper is stored.

## Code Example: Argon2 in Python
Using the `argon2-cffi` library:

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize hasher with secure defaults (Argon2id)
ph = PasswordHasher(
    time_cost=3,          # Number of iterations
    memory_cost=65536,    # 64 MB of RAM
    parallelism=4         # 4 threads
)

password = "correct_horse_battery_staple"

# 1. Hash the password (Salt is generated automatically)
hashed_password = ph.hash(password)
print(f"Stored Hash: {hashed_password}")

# 2. Verify the password
try:
    ph.verify(hashed_password, password)
    print("Login successful!")
except VerifyMismatchError:
    print("Invalid password!")

# 3. Check if parameters need upgrading
if ph.check_needs_rehash(hashed_password):
    print("Needs rehash with new parameters.")
```
