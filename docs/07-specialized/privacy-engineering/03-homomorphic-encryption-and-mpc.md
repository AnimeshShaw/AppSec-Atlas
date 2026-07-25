---
title: "Homomorphic Encryption and Secure MPC"
description: "Advanced Privacy Enhancing Technologies (PETs) allow computation on data without exposing the raw data itself."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Privacy Engineering", "03 Homomorphic Encryption And Mpc.Md"]
---

# Homomorphic Encryption and Secure MPC

Advanced Privacy Enhancing Technologies (PETs) allow computation on data without exposing the raw data itself.

## Fully Homomorphic Encryption (FHE)
FHE allows computations to be performed on encrypted data. The result is encrypted and can only be decrypted by the owner of the secret key. 

### Implementation with TenSEAL
TenSEAL is a library for performing homomorphic encryption operations on tensors, built on Microsoft SEAL.

```python
import tenseal as ts

# Setup TenSEAL context
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
context.generate_galois_keys()
context.global_scale = 2**40

# Data Owner: Encrypts data
secret_data = [5.5, 10.2, 3.3]
encrypted_vector = ts.ckks_vector(context, secret_data)

# Cloud Provider / Processor: Performs computation on encrypted data
# Multiply encrypted data by 2
multiplier = [2.0, 2.0, 2.0]
encrypted_result = encrypted_vector * multiplier

# Data Owner: Decrypts the result
decrypted_result = encrypted_result.decrypt()
print(f"Original Data: {secret_data}")
print(f"Decrypted Computation Result: {decrypted_result}")
# Output: [11.0, 20.4, 6.6]
```

## Secure Multi-Party Computation (SMPC)
SMPC allows multiple parties to jointly compute a function over their inputs while keeping those inputs private. No single party learns the others' inputs.

### Private Set Intersection (PSI)
A common MPC use case where two parties compute the intersection of their datasets without revealing any items outside the intersection. E.g., comparing a list of known compromised passwords with user passwords without the server learning the user's password or the user learning the entire breached list.
