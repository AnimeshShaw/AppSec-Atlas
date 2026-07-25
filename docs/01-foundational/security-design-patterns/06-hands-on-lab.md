---
title: "06 - Hands-on Lab: Secure Architecture Refactoring"
description: "In this lab, we will look at a vulnerable, monolithic python script and refactor it using the Circuit Breaker and Envelope Encryption design patterns."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Security Design Patterns", "06 Hands On Lab.Md"]
---

# 06 - Hands-on Lab: Secure Architecture Refactoring

In this lab, we will look at a vulnerable, monolithic python script and refactor it using the Circuit Breaker and Envelope Encryption design patterns.

## Vulnerable Monolithic Design
This script connects directly to an external API without fault tolerance and encrypts data using a hardcoded key.

```python
# vulnerable_app.py
import requests
from cryptography.fernet import Fernet

HARDCODED_KEY = b'vU8_Wc1rA6K2r8zS_9Kk1u5B4M6a8b7c8d9e0f1g2h3='
cipher_suite = Fernet(HARDCODED_KEY)

def process_payment(user_data):
    # No circuit breaker - if the API is down, the whole app hangs
    response = requests.post("http://flaky-payment-api.internal/pay", data=user_data)
    
    if response.status_code == 200:
        # Insecure data storage with hardcoded key
        encrypted_data = cipher_suite.encrypt(user_data.encode())
        save_to_db(encrypted_data)
        return "Success"
    return "Failed"

def save_to_db(data):
    print("Saved to DB")
```

## Refactored Secure Microservices Design
We implement a basic Circuit Breaker and use a simulated KMS for Envelope Encryption.

```python
# secure_app.py
import requests
import pybreaker
from cryptography.fernet import Fernet

# Circuit Breaker: Fail fast after 3 errors, wait 60s to retry
payment_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=60)

class KMS:
    @staticmethod
    def encrypt_dek(plain_dek):
        # In reality, this calls AWS KMS or HashiCorp Vault
        return b"ENCRYPTED_BY_KMS_" + plain_dek

def get_secure_cipher():
    # Envelope Encryption: Generate DEK on the fly
    plain_dek = Fernet.generate_key()
    encrypted_dek = KMS.encrypt_dek(plain_dek)
    return Fernet(plain_dek), encrypted_dek

@payment_breaker
def call_payment_api(user_data):
    # This will fail fast if the circuit is open
    response = requests.post("http://flaky-payment-api.internal/pay", data=user_data, timeout=5)
    response.raise_for_status()
    return response

def process_payment_secure(user_data):
    try:
        call_payment_api(user_data)
        
        cipher_suite, encrypted_dek = get_secure_cipher()
        encrypted_data = cipher_suite.encrypt(user_data.encode())
        
        # Store both the encrypted data and the encrypted DEK
        save_to_db(encrypted_data, encrypted_dek)
        return "Secure Success"
    except pybreaker.CircuitBreakerError:
        return "Service Unavailable. Circuit Open."
    except requests.exceptions.RequestException:
        return "Payment API Error"

def save_to_db(data, encrypted_dek):
    print("Saved Encrypted Data and Encrypted DEK to DB safely")
```
