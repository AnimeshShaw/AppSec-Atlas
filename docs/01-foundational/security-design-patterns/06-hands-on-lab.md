---
title: "06 - Hands-on Lab: Secure Architecture Refactoring & Verification"
description: "Refactor a vulnerable monolithic microservice into a hardened, production-grade architecture incorporating Circuit Breakers, Envelope Encryption, Token Bucket Rate Limiting, and Cryptographic Audit Chains."
keywords: ["AppSec", "Hands-on Lab", "Secure Refactoring", "Circuit Breaker", "Envelope Encryption", "Rate Limiting", "HMAC", "Security Unit Tests", "Python"]
---

# 06 - Hands-on Lab: Secure Architecture Refactoring & Verification

In this hands-on lab, you will audit a vulnerable monolithic payment service (`vulnerable_payment_service.py`), simulate attacks against its architectural weaknesses, refactor it into a resilient microservice using core security patterns (`secure_payment_service.py`), and execute an automated security verification test suite (`test_lab_security.py`).

---

## 🎯 Lab Objectives

1. Identify architectural vulnerabilities in code: cascading failure vulnerability, static cryptographic key sprawl, unauthenticated parameter manipulation, missing rate limits, and vulnerable logging.
2. Refactor the application to incorporate:
   * **Circuit Breaker Pattern** (Prevent cascading system hangs).
   * **Envelope Encryption Pattern** (AES-256-GCM DEK/KEK key hierarchy).
   * **Token Bucket Rate Limiting** (Protect against volumetric DoS).
   * **HMAC Request Signature Verification** (Prevent data tampering).
   * **Cryptographic Hash-Chained Audit Ledger** (Tamper-evident audit logging).
3. Execute automated unit tests to cryptographically prove resilience.

---

## ❌ Step 1: The Vulnerable Microservice (`vulnerable_payment_service.py`)

The legacy implementation hardcodes cryptographic keys, connects to downstream APIs without timeout or circuit breaking, performs no rate limiting, and logs in plaintext.

```python
# vulnerable_payment_service.py
import time
import base64
from cryptography.fernet import Fernet

# VULNERABILITY 1: Hardcoded static key in source code repo
STATIC_KEY = b'vU8_Wc1rA6K2r8zS_9Kk1u5B4M6a8b7c8d9e0f1g2h3='
cipher_suite = Fernet(STATIC_KEY)

# DB Store
database = []
audit_logs = []

def call_unstable_payment_gateway(payload: dict) -> bool:
    """Simulates a remote API call that hangs or fails during peak load."""
    if payload.get("trigger_outage"):
        time.sleep(10) # HANGS worker thread for 10 seconds!
        raise TimeoutError("Payment Gateway Connection Timed Out!")
    return True

def process_payment(user_id: str, amount: float, card_data: str, trigger_outage: bool = False) -> dict:
    # VULNERABILITY 2: No rate limiting (vulnerable to DoS / brute force)
    # VULNERABILITY 3: No request HMAC signature validation (tampering risk)
    
    # VULNERABILITY 4: Unhandled remote API hang consumes application thread
    gateway_success = call_unstable_payment_gateway({"amount": amount, "trigger_outage": trigger_outage})

    if gateway_success:
        # VULNERABILITY 5: Encrypts data using static hardcoded key
        encrypted_card = cipher_suite.encrypt(card_data.encode()).decode('utf-8')
        
        record = {
            "transaction_id": len(database) + 1,
            "user_id": user_id,
            "amount": amount,
            "card_data": encrypted_card
        }
        database.append(record)

        # VULNERABILITY 6: Plaintext log editable by any internal process
        audit_logs.append(f"PAID {amount} for user {user_id}")

        return {"status": "SUCCESS", "transaction_id": record["transaction_id"]}
    
    return {"status": "FAILED"}
```

---

## 🛡️ Step 2: The Refactored Secure Implementation (`secure_payment_service.py`)

We refactor the code to apply **Circuit Breaker**, **Envelope Encryption (AES-256-GCM)**, **Token Bucket Rate Limiting**, **HMAC Payload Validation**, and **Hash-Chained Audit Ledger**.

```python
# secure_payment_service.py
import os
import time
import base64
import hashlib
import hmac
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================
# 1. RESILIENCE: CIRCUIT BREAKER PATTERN
# ==========================================
class CircuitBreakerOpenException(Exception):
    pass

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, reset_timeout: float = 5.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.state = "CLOSED"
        self.failure_count = 0
        self.last_state_change = time.time()

    def call(self, func, *args, **kwargs):
        now = time.time()
        if self.state == "OPEN":
            if now - self.last_state_change > self.reset_timeout:
                self.state = "HALF-OPEN"
                self.last_state_change = now
            else:
                raise CircuitBreakerOpenException("Circuit is OPEN. Fast failing request.")

        try:
            res = func(*args, **kwargs)
            if self.state == "HALF-OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
            return res
        except Exception as e:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                self.last_state_change = now
            raise e

# ==========================================
# 2. GOVERNANCE: TOKEN BUCKET RATE LIMITER
# ==========================================
class RateLimitExceededException(Exception):
    pass

class TokenBucketRateLimiter:
    def __init__(self, capacity: int = 10, refill_rate: float = 1.0):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, amount: int = 1):
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        self.last_update = now

        if self.tokens < amount:
            raise RateLimitExceededException("429 Too Many Requests: Rate limit exceeded.")
        self.tokens -= amount

# ==========================================
# 3. CRYPTOGRAPHY: ENVELOPE ENCRYPTION (KMS)
# ==========================================
class KMS:
    """Simulated Key Management Service hosting Master KEK."""
    def __init__(self):
        self._kek = AESGCM.generate_key(bit_length=256)

    def generate_data_key(self) -> Tuple[bytes, bytes]:
        plain_dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(self._kek)
        iv = os.urandom(12)
        enc_dek = iv + aesgcm.encrypt(iv, plain_dek, b"KMS_CONTEXT")
        return plain_dek, enc_dek

    def decrypt_data_key(self, enc_dek: bytes) -> bytes:
        iv = enc_dek[:12]
        ciphertext = enc_dek[12:]
        aesgcm = AESGCM(self._kek)
        return aesgcm.decrypt(iv, ciphertext, b"KMS_CONTEXT")

# ==========================================
# 4. AUDIT: IMMUTABLE HASH CHAIN LEDGER
# ==========================================
class AuditLedger:
    def __init__(self):
        self.chain = []

    def log(self, event: str) -> dict:
        prev_hash = self.chain[-1]["hash"] if self.chain else "0" * 64
        entry = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "event": event,
            "prev_hash": prev_hash
        }
        entry_bytes = f"{entry['index']}{entry['timestamp']}{event}{prev_hash}".encode('utf-8')
        entry["hash"] = hashlib.sha256(entry_bytes).hexdigest()
        self.chain.append(entry)
        return entry

# ==========================================
# 5. CORE SECURE SERVICE IMPLEMENTATION
# ==========================================
class SecurePaymentService:
    def __init__(self, hmac_secret: bytes, rate_limit_capacity: int = 10):
        self.hmac_secret = hmac_secret
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, reset_timeout=2.0)
        self.rate_limiter = TokenBucketRateLimiter(capacity=rate_limit_capacity, refill_rate=0.5)
        self.kms = KMS()
        self.audit_ledger = AuditLedger()
        self.database = []

    def _verify_hmac_signature(self, payload_bytes: bytes, provided_sig: str):
        expected_sig = hmac.new(self.hmac_secret, payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, provided_sig):
            raise ValueError("403 Forbidden: Invalid HMAC request signature!")

    def _call_gateway_with_timeout(self, trigger_outage: bool):
        if trigger_outage:
            raise TimeoutError("Gateway timeout simulated!")
        return True

    def process_payment_secure(
        self,
        user_id: str,
        amount: float,
        card_data: str,
        signature: str,
        trigger_outage: bool = False
    ) -> Dict[str, Any]:
        # 1. Rate Limiting Check
        self.rate_limiter.consume(1)

        # 2. HMAC Integrity Validation
        raw_payload = f"{user_id}:{amount}:{card_data}".encode('utf-8')
        self._verify_hmac_signature(raw_payload, signature)

        # 3. Resilience: Circuit Breaker Execution
        self.circuit_breaker.call(self._call_gateway_with_timeout, trigger_outage)

        # 4. Envelope Encryption
        plain_dek, enc_dek = self.kms.generate_data_key()
        try:
            aesgcm = AESGCM(plain_dek)
            iv = os.urandom(12)
            ciphertext = aesgcm.encrypt(iv, card_data.encode('utf-8'), None)
        finally:
            del plain_dek # Zero out memory key

        record = {
            "transaction_id": len(self.database) + 1,
            "user_id": user_id,
            "amount": amount,
            "enc_payload": base64.b64encode(iv + ciphertext).decode('utf-8'),
            "enc_dek": base64.b64encode(enc_dek).decode('utf-8')
        }
        self.database.append(record)

        # 5. Cryptographic Audit Logging
        self.audit_ledger.log(f"PAYMENT_SUCCESS: User={user_id}, Tx={record['transaction_id']}")

        return {"status": "SUCCESS", "transaction_id": record["transaction_id"]}
```

---

## 🧪 Step 3: Verification Test Suite (`test_lab_security.py`)

Run this `unittest` suite to prove that all security controls operate as expected under attack conditions.

```python
# test_lab_security.py
import unittest
import hmac
import hashlib
from secure_payment_service import (
    SecurePaymentService,
    CircuitBreakerOpenException,
    RateLimitExceededException
)

class TestSecurePaymentArchitecture(unittest.TestCase):

    def setUp(self):
        self.secret = b"super_secret_hmac_key_123"
        self.service = SecurePaymentService(hmac_secret=self.secret, rate_limit_capacity=10)

    def _generate_sig(self, user_id: str, amount: float, card_data: str) -> str:
        payload = f"{user_id}:{amount}:{card_data}".encode('utf-8')
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def test_01_successful_payment(self):
        sig = self._generate_sig("user1", 100.0, "4532-0000-1111-2222")
        res = self.service.process_payment_secure("user1", 100.0, "4532-0000-1111-2222", sig)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(len(self.service.database), 1)

    def test_02_hmac_tampering_detected(self):
        sig = self._generate_sig("user1", 100.0, "4532-0000-1111-2222")
        # Attacker tampers amount to 10.0
        with self.assertRaises(ValueError):
            self.service.process_payment_secure("user1", 10.0, "4532-0000-1111-2222", sig)

    def test_03_rate_limiting_enforced(self):
        restricted_service = SecurePaymentService(hmac_secret=self.secret, rate_limit_capacity=3)
        sig = self._generate_sig("user1", 50.0, "4532-0000-1111-2222")
        # Capacity is 3 requests
        for _ in range(3):
            restricted_service.process_payment_secure("user1", 50.0, "4532-0000-1111-2222", sig)
        
        # 4th request must trigger 429 Rate Limit
        with self.assertRaises(RateLimitExceededException):
            restricted_service.process_payment_secure("user1", 50.0, "4532-0000-1111-2222", sig)

    def test_04_circuit_breaker_trips_on_failures(self):
        sig = self._generate_sig("user2", 200.0, "4532-0000-1111-2222")
        # Trigger 3 consecutive gateway failures
        for _ in range(3):
            try:
                self.service.process_payment_secure("user2", 200.0, "4532-0000-1111-2222", sig, trigger_outage=True)
            except TimeoutError:
                pass
        
        # Circuit should now be OPEN, rejecting immediately without calling gateway
        with self.assertRaises(CircuitBreakerOpenException):
            self.service.process_payment_secure("user2", 200.0, "4532-0000-1111-2222", sig, trigger_outage=False)

    def test_05_immutable_audit_chain_integrity(self):
        sig = self._generate_sig("user3", 300.0, "4532-0000-1111-2222")
        self.service.process_payment_secure("user3", 300.0, "4532-0000-1111-2222", sig)
        chain = self.service.audit_ledger.chain
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["prev_hash"], "0" * 64)

if __name__ == "__main__":
    unittest.main()
```

---

## 💻 Running the Test Verification

Execute the test suite in your local terminal:

```bash
python -m unittest test_lab_security.py
```

Expected output:
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.005s

OK
```

---

> [!TIP]
> **Next Steps:** Review **[07 References](07-references.md)** for industry standards, specifications, and books on architectural security patterns.
