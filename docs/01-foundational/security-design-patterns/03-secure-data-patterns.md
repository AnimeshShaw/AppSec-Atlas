---
title: "03 - Secure Data Patterns"
description: "Protecting data at rest and in transit requires robust patterns that go beyond simple encryption."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Security Design Patterns", "03 Secure Data Patterns.Md"]
---

# 03 - Secure Data Patterns

Protecting data at rest and in transit requires robust patterns that go beyond simple encryption.

## 1. Envelope Encryption Pattern
Envelope encryption involves encrypting data with a Data Encryption Key (DEK), and then encrypting the DEK with a Key Encryption Key (KEK). This pattern is highly efficient and integrates well with Key Management Services (KMS).

**Flow:**
1. Generate a plain DEK.
2. Encrypt the data using the plain DEK.
3. Send the plain DEK to KMS to be encrypted by the KEK.
4. Store the encrypted data alongside the encrypted DEK.
5. Discard the plain DEK.

```java
// Java conceptual example
byte[] plainData = "Sensitive User Information".getBytes();
byte[] plainDEK = generateAESKey();
byte[] encryptedData = aesEncrypt(plainData, plainDEK);
byte[] encryptedDEK = kms.encrypt(plainDEK, "arn:aws:kms:...:key/my-kek");

storeToDatabase(encryptedData, encryptedDEK);
```

## 2. Tokenization & Anonymization Pattern
Tokenization replaces sensitive data (like credit card numbers) with non-sensitive substitutes (tokens) that have no extrinsic or exploitable meaning. Anonymization removes Personally Identifiable Information (PII) from datasets, ensuring individuals cannot be identified.

## 3. Data Sanitization Pipeline
A centralized pattern where all incoming data passes through a strict validation and sanitization pipeline before reaching the core application logic. This centralizes the defense against XSS, SQLi, and command injection.

## 4. Immutable Ledger Auditing
Security-critical logs and audit trails should be stored in an append-only, immutable format. This ensures that even if an attacker compromises the system, they cannot alter the history of their actions. Often implemented using specialized databases (like Amazon QLDB) or cryptographic hashing (blockchain concepts).
