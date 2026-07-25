---
title: "Hands-On Lab: Implementing GDPR Controls"
description: "Comprehensive guide and best practices for Hands-On Lab: Implementing GDPR Controls in the gdpr-technical section of AppSec Atlas. Learn how to secure your infr"
keywords: ['gdpr-technical', 'hands-on-lab:-implementing-gdpr-controls', 'appsec', 'security', 'compliance']
---
# Hands-On Lab: Implementing GDPR Controls

In this lab, we will remediate a non-compliant Python script that stores plain-text PII and fails to handle the "Right to be Forgotten".

## Scenario
You inherited a legacy application that stores user data, including passwords and Social Security Numbers (SSNs), in plain text. When users delete their accounts, it performs a soft delete, leaving the PII intact.

### Vulnerable Code (`vulnerable_app.py`)
```python
import sqlite3

def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT, is_deleted INTEGER)''')
    c.execute("INSERT INTO users (name, email, ssn, is_deleted) VALUES ('Alice', 'alice@test.com', '123-45-678', 0)")
    conn.commit()
    return conn

def delete_user(conn, email):
    # VULNERABILITY: Soft delete leaves PII in the database (Article 17 Violation)
    c = conn.cursor()
    c.execute("UPDATE users SET is_deleted = 1 WHERE email = ? AND is_deleted = 0", (email,))
    conn.commit()
```

## Task 1: Pseudonymization (Encryption)
Instead of storing SSNs in plain text, we will encrypt them using symmetric encryption (AES).

## Task 2: Implementing the Right to Erasure
Modify the `delete_user` function to overwrite the PII (Tombstone pattern) when a user requests account deletion.

### Secure Remediation (`secure_app.py`)
```python
import sqlite3
from cryptography.fernet import Fernet

# In production, load this from a secure secrets manager
KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)

def encrypt_ssn(ssn: str) -> str:
    return cipher_suite.encrypt(ssn.encode()).decode()

def decrypt_ssn(encrypted_ssn: str) -> str:
    return cipher_suite.decrypt(encrypted_ssn.encode()).decode()

def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, name TEXT, email TEXT, encrypted_ssn TEXT, is_deleted INTEGER)''')
    
    # Store encrypted data
    safe_ssn = encrypt_ssn('123-45-678')
    c.execute("INSERT INTO users (name, email, encrypted_ssn, is_deleted) VALUES (?, ?, ?, 0)", 
              ('Alice', 'alice@test.com', safe_ssn))
    conn.commit()
    return conn

def right_to_erasure(conn, email):
    """
    Complies with Article 17 by irreversibly destroying PII.
    """
    c = conn.cursor()
    # Overwrite PII with tombstone values, but keep the record if needed for referential integrity
    c.execute("""
        UPDATE users 
        SET name = 'REDACTED', 
            email = 'deleted-' || id || '@redacted.local', 
            encrypted_ssn = 'REDACTED',
            is_deleted = 1 
        WHERE email = ?
    """, (email,))
    conn.commit()

# Execution
if __name__ == "__main__":
    conn = init_db()
    print("Executing Right to Erasure for Alice...")
    right_to_erasure(conn, 'alice@test.com')

    # Verify Deletion
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    print("Database contents after erasure:", cursor.fetchall())
```

### Lab Verification
Run the `secure_app.py`. You should see that Alice's original email and SSN are no longer recoverable from the database, satisfying GDPR Article 17.


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
