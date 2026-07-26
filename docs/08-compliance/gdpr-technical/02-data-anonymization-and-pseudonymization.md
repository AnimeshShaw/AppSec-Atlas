---
title: Data Anonymization and Pseudonymization
description: Comprehensive guide and best practices for Data Anonymization and Pseudonymization
  in the gdpr-technical section of AppSec Atlas. Learn how to secure your infra
keywords:
- gdpr-technical
- data-anonymization-and-pseudonymization
- appsec
- security
- compliance
slug: /compliance/gdpr-technical/data-anonymization-and-pseudonymization
---

# Data Anonymization and Pseudonymization

Article 25 of the GDPR mandates **Data Protection by Design and by Default**. A key technical control to achieve this is the use of anonymization and pseudonymization techniques.

## Anonymization vs. Pseudonymization

- **Anonymization:** Irreversibly altering data so the subject can *never* be identified. Anonymized data falls *outside* the scope of GDPR.
- **Pseudonymization:** Replacing identifying data with artificial identifiers (pseudonyms). The data can only be re-identified with an additional "key" kept separately. Pseudonymized data remains *in* scope of GDPR but reduces risk.

## Pseudonymization Techniques

### 1. Tokenization / Data Vaulting
Store the actual PII in a highly secure, isolated "Data Vault" and use tokens in your primary application database.

### 2. HMAC (Hash-Based Message Authentication Code)
Useful when you need to match records without knowing the underlying value (e.g., matching email addresses for analytics).

```python
# Secure Pseudonymization in Python using HMAC
import hmac
import hashlib
import os

# The secret key must be stored securely (e.g., AWS KMS, HashiCorp Vault)
SECRET_PEPPER = os.getenv("APP_SECRET_PEPPER", b"super_secret_pepper_key")

def pseudonymize_email(email: str) -> str:
    """Pseudonymizes an email address using HMAC-SHA256."""
    # Normalize the input
    normalized_email = email.strip().lower().encode('utf-8')
    
    # Create the HMAC using SHA-256
    h = hmac.new(SECRET_PEPPER, normalized_email, hashlib.sha256)
    return h.hexdigest()

# Example Usage
original = "user@example.com"
pseudo = pseudonymize_email(original)
print(f"Original: {original}\nPseudonymized: {pseudo}")
```

### 3. Masking / Redaction
Displaying only parts of the data (e.g., `****-****-****-1234`). Useful for logs and UI.

```javascript
// Node.js example: Redacting PII from logs
function redactPII(logObject) {
    const redacted = { ...logObject };
    
    if (redacted.email) {
        const [username, domain] = redacted.email.split('@');
        redacted.email = `${username[0]}***@${domain}`;
    }
    
    if (redacted.creditCard) {
        redacted.creditCard = redacted.creditCard.replace(/\d(?=\d{4})/g, "*");
    }
    
    return redacted;
}

const logEntry = {
    event: "checkout",
    email: "alice.smith@example.com",
    creditCard: "4111222233334444"
};
console.log(redactPII(logEntry));
```

## PII Data Scrubbing Pipelines
When moving data from Production to Staging/Analytics, all PII must be scrubbed.

**Architecture Pattern:**
1. Extract data from Prod DB.
2. Run through a scrubbing service that applies hashing/masking based on data dictionaries.
3. Load into Staging DB.

> [!CAUTION]
> Never copy production databases directly to lower environments without scrubbing PII.


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
