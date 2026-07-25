---
title: "Data Subject Rights and Consent Management"
description: "A major part of privacy engineering is building systems to respect Data Subject Rights (DSRs) automatically."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "07 Specialized", "Privacy Engineering", "04 Data Subject Rights And Consent.Md"]
---

# Data Subject Rights and Consent Management

A major part of privacy engineering is building systems to respect Data Subject Rights (DSRs) automatically. 

## Data Subject Access Requests (DSAR)
Individuals have the right to request a copy of all their personal data (Right of Access) or ask for it to be deleted (Right to Erasure).

### Automated Data Deletion Workflows
Data is rarely in one place. An automated workflow needs to orchestrate deletion across:
1. Primary Relational DBs (e.g., PostgreSQL, MySQL)
2. NoSQL / Document Stores (e.g., MongoDB, DynamoDB)
3. Data Warehouses / Lakes (e.g., Snowflake, S3)
4. Third-party SaaS tools via APIs (e.g., Salesforce, Zendesk)

#### Python Example: Simple Deletion Orchestrator
```python
import requests

def delete_user_data(user_id):
    # 1. Delete from internal Database
    db_status = delete_from_internal_db(user_id)
    
    # 2. Delete from 3rd Party Marketing Tool
    marketing_api_url = f"https://api.marketing-tool.com/users/{user_id}"
    marketing_status = requests.delete(marketing_api_url, headers={"Authorization": "Bearer TOKEN"})
    
    # 3. Log the deletion for compliance auditing (without keeping the PII)
    log_deletion_event(user_id_hash=hash(user_id), status="SUCCESS")

    return db_status and marketing_status.status_code == 200

def delete_from_internal_db(user_id):
    # Execute SQL: DELETE FROM users WHERE id = %s
    return True

def log_deletion_event(user_id_hash, status):
    # Store audit trail
    pass
```

## Consent Management Platforms (CMP)
Consent must be explicitly given, informed, and easy to revoke. Consent state should be stored immutably and verified before any data processing pipeline runs.

### Node.js Example: Verifying Consent Before Processing
```javascript
async function processUserData(userId, processingPurpose) {
    const userConsent = await getConsentRecord(userId);
    
    if (!userConsent.granted_purposes.includes(processingPurpose)) {
        throw new Error(`Consent not granted for processing purpose: ${processingPurpose}`);
    }
    
    // Proceed with processing
    console.log(`Processing user data for ${processingPurpose}`);
}
```
