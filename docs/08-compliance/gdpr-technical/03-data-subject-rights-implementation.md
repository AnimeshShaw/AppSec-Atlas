---
title: "Implementing Data Subject Rights"
description: "Comprehensive guide and best practices for Implementing Data Subject Rights in the gdpr-technical section of AppSec Atlas. Learn how to secure your infrastructu"
keywords: ['gdpr-technical', 'implementing-data-subject-rights', 'appsec', 'security', 'compliance']
---
# Implementing Data Subject Rights

GDPR grants individuals specific rights regarding their personal data. Implementing these requires robust API endpoints and data orchestration.

## Article 15: Right of Access (DSAR)
Users have the right to request a copy of all their personal data.

### Implementation Strategy
Create an internal service that queries all microservices and databases for a specific `user_id`.

```python
# Python/FastAPI: Handling a DSAR request
from fastapi import APIRouter, Depends
import json

router = APIRouter()

@router.get("/api/v1/dsar/export/{user_id}")
async def export_user_data(user_id: str, current_user = Depends(get_admin_user)):
    """Aggregates all user data for a Data Subject Access Request."""
    
    # In a real app, these would call different microservices/DBs
    profile_data = db.get_user_profile(user_id)
    order_history = db.get_orders(user_id)
    support_tickets = db.get_tickets(user_id)
    
    export_payload = {
        "profile": profile_data,
        "orders": order_history,
        "support_interactions": support_tickets,
        "export_date": "2023-10-27T10:00:00Z"
    }
    
    # Return as structured JSON (satisfies Data Portability as well)
    return export_payload
```

## Article 17: Right to Erasure ("Right to be Forgotten")
Users can request deletion of their data.

### Hard Delete vs. Soft Delete
- **Soft Delete** (`deleted_at = NOW()`) is generally **NOT** sufficient for Article 17 unless the data is subsequently anonymized.
- Backups are often exempt from immediate deletion, but if data is restored from a backup, the deletion request must be re-applied.

### Implementation: The Tombstone Pattern
Instead of hard-deleting the entire row (which might break foreign keys), overwrite PII with a tombstone or anonymized value.

```javascript
// Node.js/Express: Handling Right to Erasure
app.post('/api/v1/users/:id/forget', async (req, res) => {
    const userId = req.params.id;
    
    try {
        // 1. Anonymize user profile (Tombstone)
        await db.User.update({
            first_name: 'ANONYMIZED',
            last_name: 'ANONYMIZED',
            email: `deleted-${userId}@anonymized.local`,
            phone: null,
            status: 'DELETED'
        }, { where: { id: userId } });

        // 2. Delete or anonymize related PII
        await db.UserLocations.destroy({ where: { userId } });
        
        // Note: Financial records might be retained for legal/tax reasons!
        // await db.Invoices.keep(userId); // Retained for 7 years per tax law
        
        res.status(200).json({ message: "User forgotten successfully." });
    } catch (error) {
        res.status(500).json({ error: "Erasure failed" });
    }
});
```

## Article 20: Right to Data Portability
Users can receive their data in a "structured, commonly used and machine-readable format" (e.g., JSON, XML, CSV). The DSAR JSON export example above often satisfies this requirement.


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
