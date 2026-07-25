---
title: "Identity and Device Trust"
description: "Zero Trust relies on strong identity verification (AuthN) and contextual access management (AuthZ)."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Zero Trust", "02 Identity And Device Trust.Md"]
---

# Identity and Device Trust

Zero Trust relies on strong identity verification (AuthN) and contextual access management (AuthZ).

## Contextual Access Management
Authorization decisions should factor in context:
- Identity context (MFA, roles)
- Device context (managed, patched, disk encryption)
- Network context (location, IP reputation)

### Python Example: Context-Aware Authorization

```python
# secure_auth.py
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

def check_device_posture(device_context: dict) -> bool:
    if not device_context.get("is_managed", False):
        return False
    if not device_context.get("disk_encrypted", False):
        return False
    return True

@app.middleware("http")
async def zero_trust_middleware(request: Request, call_next):
    # Extract identity and context from headers (injected by identity proxy)
    user_id = request.headers.get("X-User-Id")
    is_managed = request.headers.get("X-Device-Managed") == "true"
    disk_encrypted = request.headers.get("X-Device-Encrypted") == "true"
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    device_context = {
        "is_managed": is_managed,
        "disk_encrypted": disk_encrypted
    }
    
    if not check_device_posture(device_context):
        raise HTTPException(status_code=403, detail="Device does not meet security posture requirements")
        
    return await call_next(request)

@app.get("/")
def read_root():
    return {"message": "Access Granted: Zero Trust Verification Passed"}
```
