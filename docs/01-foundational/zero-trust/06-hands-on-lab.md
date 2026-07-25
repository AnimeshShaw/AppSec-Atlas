# Hands-on Lab: From Perimeter to Zero Trust

## Scenario
A vulnerable application trusts all requests originating from the internal network (`10.0.0.0/8`). 

## Vulnerable Implementation (Perimeter-Based)
```python
# vulnerable_app.py
from fastapi import FastAPI, Request, HTTPException
import ipaddress

app = FastAPI()

INTERNAL_NET = ipaddress.ip_network("10.0.0.0/8")

@app.get("/admin/data")
async def get_admin_data(request: Request):
    client_ip = ipaddress.ip_address(request.client.host)
    # VULNERABILITY: Implicit trust based on network location
    if client_ip not in INTERNAL_NET:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"secret": "Super confidential data"}
```

## Exploit
If an attacker breaches a low-privileged container in the internal network, they can freely query the admin endpoint.
```bash
curl http://admin-service/admin/data
# Output: {"secret": "Super confidential data"}
```

## Secure Implementation (Zero Trust)
```python
# secure_app.py
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

app = FastAPI()
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        # In reality, verify signature with IdP's public key
        token = jwt.decode(credentials.credentials, "secret", algorithms=["HS256"])
        if token.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        if not token.get("device_compliant"):
            raise HTTPException(status_code=403, detail="Device posture non-compliant")
        return token
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/admin/data")
async def get_admin_data(token_data: dict = Depends(verify_token)):
    # TRUST VERIFIED: Identity, role, and device context validated
    return {"secret": "Super confidential data"}
```
