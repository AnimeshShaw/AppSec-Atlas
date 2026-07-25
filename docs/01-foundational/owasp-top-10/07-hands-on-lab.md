---
title: "07. Hands-On Vulnerability Lab"
description: "In this lab, you will audit a **vulnerable Flask e-commerce API**, exploit an IDOR vulnerability to view another user's private credit card data, and ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Owasp Top 10", "07 Hands On Lab.Md"]
---

# 07. Hands-On Vulnerability Lab

In this lab, you will audit a **vulnerable Flask e-commerce API**, exploit an IDOR vulnerability to view another user's private credit card data, and then apply the secure fix.

---

## 🧪 Lab Setup

### Step 1: Create Vulnerable API (`owasp_lab_app.py`)

```python
# owasp_lab_app.py
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, card_number TEXT)')
    cursor.execute("INSERT INTO users VALUES (101, 'alice', '4532-XXXX-XXXX-9811')")
    cursor.execute("INSERT INTO users VALUES (102, 'bob', '4111-XXXX-XXXX-1122')")
    conn.commit()
    return conn

db = init_db()

# VULNERABLE ENDPOINT: IDOR / Broken Access Control
@app.route('/api/user/<int:user_id>/card', methods=['GET'])
def get_user_card(user_id):
    # Simulated authentication: Current logged-in user is 'bob' (ID: 102)
    logged_in_user_id = 102 
    
    # VULNERABLE: Fetches card by user_id URL parameter without checking logged_in_user_id!
    cursor = db.cursor()
    cursor.execute(f"SELECT username, card_number FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    
    if not row:
        return jsonify({"error": "User not found"}), 404
        
    return jsonify({"username": row[0], "card_number": row[1]})

if __name__ == '__main__':
    app.run(port=5005)
```

---

### Step 2: Create Exploit Test (`exploit_owasp.py`)

```python
# exploit_owasp.py
import requests

BASE_URL = "http://localhost:5005"

print("=== EXPLOITING IDOR VULNERABILITY ===")
print("Attacker (Bob, ID: 102) requesting Alice's (ID: 101) credit card data...\n")

# Bob requests Alice's ID (101)
response = requests.get(f"{BASE_URL}/api/user/101/card")

print(f"HTTP Status Code: {response.status_code}")
print(f"Response Payload: {response.text}")

if response.status_code == 200 and "alice" in response.text:
    print("\n🚨 VULNERABILITY CONFIRMED: IDOR Exploited! Alice's credit card leaked to Bob.")
else:
    print("\n✅ Access denied or secure.")
```

---

### Step 3: Implement Secure Fix (`secure_owasp_app.py`)

```python
# secure_owasp_app.py
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# SECURE ENDPOINT: Enforce Ownership Authorization Check
@app.route('/api/user/<int:user_id>/card', methods=['GET'])
def get_user_card_secure(user_id):
    # Simulated authentication context
    logged_in_user_id = 102 
    
    # SECURE FIX 1: Access Control Ownership Check
    if logged_in_user_id != user_id:
        return jsonify({"error": "Forbidden: You do not have permission to view this card"}), 403
        
    # SECURE FIX 2: Parameterized SQL Query
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT username, card_number FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    
    return jsonify({"username": row[0], "card_number": row[1]})
```

---

*Next Chapter: [08. References & Tooling →](08-references.md)*
