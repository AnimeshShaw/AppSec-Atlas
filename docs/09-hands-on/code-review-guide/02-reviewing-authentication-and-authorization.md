---
title: 02 Reviewing Authentication and Authorization
description: Authentication (AuthN) and Authorization (AuthZ) are the most critical
  components of any application. Flaws here often lead to complete system comprom...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- 09
- Hands
- 'On'
- Code
- Review
- Guide
- '02'
- Reviewing
- Authentication
- And
- Authorization
- Md
slug: /hands-on/code-review-guide/reviewing-authentication-and-authorization
---


# 02 Reviewing Authentication and Authorization

Authentication (AuthN) and Authorization (AuthZ) are the most critical components of any application. Flaws here often lead to complete system compromise.

## 1. Broken Authentication: Weak Password Hashing

**Context:** Storing passwords securely is fundamental. MD5, SHA1, and even standard SHA256 are too fast and vulnerable to brute-force and dictionary attacks.

### Vulnerable Pattern (Python/Flask)
```python
import hashlib
from flask import request

@app.route('/register', methods=['POST'])
def register():
    password = request.form['password']
    # BAD: Using SHA-256 (too fast, no salt by default)
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.execute("INSERT INTO users (password) VALUES (?)", (hashed,))
```

### Secure Pattern (Python/Flask)
```python
import bcrypt
from flask import request

@app.route('/register', methods=['POST'])
def register():
    password = request.form['password'].encode('utf-8')
    # GOOD: Using bcrypt with a work factor
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt)
    db.execute("INSERT INTO users (password) VALUES (?)", (hashed,))
```

## 2. JWT Verification Bugs

**Context:** JSON Web Tokens (JWT) are widely used for stateless authentication. Common flaws include not verifying the signature or trusting the `alg` header blindly.

### Vulnerable Pattern (Node.js)
```javascript
const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    // BAD: Decoding without verifying the signature
    const decoded = jwt.decode(token); 
    if (decoded) {
        req.user = decoded;
        next();
    } else {
        res.status(401).send();
    }
}
```

### Secure Pattern (Node.js)
```javascript
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET;

function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    try {
        // GOOD: Verifying the signature and explicitly defining allowed algorithms
        const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send();
    }
}
```

## 3. Broken Object Level Authorization (BOLA / IDOR)

**Context:** BOLA occurs when an application exposes a reference to an internal implementation object but fails to check if the current user has permission to access that specific object.

### Vulnerable Pattern (Go)
```go
func GetReceipt(w http.ResponseWriter, r *http.Request) {
    // Extract receipt ID from URL (e.g., /receipts/123)
    vars := mux.Vars(r)
    receiptID := vars["id"]

    // BAD: Fetching the receipt without checking who owns it
    receipt, err := db.GetReceiptByID(receiptID)
    if err != nil {
        http.Error(w, "Not found", 404)
        return
    }
    json.NewEncoder(w).Encode(receipt)
}
```

### Secure Pattern (Go)
```go
func GetReceipt(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    receiptID := vars["id"]
    
    // Get the authenticated user ID from context
    userID := r.Context().Value("userID").(string)

    receipt, err := db.GetReceiptByID(receiptID)
    if err != nil {
        http.Error(w, "Not found", 404)
        return
    }

    // GOOD: Verify ownership before returning data
    if receipt.OwnerID != userID {
        http.Error(w, "Forbidden", 403)
        return
    }
    json.NewEncoder(w).Encode(receipt)
}
```
