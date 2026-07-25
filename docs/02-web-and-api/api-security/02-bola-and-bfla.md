---
title: "02. BOLA & BFLA Masterclass"
description: "Broken Object Level Authorization (**BOLA / API1**) and Broken Function Level Authorization (**BFLA / API5**) constitute over 40% of all API security ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Api Security", "02 Bola And Bfla.Md"]
---

# 02. BOLA & BFLA Masterclass

Broken Object Level Authorization (**BOLA / API1**) and Broken Function Level Authorization (**BFLA / API5**) constitute over 40% of all API security vulnerabilities in production.

---

## 1. BOLA (Broken Object Level Authorization)

BOLA occurs when an API endpoint takes an object identifier (e.g., `/api/v1/orders/8841`) and accesses the record without validating that the authenticated user owns that specific object.

### ❌ Vulnerable Node.js (Express) Code
```javascript
// VULNERABLE: Fetches account details using ID parameter without checking req.user.id
app.get('/api/v1/accounts/:accountId', verifyJWT, async (req, res) => {
  const account = await Account.findById(req.params.accountId);
  if (!account) return res.status(404).json({ error: "Account not found" });
  res.json(account);
});
```

### ✅ Secure Node.js Code
```javascript
// SECURE: Enforces that account.ownerId matches req.user.id
app.get('/api/v1/accounts/:accountId', verifyJWT, async (req, res) => {
  const account = await Account.findOne({
    _id: req.params.accountId,
    ownerId: req.user.id // Ownership boundary check!
  });
  
  if (!account) {
    return res.status(404).json({ error: "Account not found or access denied" });
  }
  res.json(account);
});
```

---

## 2. BFLA (Broken Function Level Authorization)

BFLA occurs when administrative or sensitive API methods (e.g., `DELETE /api/users/:id` or `POST /api/admin/export`) are accessible to regular users because function-level role permissions are missing.

### ❌ Vulnerable Python (Flask) Code
```python
# VULNERABLE: Only checks if user is logged in, but fails to check if user.role == 'ADMIN'
@app.route('/api/v1/admin/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    User.delete_by_id(user_id)
    return jsonify({"message": "User deleted successfully"})
```

### ✅ Secure Python (Flask) Code
```python
# SECURE: Role-Based Access Control (RBAC) Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'ADMIN':
            return jsonify({"error": "Forbidden: Requires Admin Role"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/v1/admin/users/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user_secure(user_id):
    User.delete_by_id(user_id)
    return jsonify({"message": "User deleted successfully"})
```

---

## 3. Mass Assignment (API3 - Broken Property Level Authorization)

Mass Assignment occurs when client input automatically binds to internal data model fields without filtering, allowing attackers to modify fields like `is_admin`, `balance`, or `role`.

### ❌ Vulnerable Python Code
```python
# VULNERABLE: Binds entire JSON payload directly into User object!
@app.route('/api/v1/profile', methods=['PUT'])
@login_required
def update_profile():
    # Attacker sends: {"name": "Bob", "is_admin": true, "balance": 999999}
    user_data = request.get_json()
    for key, value in user_data.items():
        setattr(current_user, key, value) # Dangerous!
    db.session.commit()
    return jsonify({"message": "Profile updated"})
```

### ✅ Secure Python Code (Allowlisting / DTO Pattern)
```python
# SECURE: Explicitly allowlist only editable fields
ALLOWED_FIELDS = {'name', 'bio', 'phone_number'}

@app.route('/api/v1/profile', methods=['PUT'])
@login_required
def update_profile_secure():
    user_data = request.get_json()
    
    for key, value in user_data.items():
        if key in ALLOWED_FIELDS: # Only update permitted properties!
            setattr(current_user, key, value)
            
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"})
```

---

*Next Chapter: [03. GraphQL & gRPC Security →](03-graphql-and-grpc-security.md)*
