# 02. A01: Broken Access Control & IDOR

Broken Access Control is the **#1 most prevalent web application vulnerability**. It occurs when an application fails to properly enforce permissions, allowing users to access resources, perform actions, or view data belonging to other users or administrators.

---

## 1. Vulnerability Breakdown: IDOR / BOLA

**Insecure Direct Object Reference (IDOR)** — also known as **Broken Object-Level Authorization (BOLA)** — happens when an API endpoint uses a user-supplied key (e.g., ID in URL) to fetch a database record without checking if the logged-in user owns that record.

```
Attacker (User ID: 105) ──► GET /api/v1/invoices/104 ──► Server fetches Invoice #104 without ownership check
                                                                        │
                                                                        ▼
                                                         Returns Victim's Private Invoice!
```

---

## 2. Side-by-Side Code Examples & Mitigations

### Example A: Python (Flask & SQLAlchemy)

#### ❌ Vulnerable Code (Python)
```python
# VULNERABLE: Direct database fetch using URL parameter without ownership check
@app.route('/api/user/profile/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    # Attacker passes user_id = 999 to read another user's profile!
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"email": user.email, "ssn": user.ssn, "address": user.address})
```

#### ✅ Secure Code (Python)
```python
# SECURE: Enforce ownership check using current authenticated user token
@app.route('/api/user/profile/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    current_user_id = get_jwt_identity()
    
    # Ownership Check: Only allow if requesting own profile OR if caller is ADMIN
    if current_user_id != user_id and not current_user_is_admin():
        return jsonify({"error": "Forbidden: You do not have permission to view this profile"}), 403
        
    user = User.query.get(user_id)
    return jsonify({"email": user.email, "address": user.address})
```

---

### Example B: Node.js (Express & MongoDB)

#### ❌ Vulnerable Code (Node.js)
```javascript
// VULNERABLE: Deletes document directly from ID parameter
app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
  // Anyone with a valid JWT can delete ANY document ID!
  const doc = await Document.findByIdAndDelete(req.params.id);
  res.json({ message: "Document deleted successfully" });
});
```

#### ✅ Secure Code (Node.js)
```javascript
// SECURE: Include ownerId in the query condition itself
app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
  const doc = await Document.findOneAndDelete({
    _id: req.params.id,
    ownerId: req.user.id // Enforces that document MUST belong to logged-in user
  });

  if (!doc) {
    return res.status(404).json({ error: "Document not found or access denied" });
  }
  res.json({ message: "Document deleted successfully" });
});
```

---

### Example C: Go (Gin Framework)

#### ❌ Vulnerable Code (Go)
```go
// VULNERABLE: Direct access without ownership check
func GetInvoice(c *gin.Context) {
    invoiceID := c.Param("id")
    var invoice Invoice
    db.First(&invoice, invoiceID) // No check against current user context!
    c.JSON(http.StatusOK, invoice)
}
```

#### ✅ Secure Code (Go)
```go
// SECURE: Filter query by user_id extracted from authenticated session
func GetInvoice(c *gin.Context) {
    userID := c.GetString("current_user_id")
    invoiceID := c.Param("id")

    var invoice Invoice
    result := db.Where("id = ? AND user_id = ?", invoiceID, userID).First(&invoice)
    if result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Invoice not found or access denied"})
        return
    }
    c.JSON(http.StatusOK, invoice)
}
```

---

## 3. Practical Testing & Exploit Verification

### Exploit Command (curl)
```bash
# 1. Login as Low-Privilege User (User ID: 102)
TOKEN=$(curl -s -X POST http://localhost:5000/api/login -d '{"user":"alice"}' | jq -r .token)

# 2. Attempt to fetch User 101's private document (IDOR Test)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/user/profile/101

# Expected Vulnerable Result: HTTP 200 OK + Private Data of User 101
# Expected Secure Result:     HTTP 403 Forbidden
```

---

*Next Chapter: [03. A02: Cryptographic Failures →](03-a02-cryptographic-failures.md)*
