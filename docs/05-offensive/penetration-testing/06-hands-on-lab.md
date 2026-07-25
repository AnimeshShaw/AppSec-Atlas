# 06. Hands-On Audit Lab

In this hands-on lab, you will audit a **target Flask application**, run an automated Python audit script to discover security misconfigurations, calculate CVSS scores, and verify the remediation fix.

---

## 🧪 Lab Scenario

### Step 1: Target Flask App (`target_app.py`)

```python
# target_app.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerable Endpoint: Verbose Error & Missing Security Headers
@app.route('/api/v1/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    if not query:
        # VULNERABLE: Exposes internal stack trace / system details!
        return jsonify({"error": "Missing parameter q", "internal_debug": "DB_CONN_STR=postgresql://user:pass@localhost/db"}), 400
    return jsonify({"results": f"Found results for: {query}"})

if __name__ == '__main__':
    app.run(port=5007)
```

---

### Step 2: Security Audit Script (`audit_target.py`)

```python
# audit_target.py
import requests

TARGET_URL = "http://localhost:5007/api/v1/search"

print("=== STARTING PENTEST AUDIT SCAN ===")
resp = requests.get(TARGET_URL)

print(f"Status Code: {resp.status_code}")
print(f"Response: {resp.text}")

if "internal_debug" in resp.text:
    print("🚨 VULNERABILITY DISCOVERED: Information Disclosure (Verbose Error / Credentials Leaked)")
    print("CVSS v4.0 Score: 7.5 (High) - CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N")
```

---

### Step 3: Secure Fix (`secure_app.py`)

```python
# secure_app.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/api/v1/search', methods=['GET'])
def search_secure():
    query = request.args.get('q', '')
    if not query:
        # SECURE: Generic error message without internal state exposure
        return jsonify({"error": "Invalid or missing search parameter"}), 400
    return jsonify({"results": f"Found results for: {query}"})

if __name__ == '__main__':
    app.run(port=5007)
```

---

*Next Chapter: [07. References & Standards →](07-references.md)*
