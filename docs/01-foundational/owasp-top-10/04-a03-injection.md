---
title: "04. A03: Injection (SQLi, Command Injection & SSRF)"
description: "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter ..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Owasp Top 10", "04 A03 Injection.Md"]
---

# 04. A03: Injection (SQLi, Command Injection & SSRF)

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing unauthorized data.

---

## 1. SQL Injection (SQLi)

### Vulnerability Mechanics
SQL Injection occurs when user input is concatenated directly into a SQL query string instead of using parameterized queries.

```
Input: ' OR '1'='1
Query: SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '...'
Result: Returns ALL rows in database, bypassing authentication!
```

---

### Side-by-Side Code Fixes

#### A. Python (psycopg2 / PostgreSQL)

##### ❌ Vulnerable Code (Python)
```python
# VULNERABLE: String formatting allows SQL Injection
def login_user_bad(username, password):
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query) # Vulnerable!
    return cursor.fetchone()
```

##### ✅ Secure Code (Python)
```python
# SECURE: Parameterized Query separates SQL code from user data
def login_user_secure(username, password):
    query = "SELECT id, role FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password)) # Safe! Driver handles escaping.
    return cursor.fetchone()
```

---

#### B. Node.js (mysql2 / Postgres)

##### ❌ Vulnerable Code (Node.js)
```javascript
// VULNERABLE: String concatenation
app.get('/api/users/search', (req, res) => {
  const name = req.query.name;
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query(sql, (err, result) => {
    res.json(result);
  });
});
```

##### ✅ Secure Code (Node.js)
```javascript
// SECURE: Parameterized placeholder (?)
app.get('/api/users/search', (req, res) => {
  const name = req.query.name;
  const sql = "SELECT * FROM users WHERE name = ?";
  db.query(sql, [name], (err, result) => {
    res.json(result);
  });
});
```

---

## 2. Command Injection

Command Injection occurs when application code passes unsanitized user input directly to a system shell (`bash`, `cmd.exe`).

### ❌ Vulnerable Code (Python)
```python
import os

# VULNERABLE: User input passed directly to OS shell
def ping_host_bad(target_ip):
    # Input like "8.8.8.8; cat /etc/passwd" executes extra arbitrary commands!
    os.system(f"ping -c 1 {target_ip}")
```

### ✅ Secure Code (Python)
```python
import subprocess
import ipaddress

# SECURE: Avoid shell=True and validate input format strictly
def ping_host_secure(target_ip):
    # Validate input is an actual IP address
    try:
        valid_ip = str(ipaddress.ip_address(target_ip))
    except ValueError:
        raise ValueError("Invalid IP address format")
        
    # Pass arguments as a list without shell execution context
    res = subprocess.run(["ping", "-c", "1", valid_ip], capture_output=True, text=True, timeout=5)
    return res.stdout
```

---

## 3. Server-Side Request Forgery (SSRF)

SSRF occurs when a web application fetches a remote resource (e.g., URL submitted by user) without validating whether the target IP address is internal/restricted.

```
Attacker ──► Submits URL: "http://169.254.169.254/latest/meta-data/" ──► App Fetches AWS Cloud Keys!
```

### ❌ Vulnerable Code (Python)
```python
import requests

# VULNERABLE: App fetches any URL submitted by user
@app.route('/fetch-avatar')
def fetch_avatar():
    url = request.args.get('url')
    resp = requests.get(url) # Can target 127.0.0.1 or cloud IMDS!
    return resp.content
```

### ✅ Secure Code (Python - Allowlisting & IP Checks)
```python
import urllib.parse
import ipaddress
import socket
import requests

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),     # Loopback
    ipaddress.ip_network('10.0.0.0/8'),      # Private Network
    ipaddress.ip_network('172.16.0.0/12'),   # Private Network
    ipaddress.ip_network('192.168.0.0/16'),  # Private Network
    ipaddress.ip_network('169.254.0.0/16'),  # AWS Cloud Metadata (IMDS)
]

def is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
        
    hostname = parsed.hostname
    if not hostname:
        return False
        
    # Resolve hostname to IP address
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except socket.gaierror:
        return False
        
    # Block internal IP ranges
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return False # Blocked internal IP!
            
    return True
```

---

*Next Chapter: [05. A04 & A05: Insecure Design & Misconfiguration →](05-a04-insecure-design-and-misconfig.md)*
