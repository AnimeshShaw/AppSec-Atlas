---
title: "03 Reviewing Data Handling and Injection"
description: "Data handling flaws occur when untrusted data is processed without sufficient validation, sanitization, or parameterization."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "09 Hands On", "Code Review Guide", "03 Reviewing Data Handling And Injection.Md"]
---

# 03 Reviewing Data Handling and Injection

Data handling flaws occur when untrusted data is processed without sufficient validation, sanitization, or parameterization.

## 1. SQL Injection (SQLi)

**Context:** SQLi happens when user input is dynamically concatenated directly into a SQL query string.

### Vulnerable Pattern (Node.js/Express)
```javascript
app.get('/users', async (req, res) => {
    const username = req.query.username;
    // BAD: String concatenation
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    const result = await db.query(query);
    res.json(result);
});
```

### Secure Pattern (Node.js/Express)
```javascript
app.get('/users', async (req, res) => {
    const username = req.query.username;
    // GOOD: Parameterized query
    const query = 'SELECT * FROM users WHERE username = $1';
    const result = await db.query(query, [username]);
    res.json(result);
});
```

## 2. Server-Side Request Forgery (SSRF)

**Context:** SSRF occurs when an application fetches a remote resource based on user-supplied URLs without adequate validation.

### Vulnerable Pattern (Python/Requests)
```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # BAD: Fetching arbitrary URL (can hit internal metadata APIs like 169.254.169.254)
    response = requests.get(url)
    return response.content
```

### Secure Pattern (Python/Requests)
```python
import requests
import urllib.parse
from flask import Flask, request, abort

app = Flask(__name__)
ALLOWED_DOMAINS = {"example.com", "api.example.com"}

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    parsed_url = urllib.parse.urlparse(url)
    
    # GOOD: Validate protocol and host against strict allowlist
    if parsed_url.scheme not in ("http", "https") or parsed_url.hostname not in ALLOWED_DOMAINS:
        abort(403)
        
    # Additional defense: disable redirects and set a timeout
    response = requests.get(url, allow_redirects=False, timeout=5)
    return response.content
```

## 3. Command Injection

**Context:** Passing user input directly to a system shell can lead to arbitrary command execution.

### Vulnerable Pattern (Java)
```java
public void pingHost(String ipAddress) throws IOException {
    // BAD: Executing raw shell command with user input
    String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + ipAddress};
    Runtime.getRuntime().exec(cmd);
}
```

### Secure Pattern (Java)
```java
public void pingHost(String ipAddress) throws IOException {
    // PREFERRED: Use built-in libraries instead of shell commands
    // InetAddress.getByName(ipAddress).isReachable(5000);
    
    // GOOD: If you must execute, avoid the shell (-c) and pass arguments strictly as an array
    if (!ipAddress.matches("^[a-zA-Z0-9.-]+$")) {
        throw new IllegalArgumentException("Invalid IP");
    }
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", ipAddress);
    pb.start();
}
```
