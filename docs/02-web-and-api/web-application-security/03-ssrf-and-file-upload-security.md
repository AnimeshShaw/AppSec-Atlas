---
title: "03 - SSRF and File Upload Security"
description: "SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL. Attackers can force the application to send cra..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "02 Web And Api", "Web Application Security", "03 Ssrf And File Upload Security.Md"]
---

# 03 - SSRF and File Upload Security

## Server-Side Request Forgery (SSRF)
SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL. Attackers can force the application to send crafted requests to unintended destinations, such as internal services (e.g., cloud metadata endpoints at `169.254.169.254`).

### SSRF Bypasses
- URL encoding or alternate IP representations (e.g., `http://2852039166` instead of `http://169.254.169.254`).
- DNS rebinding.
- Open redirects on trusted domains.

### Secure Python Implementation
```python
import requests
import socket
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    try:
        parsed_url = urlparse(url)
        # Ensure scheme is http or https
        if parsed_url.scheme not in ['http', 'https']:
            return False
            
        # Resolve IP to prevent DNS rebinding attacks to internal IPs
        ip = socket.gethostbyname(parsed_url.hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Deny private, loopback, and reserved IP ranges
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
            
        return True
    except Exception:
        return False

def fetch_url(url):
    if not is_safe_url(url):
        raise ValueError("Invalid or unsafe URL")
    # Timeout is essential to prevent DoS
    return requests.get(url, timeout=5)
```

## File Upload Security
Unrestricted file upload can lead to Remote Code Execution (RCE), XSS, or system compromise.

### Defensive Practices
1. Validate MIME types and file extensions against a strict allowlist.
2. Strip EXIF and metadata (which can conceal payloads).
3. Generate random, unpredictable filenames.
4. Store files outside the web root or on a separate domain.
5. Limit file sizes.

### Secure File Upload in Python (Flask)
```python
import os
import uuid
from werkzeug.utils import secure_filename
from PIL import Image

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
UPLOAD_FOLDER = '/path/to/upload/dir'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_safe_image(file_storage):
    if not allowed_file(file_storage.filename):
        raise ValueError("File type not allowed")
        
    # Generate random filename
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    random_filename = f"{uuid.uuid4().hex}.{ext}"
    
    # Strip EXIF via PIL
    try:
        image = Image.open(file_storage)
        
        # Save image without EXIF data
        data = list(image.getdata())
        image_without_exif = Image.new(image.mode, image.size)
        image_without_exif.putdata(data)
        
        save_path = os.path.join(UPLOAD_FOLDER, random_filename)
        image_without_exif.save(save_path)
        return random_filename
    except Exception as e:
        raise ValueError("Invalid image file")
```

## Path Traversal (`../`)
Path traversal allows an attacker to access files outside the intended directory.
Always sanitize file paths. `secure_filename` from `werkzeug.utils` is a good starting point, but restricting reads to specific directories via absolute path comparisons is safer.
