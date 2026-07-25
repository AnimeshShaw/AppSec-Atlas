# 06 Hands-on Lab: Secure Code Review

In this lab, you act as the Security Champion reviewing a Pull Request (PR) for a new Python/Flask microservice.

## The Pull Request (Vulnerable Code)

**Context:** The developer is adding an endpoint to download invoice PDFs and an endpoint to generate API tokens.

```diff
--- a/app.py
+++ b/app.py
@@ -1,5 +1,8 @@
 from flask import Flask, request, send_file
+import os
+import random
+import string
 
 app = Flask(__name__)
 
@@ -15,5 +18,17 @@
 
+@app.route('/download')
+def download_invoice():
+    filename = request.args.get('file')
+    # Feature: Download invoices from the reports directory
+    filepath = os.path.join('/app/data/reports', filename)
+    return send_file(filepath)
+
+@app.route('/generate_token')
+def generate_token():
+    chars = string.ascii_letters + string.digits
+    token = ''.join(random.choice(chars) for _ in range(32))
+    return {"api_token": token}
```

## Security Reviewer Findings Checklist

As a reviewer, you should flag the following issues:

1. **Path Traversal (CWE-22):** 
   - **Line:** `filepath = os.path.join('/app/data/reports', filename)`
   - **Risk:** An attacker can provide `file=../../../../etc/passwd` to read arbitrary system files. `os.path.join` does not sanitize path traversal characters.
2. **Insecure Randomness (CWE-338):**
   - **Line:** `token = ''.join(random.choice(chars) for _ in range(32))`
   - **Risk:** The `random` module is predictable. Attackers could theoretically predict generated API tokens.

## Hardened Refactored Pull Request

Here is how the developer should refactor the code based on the review.

```diff
--- a/app.py
+++ b/app.py
@@ -1,5 +1,8 @@
-from flask import Flask, request, send_file
+from flask import Flask, request, send_file, abort
 import os
-import random
+import secrets
 import string
+from werkzeug.utils import secure_filename
 
 app = Flask(__name__)
 
@@ -15,5 +18,22 @@
 
 @app.route('/download')
 def download_invoice():
     filename = request.args.get('file')
-    filepath = os.path.join('/app/data/reports', filename)
-    return send_file(filepath)
+    
+    # FIX: Sanitize the filename to prevent path traversal
+    safe_filename = secure_filename(filename)
+    if not safe_filename:
+        abort(400, "Invalid filename")
+        
+    filepath = os.path.join('/app/data/reports', safe_filename)
+    
+    # Additional defense: verify absolute path remains within intended directory
+    if not os.path.abspath(filepath).startswith('/app/data/reports/'):
+        abort(403)
+        
+    return send_file(filepath)
 
 @app.route('/generate_token')
 def generate_token():
     chars = string.ascii_letters + string.digits
-    token = ''.join(random.choice(chars) for _ in range(32))
+    # FIX: Use cryptographically secure randomness
+    token = ''.join(secrets.choice(chars) for _ in range(32))
     return {"api_token": token}
```
