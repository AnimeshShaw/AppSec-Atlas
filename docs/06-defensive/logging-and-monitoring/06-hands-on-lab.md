---
title: "06 - Hands-on Lab: Logging, Detection, & Response"
description: "In this self-contained lab, we will build a vulnerable Flask application that logs authentication events in structured JSON (ECS format). We will then..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Logging And Monitoring", "06 Hands On Lab.Md"]
---

# 06 - Hands-on Lab: Logging, Detection, & Response

In this self-contained lab, we will build a vulnerable Flask application that logs authentication events in structured JSON (ECS format). We will then write a Python script to simulate a SIEM evaluating a Sigma-like rule, triggering an automated SOAR response.

## 🏗️ Lab Architecture

1. **App (Flask):** Generates structured JSON logs for login attempts.
2. **SIEM Simulator:** Reads the log file, applies a detection rule (brute force).
3. **SOAR Script:** Outputs an alert and "blocks" the IP.

## 🛠️ Step 1: The Flask App (app.py)

```python
from flask import Flask, request, jsonify
import logging
import json
import datetime

app = Flask(__name__)

# Configure JSON Logging to a file
logger = logging.getLogger("security_logger")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("security.log")

class ECSFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": {
                "action": record.action,
                "outcome": record.outcome
            },
            "user": {"name": record.username},
            "source": {"ip": record.ip},
            "message": record.getMessage()
        }
        return json.dumps(log_entry)

file_handler.setFormatter(ECSFormatter())
logger.addHandler(file_handler)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    ip = request.remote_addr

    if username == "admin" and password == "secret123":
        logger.info("Login successful", extra={"action": "user-login", "outcome": "success", "username": username, "ip": ip})
        return jsonify({"status": "success"})
    else:
        logger.warning("Login failed", extra={"action": "user-login", "outcome": "failure", "username": username, "ip": ip})
        return jsonify({"status": "failure"}), 401

if __name__ == '__main__':
    app.run(port=5000)
```

## 🛠️ Step 2: SIEM / SOAR Simulator (siem.py)

```python
import json
import time
from collections import defaultdict

LOG_FILE = "security.log"
FAILED_LOGINS = defaultdict(int)
THRESHOLD = 3  # Brute force threshold

def block_ip(ip):
    print(f"\n[🚨 SOAR ACTION 🚨] IP {ip} exceeded {THRESHOLD} failed logins. Adding to WAF Blocklist!")

def monitor_logs():
    print("[*] SIEM Simulator listening for logs...")
    try:
        with open(LOG_FILE, "r") as f:
            # Go to the end of the file
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                try:
                    log_entry = json.loads(line)
                    action = log_entry["event"]["action"]
                    outcome = log_entry["event"]["outcome"]
                    ip = log_entry["source"]["ip"]

                    # Detection Logic (Sigma rule equivalent)
                    if action == "user-login" and outcome == "failure":
                        FAILED_LOGINS[ip] += 1
                        print(f"[-] SIEM Alert: Failed login from {ip} (Count: {FAILED_LOGINS[ip]})")
                        
                        if FAILED_LOGINS[ip] >= THRESHOLD:
                            block_ip(ip)
                            FAILED_LOGINS[ip] = 0 # Reset after block
                except Exception as e:
                    pass
    except FileNotFoundError:
        print("Log file not found. Run the Flask app and generate traffic first.")

if __name__ == "__main__":
    monitor_logs()
```

## 🚀 Step 3: Run the Lab

1. Start the Flask App: `python app.py`
2. In a new terminal, start the SIEM Simulator: `python siem.py`
3. Generate brute force traffic (using curl or a script):
   ```bash
   for i in {1..4}; do curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d '{"username":"admin","password":"wrong"}'; done
   ```
4. Watch the SIEM terminal trigger the SOAR block action!
