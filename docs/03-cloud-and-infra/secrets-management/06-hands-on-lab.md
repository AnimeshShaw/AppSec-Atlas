---
title: "06. Hands-On Lab: Hardcoded Secrets to Vault Integration"
description: "In this lab, you will start with a vulnerable Python application containing a hardcoded API key. You will exploit this vulnerability, then remediate i..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Secrets Management", "06 Hands On Lab.Md"]
---

# 06. Hands-On Lab: Hardcoded Secrets to Vault Integration

In this lab, you will start with a vulnerable Python application containing a hardcoded API key. You will exploit this vulnerability, then remediate it by securely injecting the secret via environment variables read from HashiCorp Vault.

## The Vulnerable Application (`app.py`)
```python
import requests

# BAD: Hardcoded API Key
API_KEY = "sk_live_1234567890abcdef1234567890abcdef"
PAYMENT_GATEWAY = "https://api.example.com/v1/charge"

def process_payment(amount):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    data = {"amount": amount, "currency": "usd"}
    response = requests.post(PAYMENT_GATEWAY, headers=headers, json=data)
    return response.status_code
```

## The Exploit
If an attacker gains read access to the repository (e.g., via a misconfigured git server, a supply chain attack, or an LFI vulnerability reading `app.py`), they immediately obtain the `sk_live_...` key. They can now make fraudulent charges against the payment gateway.

```bash
# Attacker extracting the key
curl http://vulnerable-app.local/read_file?file=app.py | grep "API_KEY"

# Attacker abusing the key
curl -X POST https://api.example.com/v1/charge \
  -H "Authorization: Bearer sk_live_1234567890abcdef1234567890abcdef" \
  -d '{"amount": 10000, "currency": "usd"}'
```

## The Remediation

### Step 1: Start and Configure Local Vault
```bash
# Start dev server
vault server -dev -dev-root-token-id="root" &

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Store the secret
vault kv put secret/payment-app/config api_key="sk_live_1234567890abcdef1234567890abcdef"
```

### Step 2: The Secure Application (`app_secure.py`)
Instead of hardcoding, the app reads from the environment. The orchestration layer (Docker/Kubernetes) is responsible for fetching from Vault and setting the environment, OR the app uses the Vault SDK directly. Here we use the environment variable approach, which decouples the app from Vault.

```python
import os
import requests

# GOOD: Read from Environment Variable
API_KEY = os.getenv("PAYMENT_API_KEY")
PAYMENT_GATEWAY = "https://api.example.com/v1/charge"

def process_payment(amount):
    if not API_KEY:
        raise ValueError("PAYMENT_API_KEY environment variable is not set")
        
    headers = {"Authorization": f"Bearer {API_KEY}"}
    data = {"amount": amount, "currency": "usd"}
    response = requests.post(PAYMENT_GATEWAY, headers=headers, json=data)
    return response.status_code
```

### Step 3: Secure Execution Wrapper
A wrapper script fetches the secret from Vault and injects it securely into the application process without writing it to disk.

```bash
#!/bin/bash
# fetch-and-run.sh

# Fetch secret from Vault using CLI (requires token/auth)
export PAYMENT_API_KEY=$(vault kv get -field=api_key secret/payment-app/config)

# Execute the application. The variable is available to app_secure.py
python3 app_secure.py

# Unset to clear from memory
unset PAYMENT_API_KEY
```
