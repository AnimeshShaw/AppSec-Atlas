---
title: "HashiCorp Vault Deep Dive"
description: "Learn how to use HashiCorp Vault for secure secret storage, AppRole authentication, dynamic database credentials, and transit encryption as a service."
keywords: ["hashicorp vault", "approle", "dynamic secrets", "transit engine", "encryption"]
---
# 02. HashiCorp Vault

> [!IMPORTANT]
> HashiCorp Vault is the industry standard for secret management, encryption as a service, and privileged access management. It follows a default-deny policy.

## Architecture & Concepts
Vault provides a unified interface to any secret, while providing tight access control and recording a detailed audit log.
- **Storage Backend**: Where Vault stores the encrypted data (Consul, etcd, PostgreSQL, local disk). Vault does not trust the storage backend; all data is encrypted via AES-256-GCM before writing.
- **Barrier**: The cryptographic boundary protecting the internal state of Vault.
- **Secrets Engines**: Components that store, generate, or encrypt data (e.g., KV, Transit, Database, AWS).
- **Auth Methods**: Components that authenticate users or applications (e.g., AppRole, Kubernetes, LDAP, OIDC).
- **Audit Devices**: Components that log every request and response.

## AppRole Authentication (Machine-to-Machine)
AppRole is designed for applications to authenticate with Vault. It relies on a `RoleID` (similar to a username) and a `SecretID` (similar to a password).

```bash
# Enable AppRole
vault auth enable approle

# Create a policy for our app
vault policy write myapp-policy - <<EOF
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
EOF

# Create the AppRole
vault write auth/approle/role/myapp \
    secret_id_ttl=10m \
    token_num_uses=10 \
    token_ttl=20m \
    token_max_ttl=30m \
    secret_id_num_uses=40 \
    policies="myapp-policy"

# Retrieve RoleID and SecretID
vault read auth/approle/role/myapp/role-id
vault write -f auth/approle/role/myapp/secret-id
```

## Key/Value (KV) v2 Secrets Engine
The KV engine is used to store static secrets. v2 supports versioning, allowing rollback to previous secret values and preventing accidental overwrites from destroying data.

> [!TIP]
> Always prefer KV v2 over KV v1 unless backward compatibility strictly requires it.

```bash
# Enable KV v2
vault secrets enable -path=secret kv-v2

# Write a secret
vault kv put secret/myapp/config db_password="SuperSecretPassword123!" api_key="abc-123"

# Read a secret
vault kv get secret/myapp/config
```

## Dynamic Secrets (Database Engine)
Instead of statically storing a database password, Vault can generate temporary database credentials on demand.

```bash
# Enable database engine
vault secrets enable database

# Configure connection to PostgreSQL
vault write database/config/my-postgresql-database \
    plugin_name=postgresql-database-plugin \
    allowed_roles="my-role" \
    connection_url="postgresql://{{username}}:{{password}}@localhost:5432/mydb?sslmode=disable" \
    username="postgres" \
    password="rootpassword"

# Create a role that generates credentials with a 1-hour TTL
vault write database/roles/my-role \
    db_name=my-postgresql-database \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Request dynamic credentials
vault read database/creds/my-role
```

## Transit Engine (Encryption as a Service)
The Transit engine allows Vault to handle cryptographic functions (encryption/decryption) without exposing the underlying keys to the application. This is ideal for Envelope Encryption, where applications encrypt data locally using a data key, and Vault encrypts that data key.

> [!WARNING]
> Do not send large payloads (like entire files) directly to Vault for encryption, as it introduces massive network overhead. Use Vault Transit for encrypting Data Encryption Keys (DEKs), not the data itself.

```bash
vault secrets enable transit
vault write -f transit/keys/my-app-key

# Encrypt data (requires base64 encoded payload)
echo -n "my sensitive data" | base64 | vault write transit/encrypt/my-app-key plaintext=-

# Decrypt data
vault write transit/decrypt/my-app-key ciphertext=vault:v1:...
```

## SDK Integration

### Python Example (hvac)
```python
import os
import hvac

client = hvac.Client(url='http://127.0.0.1:8200')

# Authenticate with AppRole
client.auth.approle.login(
    role_id=os.environ['VAULT_ROLE_ID'],
    secret_id=os.environ['VAULT_SECRET_ID'],
)

# Read secret
read_response = client.secrets.kv.v2.read_secret_version(path='myapp/config')
db_password = read_response['data']['data']['db_password']
print(f"Retrieved DB Password: {db_password}")
```

### Node.js Example (node-vault)
```javascript
const vault = require('node-vault')({
  apiVersion: 'v1',
  endpoint: 'http://127.0.0.1:8200'
});

async function getSecret() {
  const roleId = process.env.VAULT_ROLE_ID;
  const secretId = process.env.VAULT_SECRET_ID;

  const result = await vault.approleLogin({ role_id: roleId, secret_id: secretId });
  vault.token = result.auth.client_token;

  const secret = await vault.read('secret/data/myapp/config');
  console.log(`DB Password: ${secret.data.data.db_password}`);
}

getSecret();
```
