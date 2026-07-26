---
title: 02. HashiCorp Vault Deep Dive
description: Master HashiCorp Vault architecture, AppRole & Kubernetes authentication,
  KV v2 versioning, dynamic database credentials, transit envelope encryption, and
  multi-language SDK integrations.
keywords:
- hashicorp
- vault
- approle
- dynamic
- secrets
- transit
- engine
- encryption
- as
- a
- service
- raft
- integrated
- storage
- hvac
- node-vault
- go
- vault
- api
- java
- vault
sidebar_label: 02. HashiCorp Vault Deep Dive
sidebar_position: 3
slug: /cloud-and-infra/secrets-management/hashicorp-vault
---


# 02. HashiCorp Vault Deep Dive

> [!IMPORTANT]
> HashiCorp Vault is the industry-standard platform for secrets management, identity-based access control, and encryption as a service. It operates under a strict **default-deny** security posture: all paths are denied unless explicitly permitted by an attached access control list (ACL) policy.

---

## 1. Vault Architecture & Cryptographic Mechanics

Vault acts as a secure cryptographic barrier between untrusted storage backends and consuming workloads.

```mermaid
graph TD
    subgraph "Workload Requests"
        Client[Application / CLI / CI-CD]
    end

    subgraph "Vault Core Cryptographic Barrier"
        Auth[Auth Methods\nAppRole / K8s / IAM] --> Barrier{Cryptographic Barrier\nAES-256-GCM}
        Engine[Secrets Engines\nKV v2 / Database / Transit] --> Barrier
        Audit[Audit Devices\nFile / Syslog / Socket] --> Barrier
    end

    subgraph "Untrusted Storage Layer"
        Barrier -->|Encrypted Payload| Storage[(Raft Integrated Storage / Consul)]
    end

    Client -->|Authenticated Call| Auth
    Barrier -->|Log Every Event| Audit

    style Barrier fill:#2b6cb0,stroke:#2c5282,color:#fff
    style Storage fill:#4a5568,stroke:#2d3748,color:#fff
    style Audit fill:#742a2a,stroke:#9b2c2c,color:#fff
```

### Key Architectural Components

1. **Storage Backend**: Untrusted persistence layer (Raft Integrated Storage, Consul, PostgreSQL). Vault encrypts all data before sending it to the storage backend using AES-256-GCM. The storage backend never sees plaintext secrets.
2. **Cryptographic Barrier**: The encryption boundary protecting Vault's internal state. Data passing through the barrier is decrypted only in volatile RAM.
3. **Barrier Unsealing & Key Management**:
   - **Shamir's Secret Sharing**: By default, Vault generates a Master Key split into `N` key shares. A quorum of `K` shares (e.g., 3 of 5) is required to reconstruct the Master Key and unseal the vault.
   - **Cloud KMS Auto-Unseal**: Production clusters use AWS KMS, GCP KMS, or Azure Key Vault to automatically unseal Vault without human intervention upon process restart.
4. **Transit Engine (Encryption as a Service)**: Handles encryption, decryption, signing, and hashing in-flight without exposing the underlying cryptographic keys to consuming applications (Envelope Encryption pattern).

---

## 2. Machine-to-Machine Authentication Methods

Applications must prove their identity before Vault issues an access token.

### AppRole Authentication (CI/CD & Microservices)

AppRole models human username/password credentials into machine identities using a **RoleID** (static application identifier) and a **SecretID** (ephemeral credential acting as a password).

```mermaid
sequenceDiagram
    autonumber
    participant App as Application Workload
    participant CI as CI/CD Provisioner
    participant Vault as HashiCorp Vault
    
    CI->>Vault: 1. Provision AppRole (role_id, policy)
    Vault-->>CI: 2. Return RoleID
    CI->>Vault: 3. Generate Wrapped SecretID (Response Wrapping)
    Vault-->>CI: 4. Return Single-Use Wrapping Token
    CI->>App: 5. Inject RoleID & Wrapping Token via Env / Disk
    App->>Vault: 6. Unwrap SecretID (POST /v1/sys/wrapping/unwrap)
    Vault-->>App: 7. Return Plaintext SecretID
    App->>Vault: 8. Authenticate (POST /v1/auth/approle/login)
    Vault-->>App: 9. Issue Short-Lived Vault Access Token (TTL: 1h)
```

#### Provisioning an AppRole via Vault CLI

```bash
# 1. Enable AppRole auth backend
vault auth enable approle

# 2. Define application ACL policy (HCL)
vault policy write payment-service-policy - <<EOF
path "secret/data/production/payment/*" {
  capabilities = ["read"]
}
path "database/creds/payment-role" {
  capabilities = ["read"]
}
EOF

# 3. Create the AppRole with strict security parameters
vault write auth/approle/role/payment-service \
    secret_id_ttl=10m \
    token_num_uses=10 \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_num_uses=1 \
    policies="payment-service-policy"

# 4. Fetch the static RoleID
vault read auth/approle/role/payment-service/role-id

# 5. Generate a response-wrapped SecretID (valid for 60 seconds)
vault write -wrap-ttl=60s -f auth/approle/role/payment-service/secret-id
```

---

## 3. Secrets Engines Deep Dive

### Key/Value (KV) v2 Engine

KV v2 provides key-value storage with automatic versioning, rollback capabilities, and soft/hard deletion protection.

```bash
# Enable KV v2 engine at mount path 'secret/'
vault secrets enable -path=secret kv-v2

# Write version 1 of a secret
vault kv put secret/production/payment/config \
    api_key="sk_live_9988776655443322" \
    webhook_secret="whsec_abc123xyz"

# Read latest version of the secret
vault kv get secret/production/payment/config

# Read specific version (v1)
vault kv get -version=1 secret/production/payment/config

# Soft delete version 1 (can be restored)
vault kv delete -versions=1 secret/production/payment/config

# Permanently destroy version 1 metadata and key material
vault kv destroy -versions=1 secret/production/payment/config
```

### Dynamic Secrets (Database Engine)

Instead of statically configuring database passwords, Vault generates short-lived, unique PostgreSQL users on demand.

```bash
# 1. Enable Database secrets engine
vault secrets enable database

# 2. Configure connection to target PostgreSQL database
vault write database/config/prod-postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="payment-db-role" \
    connection_url="postgresql://{{username}}:{{password}}@postgres.internal:5432/payment_db?sslmode=verify-full" \
    username="vault_admin" \
    password="SuperSecureAdminPassword123!"

# 3. Define dynamic creation statements with 1-hour TTL
vault write database/roles/payment-db-role \
    db_name=prod-postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# 4. App requests dynamic database credentials
vault read database/creds/payment-db-role
# Returns:
# username: v-approle-payment--a87f9b...
# password: A1a!8f...
```

### Transit Engine (Encryption as a Service)

Perform in-memory envelope encryption without managing raw private keys in application processes.

```bash
# Enable transit secrets engine
vault secrets enable transit

# Create a named symmetric encryption key (AES-256-GCM)
vault write -f transit/keys/payment-card-key

# Encrypt plaintext payload ("4111111111111111" base64-encoded)
echo -n "4111111111111111" | base64 | vault write transit/encrypt/payment-card-key plaintext=-

# Output: ciphertext = vault:v1:8Fk2...

# Decrypt ciphertext payload
vault write transit/decrypt/payment-card-key ciphertext="vault:v1:8Fk2..."
```

---

## 4. Production Vault Configuration (`vault.hcl`)

Production Vault deployments require Raft Integrated Storage, TLS 1.3 listener hardening, KMS auto-unseal, and audit logging.

```hcl
# /etc/vault.d/vault.hcl
ui = true
disable_mlock = false

storage "raft" {
  path    = "/var/lib/vault/data"
  node_id = "vault-node-1"

  retry_join {
    leader_api_addr = "https://vault-node-2.internal:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-node-3.internal:8200"
  }
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault.d/certs/vault.crt"
  tls_key_file  = "/etc/vault.d/certs/vault.key"
  tls_min_version = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
}

# AWS KMS Auto-Unseal Configuration
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc-123-def-456"
}

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}

api_addr = "https://vault-node-1.internal:8200"
cluster_addr = "https://vault-node-1.internal:8201"
```

---

## 5. Multi-Language SDK Implementations

### Python (`hvac`)

```python
import os
import hvac

def get_vault_secret():
    vault_url = os.getenv("VAULT_ADDR", "https://vault.internal:8200")
    role_id = os.getenv("VAULT_ROLE_ID")
    secret_id = os.getenv("VAULT_SECRET_ID")

    # Initialize client with TLS verification
    client = hvac.Client(url=vault_url, verify=True)

    # Authenticate via AppRole
    login_response = client.auth.approle.login(
        role_id=role_id,
        secret_id=secret_id
    )
    
    # Read KV v2 secret
    secret_response = client.secrets.kv.v2.read_secret_version(
        path="production/payment/config",
        mount_point="secret"
    )

    api_key = secret_response["data"]["data"]["api_key"]
    return api_key

if __name__ == "__main__":
    key = get_vault_secret()
    print("Successfully retrieved secret from Vault!")
```

### Node.js (`node-vault`)

```javascript
const vault = require('node-vault');
const process = require('process');

async function fetchSecret() {
  const client = vault({
    apiVersion: 'v1',
    endpoint: process.env.VAULT_ADDR || 'https://vault.internal:8200',
  });

  try {
    // AppRole Login
    const roleId = process.env.VAULT_ROLE_ID;
    const secretId = process.env.VAULT_SECRET_ID;

    const authResult = await client.approleLogin({
      role_id: roleId,
      secret_id: secretId,
    });

    client.token = authResult.auth.client_token;

    // Read KV v2 Secret
    const secret = await client.read('secret/data/production/payment/config');
    const apiKey = secret.data.data.api_key;
    
    console.log('Secret retrieved successfully.');
    return apiKey;
  } catch (error) {
    console.error('Vault API error:', error.message);
    throw error;
  }
}

fetchSecret();
```

### Go (`hashicorp/vault/api`)

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	vault "github.com/hashicorp/vault/api"
)

func main() {
	config := vault.DefaultConfig()
	config.Address = os.Getenv("VAULT_ADDR")

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}

	// AppRole Login Payload
	roleID := os.Getenv("VAULT_ROLE_ID")
	secretID := os.Getenv("VAULT_SECRET_ID")

	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	resp, err := client.Logical().Write("auth/approle/login", data)
	if err != nil || resp == nil {
		log.Fatalf("AppRole login failed: %v", err)
	}

	client.SetToken(resp.Auth.ClientToken)

	// Read KV v2 secret path
	secret, err := client.KVv2("secret").Get(context.Background(), "production/payment/config")
	if err != nil {
		log.Fatalf("Failed to read secret: %v", err)
	}

	apiKey := secret.Data["api_key"].(string)
	fmt.Printf("Successfully fetched API Key: %s...\n", apiKey[:4])
}
```

### Java (Spring Vault / Native Client)

```java
package com.appsec.vault;

import org.springframework.vault.authentication.AppRoleAuthentication;
import org.springframework.vault.authentication.AppRoleAuthenticationOptions;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;

import java.net.URI;
import java.util.Map;

public class VaultSecretManager {

    public static class SecretConfig {
        private Map<String, String> data;
        public Map<String, String> getData() { return data; }
        public void setData(Map<String, String> data) { this.data = data; }
    }

    public static void main(String[] args) {
        String vaultAddr = System.getenv("VAULT_ADDR");
        String roleId = System.getenv("VAULT_ROLE_ID");
        String secretId = System.getenv("VAULT_SECRET_ID");

        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(vaultAddr));

        AppRoleAuthenticationOptions options = AppRoleAuthenticationOptions.builder()
                .roleId(AppRoleAuthenticationOptions.RoleId.provided(roleId))
                .secretId(AppRoleAuthenticationOptions.SecretId.provided(secretId))
                .build();

        VaultTemplate vaultTemplate = new VaultTemplate(endpoint, new AppRoleAuthentication(options, null));

        VaultResponseSupport<SecretConfig> response = vaultTemplate.read(
                "secret/data/production/payment/config", SecretConfig.class);

        if (response != null && response.getData() != null) {
            String apiKey = response.getData().getData().get("api_key");
            System.out.println("Java SDK successfully retrieved Vault Secret!");
        }
    }
}
```

---

> [!NEXT]
> Move to **[Chapter 03: Cloud Native Secrets Managers](./03-cloud-secrets-managers.md)** to evaluate AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault.
