---
title: "04 - Secrets Management and Cold Start Hardening"
description: "Hardcoding secrets in source code or relying heavily on unencrypted environment variables are common anti-patterns in serverless applications."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Serverless Security", "04 Secrets And Cold Start Hardening.Md"]
---

# 04 - Secrets Management and Cold Start Hardening

Hardcoding secrets in source code or relying heavily on unencrypted environment variables are common anti-patterns in serverless applications.

## ❌ The Anti-Pattern: Unencrypted Environment Variables

Developers often place API keys and database passwords in Lambda environment variables. While AWS encrypts these at rest by default using an AWS managed KMS key, anyone with `lambda:GetFunction` IAM permissions can view the plaintext variables in the AWS console or via the CLI.

Furthermore, if the function is vulnerable to an SSRF or Remote Code Execution (RCE) flaw, an attacker can simply read the environment variables (e.g., `process.env` or `os.environ`) to steal the credentials.

## ✅ The Secure Pattern: Secrets Manager / Parameter Store

The recommended approach is to store secrets in a centralized vault (AWS Secrets Manager or Systems Manager Parameter Store) and fetch them at runtime.

### Mitigating Cold Starts

Fetching a secret over the network on *every* invocation adds significant latency. To mitigate this without compromising security, we can fetch the secret *once* during the function's cold start (outside the handler) and cache it in memory for subsequent warm invocations.

### Secure Python Code Example (AWS SSM Parameter Store)

```python
import os
import boto3
import json

# Initialize the SSM client outside the handler
ssm_client = boto3.client('ssm')

# Global variable to cache the secret across warm invocations
cached_db_credentials = None

def get_db_credentials():
    global cached_db_credentials
    
    # Return cached credentials if already fetched (warm start)
    if cached_db_credentials:
        return cached_db_credentials
        
    try:
        # Fetch the secret during cold start
        response = ssm_client.get_parameter(
            Name='/production/database/credentials',
            WithDecryption=True
        )
        cached_db_credentials = json.loads(response['Parameter']['Value'])
        return cached_db_credentials
    except Exception as e:
        print(f"Failed to fetch secrets: {e}")
        raise e

def handler(event, context):
    # Retrieve credentials (will be fast on warm starts)
    db_creds = get_db_credentials()
    
    # Use credentials to connect to DB...
    db_user = db_creds['username']
    db_pass = db_creds['password']
    
    # ... execution logic ...
    
    return {"status": "success"}
```

### Required IAM Policy for the Function

To make the above code work, the Lambda function needs specific permissions to read the parameter and decrypt it via KMS.

```yaml
Policies:
  - Statement:
      - Effect: Allow
        Action:
          - ssm:GetParameter
        Resource: arn:aws:ssm:us-east-1:123456789012:parameter/production/database/credentials
      - Effect: Allow
        Action:
          - kms:Decrypt
        Resource: arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id
```

## 🛡️ Best Practices

1. **Avoid Environment Variables for High-Value Secrets:** Use Secrets Manager or Parameter Store (SecureString).
2. **Cache in Memory:** Fetch secrets during the initialization phase (cold start) and store them in memory for the lifecycle of the container.
3. **Use KMS CMKs:** Use Customer Managed Keys (CMKs) in KMS rather than default AWS keys. This allows you to set granular access policies on the key itself, adding an extra layer of defense (e.g., if a developer has access to the secret in SSM but not the KMS key, they cannot read it).
4. **Environment Variable Encryption (Alternative):** If you *must* use environment variables, encrypt them at rest with a KMS CMK, and decrypt them explicitly within the application code at runtime.
