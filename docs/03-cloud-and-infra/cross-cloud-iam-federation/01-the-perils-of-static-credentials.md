---
sidebar_position: 2
title: 01 - The Perils of Static Credentials
description: Why static service account keys are the weakest link in multi-cloud architecture.
---

# The Perils of Static Credentials

## 1. The Concept (ELI5)

Imagine you own a highly secure bank vault. To let the cleaning staff in, you give them a permanent, physical master key. If the cleaning staff loses that key, or if it gets stolen, the thief has unrestricted access to the vault forever—or at least until you realize the key is gone and change all the locks. This permanent key is like a **static credential** (an AWS Access Key, a GCP Service Account JSON file, or an Azure Client Secret).

Now, imagine a different system: The cleaner arrives at the bank, shows their ID to the guard, and the guard gives them a temporary keycard that only works for the next hour and only opens the doors they need to clean. If the keycard is stolen on the way home, it’s already useless because it expired. This is the essence of **Workload Identity Federation (WIF)** and **OIDC Trust**. 

Static credentials are the leading cause of massive cloud data breaches. They are easily leaked via public GitHub repositories, exposed in CI/CD build logs, or extracted from compromised developer laptops. The goal of this module is to completely eliminate the need for permanent keys when machines talk to machines.

## 2. The Visual

```mermaid
sequenceDiagram
    participant Attacker
    participant CI_CD as CI/CD Pipeline (with static key)
    participant Cloud as Cloud Provider (AWS/GCP/Azure)
    
    rect rgb(255, 200, 200)
        Note over Attacker, Cloud: ❌ The Vulnerable Static Key Flow
        CI_CD->>Cloud: Authenticate with Long-Lived Key
        Cloud-->>CI_CD: Access Granted
        Attacker->>CI_CD: Breaches pipeline / Finds key in code
        Attacker->>Cloud: Uses stolen key from external IP
        Cloud-->>Attacker: Access Granted (Data Exfiltration!)
    end

    rect rgb(200, 255, 200)
        Note over Attacker, Cloud: ✅ The Secure OIDC Keyless Flow
        CI_CD->>Cloud: Present signed OIDC Token (Identity)
        Cloud->>Cloud: Verify Token Signature & Claims
        Cloud-->>CI_CD: Issue Short-Lived Access Token (1hr)
        CI_CD->>Cloud: Access Resources using Temporary Token
        Attacker->>CI_CD: Steals Temporary Token
        Attacker->>Cloud: Uses stolen token 2 hours later
        Cloud-->>Attacker: Access Denied (Token Expired)
    end
```

## 3. The Code

### Vulnerable Code ❌ (Using Hardcoded Static Keys)

**Python (AWS Boto3):**
```python
import boto3

# ❌ BAD: Hardcoded static access keys. Never do this!
# If this code is pushed to GitHub, bots will drain your AWS account in minutes.
s3 = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)

def list_buckets():
    response = s3.list_buckets()
    for bucket in response['Buckets']:
        print(f"Bucket: {bucket['Name']}")
```

**Go (GCP SDK):**
```go
package main

import (
	"context"
	"log"

	"google.golang.org/api/option"
	"cloud.google.com/go/storage"
)

func main() {
	ctx := context.Background()
	// ❌ BAD: Relying on a static JSON key file distributed with the application.
	client, err := storage.NewClient(ctx, option.WithCredentialsFile("/app/secrets/service-account.json"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	// ... do stuff with client
}
```

### Production-Ready Secure Code ✅ (Default Credential Chain / Identity)

**Python (AWS Boto3):**
```python
import boto3

# ✅ GOOD: No keys specified. Boto3 automatically uses the default credential provider chain.
# In a modern setup, it will use Web Identity (OIDC) tokens injected into the environment.
s3 = boto3.client('s3')

def list_buckets():
    # Will transparently exchange the OIDC token for AWS credentials in the background
    response = s3.list_buckets()
    for bucket in response['Buckets']:
        print(f"Bucket: {bucket['Name']}")
```

**Go (GCP SDK):**
```go
package main

import (
	"context"
	"log"

	"cloud.google.com/go/storage"
)

func main() {
	ctx := context.Background()
	// ✅ GOOD: Using default credentials. In GCP or a federated environment,
	// this automatically picks up the workload identity token and exchanges it.
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	// ... do stuff with client
}
```

**TypeScript (Azure SDK):**
```typescript
import { DefaultAzureCredential } from "@azure/identity";
import { BlobServiceClient } from "@azure/storage-blob";

// ✅ GOOD: DefaultAzureCredential automatically handles Workload Identity.
// It detects the federated token in the environment and exchanges it for an AAD token.
const credential = new DefaultAzureCredential();
const accountName = "myaccount";
const blobServiceClient = new BlobServiceClient(
  `https://${accountName}.blob.core.windows.net`,
  credential
);

async function listContainers() {
  for await (const container of blobServiceClient.listContainers()) {
    console.log(`Container: ${container.name}`);
  }
}
```

## 4. The Guardrail

To prevent static keys from even existing, use Infrastructure as Code (Terraform) combined with policy engines to block the creation of long-lived access keys.

### Terraform & Rego Policy (OPA)

You can use a Rego policy to reject any Terraform plan that attempts to create an AWS IAM Access Key (`aws_iam_access_key`) or a GCP Service Account Key (`google_service_account_key`).

**Rego Rule (`prevent_static_keys.rego`):**

```rego
package terraform.policies.iam

import input.resource_changes

# Define banned resource types
banned_resources = {
    "aws_iam_access_key",
    "google_service_account_key",
    "azuread_application_password"
}

deny[msg] {
    resource := resource_changes[_]
    resource.type == banned_resources[_]
    resource.change.actions[_] == "create"
    
    msg := sprintf(
        "SECURITY VIOLATION: Creation of static keys (%v) is prohibited. Use Workload Identity Federation instead.", 
        [resource.type]
    )
}
```

By enforcing this guardrail in your CI/CD pipeline (e.g., during `terraform plan`), developers are physically unable to provision static credentials, forcing the adoption of OIDC-based Workload Identity Federation.
