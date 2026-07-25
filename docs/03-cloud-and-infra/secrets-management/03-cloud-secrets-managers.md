---
title: "Cloud Native Secrets Managers"
description: "Explore native secret management solutions in AWS, GCP, and Azure, including IAM integration, automated rotation, and usage via Python, Node.js, and Go SDKs."
keywords: ["aws secrets manager", "gcp secret manager", "azure key vault", "cloud security"]
---
# 03. Cloud Native Secrets Managers

> [!NOTE]
> If your infrastructure is entirely within a single cloud provider, their native secret management solutions offer tight IAM integration and simplified operations compared to managing a self-hosted HashiCorp Vault cluster. They reduce operational overhead while providing excellent security guarantees.

## AWS Secrets Manager
AWS Secrets Manager provides native integration with RDS for automatic password rotation, granular IAM policies, and cross-account access. 

> [!TIP]
> AWS Secrets Manager is different from AWS Systems Manager Parameter Store. While Parameter Store `SecureString` parameters are cheaper, Secrets Manager offers native rotation capabilities and cross-account sharing.

### Python (Boto3)
```python
import boto3
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "prod/myapp/db"
    region_name = "us-east-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        return get_secret_value_response['SecretString']
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        raise e
```

## Google Cloud Secret Manager
GCP Secret Manager integrates deeply with Google Cloud IAM, Workload Identity, and Cloud Build.

### Node.js (@google-cloud/secret-manager)
```javascript
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const client = new SecretManagerServiceClient();

async function accessSecretVersion() {
  const name = 'projects/my-project/secrets/my-secret/versions/latest';
  
  const [version] = await client.accessSecretVersion({
    name: name,
  });

  const payload = version.payload.data.toString('utf8');
  console.log(`Payload: ${payload}`);
}
accessSecretVersion();
```

## Azure Key Vault
Azure Key Vault manages secrets, encryption keys, and certificates. It natively integrates with Managed Identities for Azure resources.

### Go (azsecrets)
```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

func main() {
	keyVaultName := os.Getenv("KEY_VAULT_NAME")
	keyVaultUrl := fmt.Sprintf("https://%s.vault.azure.net/", keyVaultName)

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}

	client, err := azsecrets.NewClient(keyVaultUrl, cred, nil)
	if err != nil {
		log.Fatalf("failed to create a client: %v", err)
	}

	secretName := "DatabasePassword"
	
	resp, err := client.GetSecret(context.TODO(), secretName, "", nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	fmt.Printf("Secret value: %s\n", *resp.Value)
}
```
