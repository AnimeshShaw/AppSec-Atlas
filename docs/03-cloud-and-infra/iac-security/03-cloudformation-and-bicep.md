---
title: "03 - CloudFormation and Bicep Hardening"
description: "While Terraform is cloud-agnostic, AWS CloudFormation and Azure Bicep (and ARM templates) are native IaC solutions. They require specific security con..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Iac Security", "03 Cloudformation And Bicep.Md"]
---

# 03 - CloudFormation and Bicep Hardening

While Terraform is cloud-agnostic, AWS CloudFormation and Azure Bicep (and ARM templates) are native IaC solutions. They require specific security considerations.

## 🌩️ Hardening AWS CloudFormation

### 1. Secure Parameter Handling
Never hardcode secrets. Use `NoEcho` for sensitive parameters and integrate with AWS Secrets Manager or Systems Manager Parameter Store.

**✅ Secure CloudFormation (Fetching Secret dynamically):**
```yaml
Parameters:
  DBPassword:
    Type: 'AWS::SSM::Parameter::Value<String>'
    Default: '/prod/db/password'
    NoEcho: true # Hides the value in AWS Console and logs

Resources:
  MyRDSInstance:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: !Ref DBPassword
      StorageEncrypted: true
```

### 2. IAM Role Restrictions
When executing CloudFormation, assign a specific IAM role to the stack rather than relying on the user's permissions. This enforces least privilege for the deployment process.

### 3. Stack Policies
Use Stack Policies to prevent accidental or malicious updates to critical resources (like databases or key S3 buckets).

## 🔷 Hardening Azure Bicep / ARM

Bicep is Azure's domain-specific language for deploying Azure resources, compiling down to ARM templates.

### 1. Secure Parameters with `@secure()`
Always decorate sensitive parameters with the `@secure()` decorator to prevent them from being logged or stored in deployment history.

**❌ Vulnerable Bicep:**
```bicep
param adminPassword string
// Password will be visible in deployment logs!
```

**✅ Secure Bicep:**
```bicep
@secure()
param adminPassword string

resource sqlServer 'Microsoft.Sql/servers@2021-11-01-preview' = {
  name: 'myserver'
  location: resourceGroup().location
  properties: {
    administratorLogin: 'adminUser'
    administratorLoginPassword: adminPassword
  }
}
```

### 2. Azure Key Vault Integration
Fetch secrets directly from Azure Key Vault during deployment using the `getSecret` function in ARM/Bicep.

```bicep
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' existing = {
  name: 'my-secure-keyvault'
}

resource sqlServer 'Microsoft.Sql/servers@2021-11-01-preview' = {
  name: 'myserver'
  location: resourceGroup().location
  properties: {
    administratorLogin: 'adminUser'
    administratorLoginPassword: keyVault.getSecret('sqlAdminPassword')
  }
}
```

### 3. Enforcing Managed Identities
Avoid using connection strings with passwords. Provision System-Assigned or User-Assigned Managed Identities for your resources to communicate securely without explicit credentials.

---
**Next:** [IaC SAST & Policy as Code](04-iac-sast-and-policy-as-code.md)
