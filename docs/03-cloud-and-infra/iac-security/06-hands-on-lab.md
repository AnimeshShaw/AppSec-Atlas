---
title: "06 - Hands-On Lab: IaC Vulnerability and Remediation"
description: "In this lab, you will analyze a vulnerable Terraform manifest, scan it with Checkov, analyze the exploit report, and apply the secure remediation."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Iac Security", "06 Hands On Lab.Md"]
---

# 06 - Hands-On Lab: IaC Vulnerability and Remediation

In this lab, you will analyze a vulnerable Terraform manifest, scan it with Checkov, analyze the exploit report, and apply the secure remediation.

## 🚨 The Vulnerable Code

This `main.tf` creates an S3 bucket for data storage and a Security Group for an application.

**`vulnerable.tf`**
```hcl
provider "aws" {
  region = "us-east-1"
}

# Vulnerability 1: Public S3 Bucket, unencrypted
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-customer-data-bucket-123"
  acl    = "public-read" # ❌ Publicly readable!
}

# Vulnerability 2: Open Security Group
resource "aws_security_group" "web_sg" {
  name        = "web_sg"
  description = "Allow inbound web traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # ❌ SSH open to the world!
  }
}
```

## 🔍 Running the Scan (Checkov Exploit Report)

Run Checkov against the directory:
```bash
checkov -f vulnerable.tf
```

**Checkov Output Snippet:**
```text
       _               _              
   ___| |__   ___  ___| | _______   __
  / __| '_ \ / _ \/ __| |/ / _ \ \ / /
 | (__| | | |  __/ (__|   < (_) \ V / 
  \___|_| |_|\___|\___|_|\_\___/ \_/  

By Prisma Cloud | version: 2.3.xxx 

terraform scan results:

Passed checks: 0, Failed checks: 3, Skipped checks: 0

Check: CKV_AWS_20: "S3 Bucket has an ACL defined which allows public READ access."
        FAILED for resource: aws_s3_bucket.data_bucket
        File: /vulnerable.tf:6-9

Check: CKV_AWS_19: "Ensure all data stored in the S3 bucket is securely encrypted at rest"
        FAILED for resource: aws_s3_bucket.data_bucket
        File: /vulnerable.tf:6-9

Check: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
        FAILED for resource: aws_security_group.web_sg
        File: /vulnerable.tf:12-21
```

## ✅ The Secure Remediation

Let's fix the findings by modifying the Terraform code.

**`secure.tf`**
```hcl
provider "aws" {
  region = "us-east-1"
}

# Remediation 1: Private bucket with encryption
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-customer-data-bucket-123"
  # ACL removed, relying on default private or using aws_s3_bucket_acl
}

resource "aws_s3_bucket_public_access_block" "data_bucket_pab" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket_enc" {
  bucket = aws_s3_bucket.data_bucket.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Remediation 2: Restrict SSH to corporate VPN CIDR
resource "aws_security_group" "web_sg" {
  name        = "web_sg"
  description = "Allow inbound web traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # ✅ Restricted to internal network
  }
}
```

If you re-run Checkov on `secure.tf`, it will pass successfully!

---
**Next:** [References](07-references.md)
