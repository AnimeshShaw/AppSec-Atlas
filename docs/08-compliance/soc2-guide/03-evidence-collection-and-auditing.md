---
title: "03 - Evidence Collection and Auditing"
description: "Comprehensive guide and best practices for 03 - Evidence Collection and Auditing in the soc2-guide section of AppSec Atlas. Learn how to secure your infrastruct"
keywords: ['soc2-guide', '03---evidence-collection-and-auditing', 'appsec', 'security', 'compliance']
---
# 03 - Evidence Collection and Auditing

To pass a SOC 2 audit, you need **evidence** that your controls are working. Manual screenshots are painful. Automate this.

## 🛠 AWS Evidence Collection (CC6.x)

Auditors will want to see that your AWS environment is secure.

### Terraform Configuration for CloudTrail (CC7.1)
CloudTrail is mandatory for SOC 2 to prove you are logging API activity.

```hcl
# main.tf
resource "aws_cloudtrail" "compliance_trail" {
  name                          = "soc2-compliance-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # CRITICAL FOR SOC 2 (Proves logs weren't tampered with)
  kms_key_id                    = aws_kms_key.cloudtrail_key.arn
}
```

### Python Script to Verify S3 Public Access Block (CC6.6)
Auditors want proof that S3 buckets aren't public.

```python
import boto3
import json

def check_s3_public_access():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    evidence = []
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response['PublicAccessBlockConfiguration']
            is_secure = (config.get('BlockPublicAcls') and 
                         config.get('IgnorePublicAcls') and 
                         config.get('BlockPublicPolicy') and 
                         config.get('RestrictPublicBuckets'))
            
            evidence.append({
                "bucket": bucket_name,
                "public_access_blocked": is_secure
            })
        except s3.exceptions.ClientError as e:
            # If no PublicAccessBlock is set, it might be exposed
            evidence.append({
                "bucket": bucket_name,
                "public_access_blocked": False,
                "error": str(e)
            })
            
    with open('s3_evidence.json', 'w') as f:
        json.dump(evidence, f, indent=4)
    print("Evidence saved to s3_evidence.json")

if __name__ == "__main__":
    check_s3_public_access()
```

## 🐙 GitHub Evidence Collection (CC8.1)

Auditors need proof that code changes require review (Change Management).

### Python Script to Check Branch Protections

```python
import requests
import os

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = "your-org/your-repo"
HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}

def get_branch_protection():
    url = f"https://api.github.com/repos/{REPO}/branches/main/protection"
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code == 200:
        data = response.json()
        required_reviews = data.get("required_pull_request_reviews", {})
        approvals = required_reviews.get("required_approving_review_count", 0)
        
        print(f"[SUCCESS] Repository {REPO} main branch is protected.")
        print(f"Required Approvals: {approvals}")
        
        # Save as evidence
        with open("github_branch_evidence.txt", "w") as f:
            f.write(f"Repo: {REPO}\nProtected: True\nApprovals Required: {approvals}")
    else:
        print(f"[FAIL] Branch protection not enabled or accessible. Status: {response.status_code}")

if __name__ == "__main__":
    get_branch_protection()
```

## 🐕 Datadog / Monitoring Evidence (CC7.1)

Auditors want to see that critical alerts exist and are routed correctly. Take a screenshot of your Datadog Monitors page showing:
- High CPU/Memory alerts
- Application Error Rate (5xx) > threshold alerts
- Unusually high number of failed logins (Security)

*Tip:* Export your Terraform Datadog monitor definitions as text evidence.


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
