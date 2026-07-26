---
title: '06 - Hands-On Lab: Automated SOC 2 Evidence Collector'
description: 'Comprehensive guide and best practices for 06 - Hands-On Lab: Automated
  SOC 2 Evidence Collector in the soc2-guide section of AppSec Atlas. Learn how to
  secure '
keywords:
- soc2-guide
- '06'
slug: /compliance/soc2-guide/hands-on-lab
---
hands-on-lab:-automated-soc-2-evidence-collector', 'appsec', 'security', 'compliance']
---
# 06 - Hands-On Lab: Automated SOC 2 Evidence Collector

In this lab, we build a self-contained Python tool that simulates what Vanta/Drata do under the hood. 

We will check AWS S3 bucket configurations (CC6.6) and IAM user MFA status (CC6.1), alert on non-compliance, and generate an evidence report.

## 🐍 Python Lab: `soc2_collector.py`

### Prerequisites
- Python 3.9+
- `boto3` installed (`pip install boto3`)
- AWS CLI configured with read-only credentials

### The Code

```python
import boto3
import json
import datetime

class SOC2EvidenceCollector:
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.iam_client = boto3.client('iam')
        self.evidence = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "controls": {
                "CC6.6_S3_Encryption": [],
                "CC6.1_IAM_MFA": []
            },
            "status": "PASS"
        }

    def check_s3_encryption(self):
        """CC6.6: Verify all S3 buckets have default encryption enabled."""
        buckets = self.s3_client.list_buckets()['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                enc = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                is_encrypted = len(rules) > 0
                
                self.evidence["controls"]["CC6.6_S3_Encryption"].append({
                    "resource": bucket_name,
                    "compliant": is_encrypted,
                    "details": rules
                })
            except self.s3_client.exceptions.ClientError as e:
                # If no encryption policy exists, it raises an error
                self.evidence["controls"]["CC6.6_S3_Encryption"].append({
                    "resource": bucket_name,
                    "compliant": False,
                    "error": "No ServerSideEncryptionConfiguration found."
                })
                self.evidence["status"] = "FAIL"
                print(f"[ALERT] CC6.6 VIOLATION: Bucket {bucket_name} is unencrypted at rest!")

    def check_iam_mFA(self):
        """CC6.1: Verify all IAM users have MFA enabled."""
        users = self.iam_client.list_users()['Users']
        
        for user in users:
            username = user['UserName']
            mfa_devices = self.iam_client.list_mfa_devices(UserName=username)['MFADevices']
            has_mfa = len(mfa_devices) > 0
            
            self.evidence["controls"]["CC6.1_IAM_MFA"].append({
                "resource": username,
                "compliant": has_mfa
            })
            
            if not has_mfa:
                self.evidence["status"] = "FAIL"
                print(f"[ALERT] CC6.1 VIOLATION: User {username} does not have MFA enabled!")

    def generate_report(self):
        report_file = f"soc2_evidence_{datetime.datetime.now().strftime('%Y%m%d')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.evidence, f, indent=4)
        print(f"\n[INFO] Evidence report generated: {report_file}")
        print(f"[INFO] Overall Status: {self.evidence['status']}")

if __name__ == "__main__":
    print("Starting SOC 2 Evidence Collection...")
    collector = SOC2EvidenceCollector()
    collector.check_s3_encryption()
    collector.check_iam_mFA()
    collector.generate_report()
```

## 🛠 Remediation

If the script outputs `[FAIL]`, you must remediate:
1. **S3 Encryption:** Go to AWS Console -> S3 -> Bucket -> Properties -> Default Encryption -> Enable (SSE-S3 or SSE-KMS).
2. **IAM MFA:** Go to IAM -> Users -> Security Credentials -> Assign MFA device. 


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
