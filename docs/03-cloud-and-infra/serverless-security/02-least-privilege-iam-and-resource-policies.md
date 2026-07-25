# 02 - Least Privilege IAM and Resource Policies

In serverless architectures, Identity and Access Management (IAM) is the new perimeter. The most critical defense mechanism is assigning a dedicated, least-privilege IAM role to *each individual function*.

## ❌ The Anti-Pattern: Shared / Overly Permissive Roles

Developers often use a single IAM role for all functions in an application or use wildcard (`*`) permissions for convenience.

### Vulnerable Example (Serverless Framework - serverless.yml)
```yaml
# BAD: Single IAM role for all functions with wildcards
provider:
  name: aws
  runtime: nodejs18.x
  iam:
    role:
      statements:
        - Effect: 'Allow'
          Action:
            - 's3:*'
            - 'dynamodb:*'
          Resource: '*'
```

If any function using this role is compromised (e.g., via command injection), the attacker gains full control over all S3 buckets and DynamoDB tables in the account.

## ✅ The Secure Pattern: Per-Function Least Privilege

Each function should have an IAM role that grants access *only* to the specific actions and specific resources it needs to operate.

### Secure Example (AWS SAM - template.yaml)

AWS SAM makes it easy to apply granular policies per function.

```yaml
# GOOD: Granular, resource-specific permissions per function
Resources:
  ProcessOrderFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/app.handler
      Runtime: python3.10
      Policies:
        # Give permission ONLY to put items into a specific DynamoDB table
        - DynamoDBCrudPolicy:
            TableName: !Ref OrdersTable
        # Give permission ONLY to read from a specific S3 bucket
        - S3ReadPolicy:
            BucketName: !Ref InvoicesBucket

  OrdersTable:
    Type: AWS::DynamoDB::Table
    # ... table definition ...
```

### Implementing Least Privilege in Serverless Framework

To achieve per-function roles in Serverless Framework, use the `serverless-iam-roles-per-function` plugin.

```yaml
# GOOD: Per-function roles using a plugin
plugins:
  - serverless-iam-roles-per-function

functions:
  uploadAvatar:
    handler: upload.handler
    iamRoleStatements:
      - Effect: 'Allow'
        Action:
          - 's3:PutObject'
        Resource:
          - 'arn:aws:s3:::user-avatars-bucket/${self:custom.stage}/*'
```

## 🛡️ Resource-Based Policies

While Identity-based policies (attached to the Lambda function) control what the function can do, **Resource-based policies** (attached to the resource itself, like an S3 bucket or API Gateway) control *who* can invoke the function.

### Example: API Gateway invoking Lambda

Always ensure that only the expected event source can invoke your function. AWS usually sets this up automatically when creating triggers via the console or SAM, but it's important to verify.

```json
{
  "Version": "2012-10-17",
  "Id": "default",
  "Statement": [
    {
      "Sid": "AllowExecutionFromAPIGateway",
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "arn:aws:execute-api:us-east-1:123456789012:api-id/*/*/*"
        }
      }
    }
  ]
}
```
*This policy ensures that only a specific API Gateway (api-id) can invoke the Lambda function, mitigating direct unauthorized invocation.*
