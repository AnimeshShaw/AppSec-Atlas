# 02 - AWS Security Hardening

Amazon Web Services (AWS) is the most widely adopted cloud platform, making it a frequent target for attackers. This section covers critical security controls in AWS.

## 1. AWS IAM Least Privilege

Identity is the new perimeter. Over-permissive roles often lead to total account compromise.

### The Vulnerable Way
An overly permissive policy that allows a user or service to do anything with EC2 and IAM:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "iam:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### The Secure Way
Apply least privilege. Restrict actions to specific resources and enforce conditions (like MFA or specific source IPs).
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcd1234efgh5678"
    }
  ]
}
```

## 2. S3 Bucket Policy Hardening

Data exposure via misconfigured S3 buckets is rampant. Ensure Block Public Access is enabled at the account level.

### Enabling S3 Block Public Access (Terraform)
```hcl
resource "aws_s3_account_public_access_block" "example" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## 3. Defeating SSRF with IMDSv2 Enforcement

The Instance Metadata Service (IMDS) provides temporary credentials to EC2 instances. IMDSv1 is highly susceptible to SSRF attacks because it relies on simple HTTP GET requests. IMDSv2 requires a session token, mitigating this threat.

### AWS CLI: Enforcing IMDSv2 on an existing EC2 Instance
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-endpoint enabled
```

### Terraform: Enforcing IMDSv2 during Provisioning
```hcl
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforces IMDSv2
    http_put_response_hop_limit = 1
  }
}
```

## 4. VPC Security Groups

Never expose administrative ports (22, 3389) or databases (3306, 5432) to `0.0.0.0/0`. 

### Secure Security Group (Terraform)
```hcl
resource "aws_security_group" "web_sg" {
  name        = "web-tier-sg"
  description = "Allow HTTPS inbound traffic from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "HTTPS from Load Balancer"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}
```
