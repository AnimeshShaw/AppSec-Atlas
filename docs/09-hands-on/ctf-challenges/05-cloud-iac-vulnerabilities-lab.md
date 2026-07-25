# Cloud & IaC Vulnerabilities Lab

## 1. Privileged Docker Container
### Vulnerable Code (Dockerfile)
```dockerfile
FROM ubuntu:20.04
# VULNERABLE: Running as root
USER root
RUN apt-get update && apt-get install -y curl
CMD ["curl", "http://example.com"]
```

### Vulnerable Docker Compose
```yaml
services:
  app:
    image: my-app
    # VULNERABLE: Granting privileged mode
    privileged: true
```

### Secure Fix
```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y curl
# SECURE: Create and use a non-root user
RUN useradd -m myuser
USER myuser
CMD ["curl", "http://example.com"]
```
```yaml
services:
  app:
    image: my-app
    # SECURE: Drop unnecessary capabilities
    cap_drop:
      - ALL
```

## 2. Exposed S3 Bucket (Terraform)
### Vulnerable Code (main.tf)
```hcl
resource "aws_s3_bucket" "vuln_bucket" {
  bucket = "my-public-company-data"
}

resource "aws_s3_bucket_acl" "vuln_bucket_acl" {
  bucket = aws_s3_bucket.vuln_bucket.id
  # VULNERABLE: Public read access
  acl    = "public-read"
}
```

### Checkov Audit Command
```bash
checkov -f main.tf
```

### Secure Fix
```hcl
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-private-company-data"
}

# SECURE: Enforce public access block
resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## 3. Hardcoded Secrets in Terraform
### Vulnerable Code
```hcl
resource "aws_db_instance" "default" {
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "admin"
  # VULNERABLE: Hardcoded password in version control
  password             = "SuperSecretPassword123!"
}
```

### Secure Fix
```hcl
# SECURE: Use AWS Secrets Manager or variables
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "my/db/password"
}

resource "aws_db_instance" "default" {
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "admin"
  password             = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```
