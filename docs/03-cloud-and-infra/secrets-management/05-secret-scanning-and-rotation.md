# 05. Secret Scanning and Rotation

## 1. Automated Secret Detection in CI/CD
To prevent developers from accidentally pushing hardcoded credentials, implement secret scanning as pre-commit hooks and CI pipeline checks.

### TruffleHog
TruffleHog searches through git repositories for high-entropy strings and secret patterns, and actively verifies them against APIs to reduce false positives.

```bash
# Scan a GitHub repository
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified

# Scan a local directory
trufflehog filesystem /path/to/code
```

### Gitleaks
Gitleaks is a fast, SAST-like tool for detecting hardcoded secrets using regular expressions.

**GitHub Actions Integration:**
```yaml
name: gitleaks
on:
  push:
  pull_request:
jobs:
  scan:
    name: gitleaks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 2. Automated Secret Rotation
When a secret is compromised or expires, it must be rotated. This often requires coordinating the change between the Secrets Manager and the target system (e.g., the database).

### AWS Secrets Manager Rotation via Lambda
AWS provides pre-built Lambda functions to rotate RDS, DocumentDB, and Redshift credentials.
The Lambda function follows a strict 4-step process:
1. `create_secret`: Generates a new password and stores it in Secrets Manager as `AWSPENDING`.
2. `set_secret`: Updates the database user's password to the new value.
3. `test_secret`: Connects to the database to verify the new credentials work.
4. `finish_secret`: Marks the `AWSPENDING` version as `AWSCURRENT`.

### Webhook Rotation (General Pattern)
For systems without native integration, you can build a serverless function that:
1. Generates a new cryptographically secure random string.
2. Calls the Target API to update the key.
3. Updates Vault/Secrets Manager with the new value.
4. Restarts the dependent application pods (if they do not dynamically reload configs).
