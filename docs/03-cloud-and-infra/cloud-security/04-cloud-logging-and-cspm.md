# 04 - Cloud Logging and CSPM

Visibility is the cornerstone of cloud security. If you cannot see what is happening in your environment, you cannot secure it. 

## Cloud Audit Logs

Every major cloud provider has a centralized logging service that records API activity. These logs must be enabled, centralized in a secure location, and monitored.

- **AWS CloudTrail:** Records AWS API calls. Ensure CloudTrail is enabled across all regions and that log files are sent to a dedicated, restricted logging AWS account.
- **GCP Cloud Audit Logs:** Provides Admin Activity, Data Access, and System Event logs. Data Access logs (e.g., reading a file from a bucket) are disabled by default due to volume and must be explicitly enabled.
- **Azure Activity Log:** Provides insight into subscription-level events. Connect Activity Logs to Azure Monitor or Microsoft Sentinel.

### AWS CLI: Checking CloudTrail Status
```bash
aws cloudtrail describe-trails
```

## Cloud Security Posture Management (CSPM)

CSPM tools automatically evaluate cloud environments against compliance frameworks (like CIS Benchmarks) and best practices. They detect misconfigurations such as open security groups, lack of MFA, and unencrypted databases.

### 1. Prowler (AWS, Azure, GCP)
Prowler is a leading open-source security tool to perform security assessments, audits, and incident response.

**Running Prowler against AWS:**
```bash
# Install Prowler
pip install prowler

# Run Prowler with specific checks (CIS AWS Foundations Benchmark)
prowler aws --checks cis_1.4_aws
```

### 2. Scout Suite (Multi-Cloud)
Scout Suite is an open-source multi-cloud security-auditing tool that generates HTML reports.

**Running Scout Suite against GCP:**
```bash
# Install Scout Suite
pip install scoutsuite

# Run Scout Suite (requires active gcloud session)
scout gcp --project-id my-gcp-project-id
```

### CSPM Architecture Best Practices
- Run CSPM scans daily or continuously via Event-Driven architecture (e.g., triggering a check via AWS EventBridge when a new S3 bucket is created).
- Alert security teams via Slack/Jira for high-severity misconfigurations.
- Auto-remediate low-risk, high-confidence findings (e.g., automatically attaching a Block Public Access policy to new S3 buckets).
