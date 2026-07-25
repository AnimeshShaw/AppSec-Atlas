# 05 - Drift Detection and Compliance

Even with strict CI/CD pipelines, "click-ops" (manual changes made in the cloud console) can cause the actual infrastructure to drift from the IaC definitions. This creates massive security blind spots.

## 🚨 Automated Drift Detection

Drift detection ensures that your source of truth (Git) matches reality (the Cloud). 

### Tools for Drift Detection

1. **Terraform `plan` in CI/CD**: Running `terraform plan` on a schedule (e.g., nightly) can alert you if the plan indicates changes. If the plan shows changes, it means drift has occurred.
2. **Driftctl**: An open-source tool specifically designed to track IaC drift.
   ```bash
   # Run driftctl
   driftctl scan
   ```
3. **Cloud Native Tools**:
   - **AWS CloudFormation Drift Detection**: Native feature to detect stack drift.
   - **AWS Config**: Continuously monitors AWS resource configurations and compares them against desired states.

## 🛡️ Enforcing Compliance via IaC

Frameworks like the **CIS Benchmarks** provide consensus-based best practices for securing cloud environments. You should enforce these via your IaC configurations.

### AWS Config Rules via Terraform
You can use Terraform to provision AWS Config Rules that continuously monitor for compliance.

```hcl
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.example]
}
```

### Remediation
When drift or non-compliance is detected:
1. **Alerting**: Send notifications via Slack/Teams or PagerDuty.
2. **Automated Remediation**: Tools like AWS Config can trigger SSM automation documents to automatically fix issues (e.g., stripping public access from an S3 bucket).
3. **Re-sync via IaC**: Update the IaC repository to incorporate the change if it was legitimate, or re-run the IaC pipeline to overwrite the unauthorized manual change.

---
**Next:** [Hands-On Lab](06-hands-on-lab.md)
