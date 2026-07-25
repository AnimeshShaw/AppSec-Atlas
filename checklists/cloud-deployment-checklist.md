# Cloud Deployment Security Checklist

## Identity & Access Management
- [ ] Root/owner account has MFA enabled and is not used for day-to-day operations
- [ ] All IAM users have MFA enabled
- [ ] Service accounts have minimum required permissions (no wildcard `*` actions)
- [ ] IAM roles used instead of long-lived access keys where possible
- [ ] Access keys rotated regularly (or replaced with IAM roles)
- [ ] No access keys in code, environment variables, or config files

## Storage Security
- [ ] S3/GCS/Blob storage buckets not publicly accessible (unless intentional)
- [ ] Default encryption enabled for all storage
- [ ] Versioning enabled for critical data stores
- [ ] Object logging enabled (S3 access logs, GCS audit logs)
- [ ] Storage lifecycle policies in place

## Network Security
- [ ] VPC/VNet used to isolate resources
- [ ] Security groups follow least privilege (no 0.0.0.0/0 inbound except for public endpoints)
- [ ] Resources not directly internet-accessible unless required
- [ ] VPC Flow Logs enabled
- [ ] Bastion host or VPN used for administrative access

## Compute Security
- [ ] Operating systems patched and up to date
- [ ] Unnecessary services and ports disabled
- [ ] Instance metadata service (IMDS) v2 required (AWS) or equivalent
- [ ] No instances with public IPs unless required

## Monitoring & Alerting
- [ ] Cloud trail / audit logging enabled across all regions
- [ ] Alerts configured for: root account usage, IAM changes, security group changes
- [ ] Log retention configured (min 90 days, 1 year recommended)
- [ ] Security hub / security center enabled

## Secrets Management
- [ ] Secrets stored in a secrets manager (Vault, AWS Secrets Manager, etc.)
- [ ] No secrets hardcoded in code or infrastructure templates
- [ ] Secrets rotated automatically where possible

## Compliance & Governance
- [ ] Resource tagging policy enforced (owner, environment, cost center)
- [ ] Budget alerts configured
- [ ] Policy-as-code in place (SCP, OPA, Azure Policy)
- [ ] Regular access reviews scheduled
