# 05 - Cloud Incident Response

Incident Response (IR) in the cloud differs heavily from on-premises environments. You rarely have physical access to machines, and IP addresses are ephemeral.

## Key Phases in Cloud IR

1. **Identification:** Utilizing GuardDuty, Security Hub, or SIEM alerts.
2. **Containment:** Revoking IAM keys, isolating network access.
3. **Eradication & Remediation:** Deleting malicious resources, patching vulnerabilities.
4. **Recovery:** Restoring known-good backups.

## Containment: Isolating a Compromised Instance

If an EC2 instance is suspected of being compromised, **do not terminate it immediately**. Terminating destroys forensic evidence in RAM. Instead, isolate it dynamically.

### AWS Network Isolation via Security Groups
Replace the instance's current Security Group with an "Isolation SG" that denies all egress traffic and only allows ingress from the forensic team's IP on port 22/3389.

```bash
# Step 1: Create an isolation SG (out of band or via terraform/console)
# Step 2: Apply isolation SG to the compromised instance
aws ec2 modify-instance-attribute \
    --instance-id i-0deadbeef12345678 \
    --groups sg-0123456789abcdef0 # The Isolation SG ID
```

### Revoking Temporary Credentials
If the instance IAM role was compromised (e.g., via SSRF), revoke all active sessions for that role.

```bash
# Attach an inline policy to deny all actions for sessions issued before right now
aws iam put-role-policy \
    --role-name CompromisedInstanceRole \
    --policy-name RevokeSessions \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Deny",
          "Action": "*",
          "Resource": "*",
          "Condition": {
            "DateLessThan": {
              "aws:TokenIssueTime": "2023-10-01T12:00:00Z"
            }
          }
        }
      ]
    }'
```

## Forensic Artifact Collection: Snapshot Creation

To perform disk forensics (using tools like Volatility or Autopsy), take a snapshot of the EBS volumes attached to the compromised instance.

```bash
# 1. Find the volume ID attached to the instance
aws ec2 describe-instances \
    --instance-id i-0deadbeef12345678 \
    --query "Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId"

# 2. Create a snapshot of the volume
aws ec2 create-snapshot \
    --volume-id vol-0a1b2c3d4e5f6g7h8 \
    --description "Forensic snapshot of compromised instance i-0deadbeef12345678"
```
Once the snapshot is created, it can be mounted to an isolated forensic workstation in a secure VPC for analysis.
