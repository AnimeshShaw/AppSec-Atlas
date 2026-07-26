---
title: 03 - Protect and Detect Functions
description: Comprehensive guide and best practices for 03 - Protect and Detect Functions
  in the nist-csf section of AppSec Atlas. Learn how to secure your infrastructure.
keywords:
- nist-csf
- '03'
slug: /compliance/nist-csf/protect-and-detect-functions
---
protect-and-detect-functions', 'appsec', 'security', 'compliance']
---
# 03 - Protect and Detect Functions

## PROTECT (PR)
The Protect function outlines safeguards to ensure delivery of critical infrastructure services and limit or contain the impact of a potential cybersecurity event.

### Identity Management and Access Control (PR.AA)
- **Zero Trust Architecture:** Never trust, always verify.
- **MFA:** Enforce Multi-Factor Authentication for all users.
- **Least Privilege:** Users and services should only have access to what they strictly need.

### Data Security (PR.DS)
- **Encryption in Transit:** Enforce TLS 1.2+ for all communications.
- **Encryption at Rest:** Use AES-256 for databases, buckets, and volumes.
- **Data Loss Prevention (DLP):** Prevent unauthorized exfiltration of sensitive data.

### Platform Security (PR.PS)
- **Hardening:** Apply CIS Benchmarks to operating systems and container images.
- **Patch Management:** Automate the application of security updates.

## DETECT (DE)
Detect defines activities to identify the occurrence of a cybersecurity event in a timely manner.

### Continuous Monitoring (DE.CM)
- **SIEM:** Aggregate logs from endpoints, networks, and cloud environments into a Security Information and Event Management system.
- **EDR/XDR:** Deploy Endpoint Detection and Response tools to detect malicious behavior.
- **Network Traffic Analysis:** Monitor for anomalous outbound connections or lateral movement.

### Adverse Event Analysis (DE.AE)
- **Threat Intelligence:** Enrich alerts with IOCs (Indicators of Compromise).
- **Triage:** Ensure alerts are prioritized accurately based on risk and context.

```yaml
# Example: Kubernetes Network Policy for PR.AA (Zero Trust between pods)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: prod-apps
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
