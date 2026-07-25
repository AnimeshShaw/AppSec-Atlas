# 01 - Introduction to Cloud Security

## The Shared Responsibility Model

In the cloud, security is shared between the Cloud Service Provider (CSP) and the customer. Understanding this model is the first step in building a secure cloud environment. A common misconception is that migrating to the cloud automatically guarantees security.

- **IaaS (Infrastructure as a Service)**: CSP secures the physical data centers, networking hardware, and hypervisors. The customer is responsible for guest OS patching, application security, IAM, network configuration, and data encryption.
- **PaaS (Platform as a Service)**: CSP manages the OS and runtime environment. The customer secures the application code, identity access, and data.
- **SaaS (Software as a Service)**: CSP secures almost everything. The customer is only responsible for managing who has access (IAM) and how data is shared.

### Shared Responsibility Diagram
```text
+-----------------------+--------------------+-------------------+
| Component             | IaaS               | SaaS              |
+-----------------------+--------------------+-------------------+
| Data                  | Customer           | Customer          |
| Identity / Access     | Customer           | Customer          |
| Applications          | Customer           | Provider          |
| Operating System      | Customer           | Provider          |
| Physical / Hypervisor | Provider           | Provider          |
+-----------------------+--------------------+-------------------+
```

## Cloud Attack Vectors

Cloud environments are susceptible to distinct threats that differ from traditional on-prem architectures:

1. **Misconfigured Storage:** Open S3 buckets, public Azure Blob storage.
2. **Over-privileged IAM:** Wildcard permissions (`sts:AssumeRole *`, `iam:PassRole`) enabling privilege escalation.
3. **Leaked Credentials:** Hardcoded access keys in GitHub repos or Docker images.
4. **Server-Side Request Forgery (SSRF) & IMDS:** Querying the Instance Metadata Service (IMDS) at `169.254.169.254` to extract temporary IAM credentials.
5. **Insecure Network Controls:** Overly permissive Security Groups (0.0.0.0/0).

## CIS Benchmarks for Cloud

The **Center for Internet Security (CIS)** provides comprehensive, consensus-based guidelines for securing cloud environments. Following CIS Benchmarks helps organizations ensure a hardened baseline configuration.

Key areas covered by CIS for cloud include:
- Identity and Access Management (MFA enforcement, credential rotation).
- Storage (disabling public access, enforcing encryption at rest).
- Logging and Monitoring (enabling Audit Logs, alerting on root account usage).
- Networking (restricting SSH/RDP to known IPs).
