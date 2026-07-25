# 01 - Introduction to Serverless Security

Serverless computing changes the traditional security paradigm. While the cloud provider manages OS hardening, patching, and network infrastructure, you are entirely responsible for the application logic, identity policies, and event data processing.

## 🏗️ The Serverless Threat Model

In serverless architectures, the attack surface shifts significantly:
- **No Traditional Perimeter:** Serverless applications are often triggered by a wide array of event sources (e.g., HTTP, file uploads, database streams). The concept of a single "entry point" (like a web server) disappears.
- **Ephemeral Environments:** Functions spin up on demand and tear down shortly after. This makes traditional forensics difficult, as the container and memory are destroyed.
- **Micro-Perimeters & Identity:** Security is heavily reliant on Identity and Access Management (IAM). Every function has its own identity and permissions, which can be easily misconfigured.

### Serverless vs Traditional Architecture

| Feature | Traditional / VMs | Serverless (Lambda, Functions) | Security Implications |
| :--- | :--- | :--- | :--- |
| **OS Management** | You manage, patch, and harden | Cloud provider manages | OS-level vulnerabilities are the provider's responsibility. |
| **Network Perimeter** | Firewalls, WAFs, VPCs | API Gateway, Event sources, IAM | API Gateway/IAM become the new perimeter. Network-level WAFs are less effective against non-HTTP triggers. |
| **Execution** | Long-running processes | Ephemeral, stateless containers | Traditional EDR/AV tools don't work. Logs and traces are critical for forensics. |
| **Permissions** | Service accounts for monolithic apps | Per-function IAM roles | Increased complexity. Risk of overly permissive `*` policies if not managed carefully. |

## 💥 Event-Driven Attack Vectors

Serverless functions consume events from various sources. Each source presents a unique payload structure and injection surface.

1. **API Gateway (HTTP/S):** Traditional web vulnerabilities (SQLi, XSS, Command Injection) apply here.
2. **Cloud Storage (S3 / GCS):** Triggered by file uploads. An attacker can upload a maliciously named file or embedded malicious payload.
3. **Message Queues (SQS / SNS / PubSub):** Malicious payloads can be injected upstream and processed asynchronously, causing blind injection vulnerabilities.
4. **Database Streams (DynamoDB Streams):** Modifying database records can trigger events containing poisoned data.

### The Over-Privileged Function Risk

The most common critical vulnerability in serverless is a combination of **Event Injection** and **Over-Privileged IAM Roles**. 

If a function is vulnerable to command injection and possesses an IAM role with `AdministratorAccess` (or excessive `s3:*`, `dynamodb:*`), the attacker can compromise the entire AWS account through the ephemeral function container.

## 🚀 Key Takeaways

- Assume all event sources are untrusted.
- Identity (IAM) is the primary security boundary.
- Logging and centralized observability are non-negotiable for incident response.
