---
title: 02 - Phishing Analysis and Email Security
description: Defending against phishing requires a deep understanding of how emails
  are delivered, verified, and parsed by Mail Transfer Agents (MTAs). This sectio...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '05'
- Offensive
- Social
- Engineering
- '02'
- Phishing
- Analysis
- And
- Email
- Security
- Md
slug: /offensive/social-engineering/phishing-analysis-and-email-security
---


# 02 - Phishing Analysis and Email Security

Defending against phishing requires a deep understanding of how emails are delivered, verified, and parsed by Mail Transfer Agents (MTAs). This section covers email authentication protocols and how to dissect email headers to spot spoofed messages.

## Email Authentication Protocols

The original SMTP protocol did not include sender verification, making it trivial to spoof the "From" address. Modern email security relies on three core DNS-based protocols to verify sender identity: SPF, DKIM, and DMARC.

### 1. SPF (Sender Policy Framework)
SPF allows a domain owner to specify which mail servers (IP addresses) are authorized to send email on behalf of their domain.

* **Mechanism:** The receiving MTA checks the `Return-Path` domain's DNS TXT records for an SPF rule and verifies if the connecting IP is listed.
* **Configuration Example (DNS TXT):**
  ```text
  v=spf1 ip4:192.168.1.100 include:_spf.google.com ~all
  ```
  *(Allows IP 192.168.1.100 and Google Workspace. `~all` means soft fail for others).*

### 2. DKIM (DomainKeys Identified Mail)
DKIM provides cryptographic assurance that the email was sent by the domain owner and that the content (body and select headers) has not been tampered with in transit.

* **Mechanism:** The sending MTA signs the email with a private key. The receiving MTA fetches the public key from the sender's DNS (using the `selector` provided in the header) and verifies the signature.
* **Configuration Example (DNS TXT for `selector1._domainkey.example.com`):**
  ```text
  v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
  ```

### 3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)
DMARC ties SPF and DKIM together and enforces **alignment**. It dictates what the receiver should do if SPF or DKIM fails (none, quarantine, or reject) and provides reporting capabilities.
* **Alignment:** DMARC requires that the domain in the visible "From" header matches the domain verified by SPF (Return-Path) or DKIM (d= tag).
* **Configuration Example (DNS TXT for `_dmarc.example.com`):**
  ```text
  v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100;
  ```
  *(Instructs receivers to reject emails that fail DMARC and send aggregate reports).*

## Analyzing Email Headers

When investigating a suspected phishing email, security analysts examine the email headers to trace its origin and authentication status.

### Key Headers to Review
1.  **`Authentication-Results:`**: Added by the receiving mail server. Summarizes the results of SPF, DKIM, and DMARC checks.
    ```text
    Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1 header.b=xyz123;
       spf=pass (google.com: domain of sender@example.com designates 192.168.1.100 as permitted sender) smtp.mailfrom=sender@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
    ```
2.  **`Received:`**: Tracks the path the email took through various MTAs. Read from bottom to top (oldest to newest). Look for mismatches between the claimed host and the actual IP address.
    ```text
    Received: from malicious-server.local (unknown [203.0.113.50])
        by mx.victim.com with SMTP id 12345
        for <employee@victim.com>; Mon, 25 Jul 2026 10:00:00 +0000
    ```
3.  **`Return-Path:`**: The address used for bounce messages (envelope sender). In spoofed emails, this often differs from the visible "From" address (which is what the user sees).

## Business Email Compromise (BEC) Defenses
BEC attacks often don't contain malware or malicious links. Instead, they rely on impersonation (often via compromised internal accounts or look-alike domains) to request fraudulent wire transfers.

**Defenses:**
*   **Enforce DMARC `p=reject`**: Prevents direct domain spoofing.
*   **Look-alike Domain Monitoring**: Monitor for registrations of domains visually similar to your brand (e.g., `examp1e.com` instead of `example.com`).
*   **External Sender Tags**: Prepend `[EXTERNAL]` to the subject line or body of emails originating outside the organization to alert users.
*   **Process Controls**: Implement multi-person approval requirements (out-of-band verification like a phone call) for financial transactions.
