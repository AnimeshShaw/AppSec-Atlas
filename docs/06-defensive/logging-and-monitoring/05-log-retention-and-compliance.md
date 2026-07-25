---
title: "05 - Log Retention & Compliance"
description: "Storing logs securely and for the correct amount of time is not just a security best practice; it is a legal and regulatory requirement."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Logging And Monitoring", "05 Log Retention And Compliance.Md"]
---

# 05 - Log Retention & Compliance

Storing logs securely and for the correct amount of time is not just a security best practice; it is a legal and regulatory requirement.

## 📜 Compliance Requirements

Different frameworks mandate specific log retention periods:

| Framework | Requirement | Typical Retention Period |
| :--- | :--- | :--- |
| **PCI DSS** (Payment Card) | Audit trails must be kept for 1 year, with 3 months immediately available for analysis. | 1 Year |
| **SOC 2** | No strict timeline, but generally expects logs available for incident investigations. | 6 - 12 Months |
| **HIPAA** (Healthcare) | Requires logs of access to PHI. | Up to 6 Years |
| **GDPR** (EU Privacy) | Do not keep logs containing PII longer than necessary (Data Minimization). | 30 - 90 Days (for PII) |

## 🗄️ Storage Tiering (Hot, Warm, Cold)

Logs are massive. Keeping a year of logs on high-speed SSDs (Hot storage) is financially ruinous. SIEMs use data tiering:

1. **Hot Tier (0 - 30 days):** Fast NVMe/SSD storage. Used for immediate querying, dashboards, and active threat hunting.
2. **Warm Tier (30 - 90 days):** Standard HDD storage. Slower queries, used for recent historical investigations.
3. **Cold / Archive Tier (90 days - 1+ years):** Cheap object storage (e.g., AWS S3 Glacier, Azure Archive). Very slow to retrieve, used purely for compliance and audits.

## 🔐 Log Protection

- **Encryption at Rest:** Ensure log storage volumes and S3 buckets are encrypted (AES-256).
- **Encryption in Transit:** Forward logs via TLS (e.g., HTTPS, mutual TLS for Filebeat).
- **Masking:** Mask or drop highly sensitive data (e.g., credit card numbers, passwords) *before* they are written to the log file or sent to the SIEM.

### Log Masking Example (Fluentd/Logstash)
Never log raw passwords. If a developer accidentally logs a password, configure the Log Shipper to redact it:
```ruby
# Pseudo-Logstash filter
filter {
  mutate {
    gsub => [
      "message", "password=([^&]+)", "password=[REDACTED]"
    ]
  }
}
```
