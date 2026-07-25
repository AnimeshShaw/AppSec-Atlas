---
title: "02 - Security Logging Standards"
description: "Unstructured text logs (e.g., `User admin logged in from 192.168.1.5 at 12:00 PM`) are notoriously difficult to parse, search, and write detection rul..."
keywords: ["AppSec", "Cybersecurity", "Security Guide", "Tutorial", "06 Defensive", "Logging And Monitoring", "02 Security Logging Standards.Md"]
---

# 02 - Security Logging Standards

Unstructured text logs (e.g., `User admin logged in from 192.168.1.5 at 12:00 PM`) are notoriously difficult to parse, search, and write detection rules against. Security logging requires **Structured JSON Logging**.

## 📑 OWASP Logging Cheat Sheet

According to OWASP, you should log events that are relevant for security monitoring:
- Authentication successes and failures.
- Authorization failures (Access Denied).
- Data access (especially sensitive data like PII/PHI).
- Input validation failures (e.g., detected SQLi payloads).
- Application errors and exceptions (without leaking stack traces).

## 🧩 Structured JSON Logging & ECS/CEF

By outputting logs in JSON, SIEMs can automatically ingest and index the fields without writing complex Regex parsers.

To ensure consistency across different systems, use a standard schema like:
- **ECS (Elastic Common Schema):** Developed by Elastic.
- **CEF (Common Event Format):** Developed by ArcSight.

### Bad Logging (Unstructured)
```text
2023-10-25 14:32:01 ERROR Failed login for user john_doe from IP 10.0.0.5
```

### Good Logging (Structured ECS)
```json
{
  "@timestamp": "2023-10-25T14:32:01.000Z",
  "event": {
    "action": "user-login",
    "category": ["authentication"],
    "type": ["info"],
    "outcome": "failure"
  },
  "user": {
    "name": "john_doe"
  },
  "source": {
    "ip": "10.0.0.5"
  },
  "http": {
    "request": {
      "method": "POST"
    }
  },
  "message": "Failed login attempt."
}
```

## 🛡️ Log Integrity & Tamper-Proofing

If attackers gain access to the system, their first move is often to delete or modify logs to cover their tracks.
- **Write-Only/Append-Only Logs:** Forward logs immediately to a centralized server where local admins cannot modify them.
- **Log Hashing/Signing:** Use cryptographic hashes (e.g., SHA-256) for log files or individual log entries to detect tampering.
- **WORM Storage:** Use Write-Once-Read-Many (WORM) storage (like AWS S3 Object Lock) for the central SIEM archive.
