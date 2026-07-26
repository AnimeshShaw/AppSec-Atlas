---
title: 04. CVSS v4.0 & Risk Scoring
description: Common Vulnerability Scoring System (CVSS) v4.0 provides a standardized
  metric for rating vulnerability severity based on technical impact and environ...
keywords:
- AppSec
- Cybersecurity
- Security
- Guide
- Tutorial
- '05'
- Offensive
- Penetration
- Testing
- '04'
- Cvss
- Scoring
- And
- Risk
- Md
slug: /offensive/penetration-testing/cvss-scoring-and-risk
---


# 04. CVSS v4.0 & Risk Scoring

Common Vulnerability Scoring System (CVSS) v4.0 provides a standardized metric for rating vulnerability severity based on technical impact and environmental context.

---

## 1. CVSS v4.0 Metric Categories

- **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P).
- **Attack Complexity (AC)**: Low (L), High (H).
- **Attack Requirements (AT)**: None (N), Present (P).
- **Privileges Required (PR)**: None (N), Low (L), High (H).
- **User Interaction (UI)**: None (N), Passive (P), Active (A).
- **Impact Metrics**: Confidentiality (VC), Integrity (VI), Availability (VA).

---

## 2. CVSS Severity Ratings

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CVSS v4.0 Score Categories                             │
├──────────────┬──────────────────────────────────────────────────────────────┤
│ 0.0          │ None                                                         │
│ 0.1 – 3.9    │ Low Severity                                                 │
│ 4.0 – 6.9    │ Medium Severity                                              │
│ 7.0 – 8.9    │ High Severity                                                │
│ 9.0 – 10.0   │ Critical Severity                                            │
└──────────────┴──────────────────────────────────────────────────────────────┘
```

---

*Next Chapter: [05. Reporting & Remediation Tracking →](05-reporting-and-remediation.md)*
