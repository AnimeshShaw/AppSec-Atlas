---
title: "Breach Notification and DPIA"
description: "Comprehensive guide and best practices for Breach Notification and DPIA in the gdpr-technical section of AppSec Atlas. Learn how to secure your infrastructure."
keywords: ['gdpr-technical', 'breach-notification-and-dpia', 'appsec', 'security', 'compliance']
---
# Breach Notification and DPIA

## Article 33/34: Data Breach Notification
Under GDPR, a personal data breach is "a breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, personal data."

### The 72-Hour Rule
If a breach poses a risk to the rights and freedoms of individuals, the Controller must notify the supervisory authority **without undue delay and, where feasible, not later than 72 hours** after having become aware of it.
If the risk to individuals is *high*, you must also notify the affected users directly (Article 34).

### Technical Readiness for Breach Notification
You cannot report what you cannot see. Robust logging and monitoring are required.
1. **Centralized Logging:** (e.g., ELK stack, Splunk, Datadog).
2. **Audit Trails:** Log who accessed what PII and when.
3. **Alerting:** Automated alerts for anomalous database exports or excessive API calls.

## Data Protection Impact Assessments (DPIA)
Article 35 requires a DPIA when processing is "likely to result in a high risk to the rights and freedoms of natural persons" (e.g., using new technologies, processing sensitive data on a large scale, systematic monitoring).

### When to Conduct a DPIA (Technical Triggers)
- Implementing machine learning/AI that makes automated decisions about users.
- Deploying mass surveillance or location tracking.
- Processing special categories of data (health, biometric, political opinions).

### DPIA Technical Workflow
1. **Describe the Processing:** Data flow diagrams, architecture schematics.
2. **Assess Necessity:** Is the data collection strictly necessary?
3. **Identify Risks:** Threat modeling (e.g., STRIDE) focusing on privacy.
4. **Implement Mitigations:** Applying encryption, pseudonymization, and access controls.

> [!TIP]
> Integrate DPIA triggers into your CI/CD or Architecture Review Board (ARB) processes. If a developer proposes adding a new PII field or a new third-party integration, require a mini-privacy review.
