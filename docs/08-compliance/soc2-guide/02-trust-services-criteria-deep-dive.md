---
title: 02 - Trust Services Criteria Deep Dive
description: Comprehensive guide and best practices for 02 - Trust Services Criteria
  Deep Dive in the soc2-guide section of AppSec Atlas. Learn how to secure your infrastruc
keywords:
- soc2-guide
- '02'
slug: /compliance/soc2-guide/trust-services-criteria-deep-dive
---
trust-services-criteria-deep-dive', 'appsec', 'security', 'compliance']
---
# 02 - Trust Services Criteria Deep Dive

## 🔍 The Common Criteria (CC1.0 - CC9.0)

The Security criteria, known as the Common Criteria (CC), applies to all SOC 2 audits. It is divided into 9 series.

### CC1 - Control Environment
- **Focus:** Integrity, ethical values, board oversight, organizational structure.
- **Controls:** Employee code of conduct, background checks, organizational charts.

### CC2 - Communication and Information
- **Focus:** Internal and external communication regarding security.
- **Controls:** Security awareness training, incident reporting channels, whistleblower policies.

### CC3 - Risk Assessment
- **Focus:** Identifying and analyzing risks to achieving objectives.
- **Controls:** Annual risk assessments, fraud risk analysis, vendor risk management.

### CC4 - Monitoring Activities
- **Focus:** Evaluating whether controls are present and functioning.
- **Controls:** Internal audits, compliance automation tools (Vanta/Drata).

### CC5 - Control Activities
- **Focus:** Mitigation of risks through policies and procedures.
- **Controls:** Documented security policies, IT general controls.

### CC6 - Logical and Physical Access Controls (Highly Technical)
- **CC6.1:** Logical access security software, infrastructure, and architectures over protected information assets.
  - **Implementation:** SSO (Okta), MFA enforced for all users, RBAC (Role-Based Access Control), VPN/Zero Trust Networks.
- **CC6.2:** User registration and authorization.
  - **Implementation:** Automated provisioning/deprovisioning scripts, Quarterly Access Reviews (UAR).
- **CC6.6:** Boundary protection.
  - **Implementation:** AWS WAF, Security Groups, network segmentation.
- **CC6.7:** Transmission of data.
  - **Implementation:** TLS 1.2+ minimum, SSH.

### CC7 - System Operations
- **CC7.1:** Detection and monitoring.
  - **Implementation:** AWS GuardDuty, Datadog alerts, centralized logging (SIEM), automated incident detection.
- **CC7.2:** Incident response.
  - **Implementation:** Documented IR plan, PagerDuty integration, post-mortem templates.

### CC8 - Change Management
- **CC8.1:** Authorization and testing of changes.
  - **Implementation:** Branch protection rules on GitHub (Require 1+ approvals), CI/CD automated testing (unit tests, SAST), segregation of duties (dev vs. prod).

### CC9 - Risk Mitigation
- **Focus:** Business continuity and vendor management.
- **Controls:** Annual disaster recovery tests, third-party vendor security questionnaires (SIG Lite or custom).


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
