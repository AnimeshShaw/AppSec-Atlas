---
title: "05 - DevSecOps Metrics and Maturity"
description: "Comprehensive guide and best practices for 05 - DevSecOps Metrics and Maturity in the devsecops-handbook section of AppSec Atlas. Learn how to secure your infra"
keywords: ['devsecops-handbook', '05---devsecops-metrics-and-maturity', 'appsec', 'security', 'compliance']
---
# 05 - DevSecOps Metrics and Maturity

To prove the ROI of a DevSecOps program, you must measure it. This chapter covers the frameworks used to assess maturity and the key performance indicators (KPIs) you should track.

## Maturity Frameworks

### OWASP SAMM (Software Assurance Maturity Model)
OWASP SAMM provides a measurable way to analyze and improve your software security posture. It is broken down into five business functions:
1. **Governance:** Strategy, Metrics, Policy, and Compliance.
2. **Design:** Threat Modeling, Security Requirements, Secure Architecture.
3. **Implementation:** Secure Build, Secure Deployment, Defect Management.
4. **Verification:** Architecture Assessment, Requirements Testing, Security Testing.
5. **Operations:** Incident Management, Environment Management, Operational Management.

*Goal:* Assess your organization against SAMM yearly to identify gaps and build a roadmap.

### BSIMM (Building Security In Maturity Model)
While SAMM is prescriptive (telling you what you *should* do), BSIMM is descriptive (telling you what other organizations *are* doing). It relies on real-world data gathered from dozens of enterprises.

## Key DevSecOps Metrics

### 1. Mean Time to Remediate (MTTR)
**Definition:** The average time it takes from when a vulnerability is discovered to when it is fixed in production.
**Why it matters:** A low MTTR indicates a responsive engineering team and a smooth CI/CD pipeline. Track MTTR by severity (e.g., MTTR for Criticals vs. Mediums).

### 2. Scanner Coverage
**Definition:** The percentage of your repositories or applications actively onboarded into SAST, DAST, and SCA tools.
**Why it matters:** You cannot secure what you do not scan. Aim for 100% coverage on tier-1 (mission-critical) applications.

### 3. Open Vulnerability Aging
**Definition:** A count of vulnerabilities that have breached their SLA (e.g., Criticals older than 7 days).
**Why it matters:** Helps identify bottlenecks. Are developers ignoring tickets? Is the fix blocked by legacy architecture?

### 4. False Positive Rate
**Definition:** The percentage of automated security alerts that are manually marked as false positives.
**Why it matters:** A high false-positive rate causes alert fatigue. If this is > 20%, you need to tune your SAST/DAST rules.

## Measuring Security Culture
Metrics aren't just technical. Measure culture by tracking:
- **Security Champion Engagement:** How many champions attend the monthly syncs?
- **Voluntary Training Completion:** How many developers complete secure coding training before it becomes mandatory?


> [!TIP]
> **Pro Tip:** Always automate your security and compliance checks early in the pipeline to reduce manual overhead and ensure continuous compliance.
