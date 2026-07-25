---
title: "04 - Respond and Recover Functions"
description: "Comprehensive guide and best practices for 04 - Respond and Recover Functions in the nist-csf section of AppSec Atlas. Learn how to secure your infrastructure."
keywords: ['nist-csf', '04---respond-and-recover-functions', 'appsec', 'security', 'compliance']
---
# 04 - Respond and Recover Functions

## RESPOND (RS)
When a breach occurs, the Respond function focuses on containing the impact and coordinating the organizational response.

### Incident Management (RS.MA)
- **Playbooks:** Develop and maintain incident response playbooks for common scenarios (Ransomware, Data Breach, DDoS).
- **Containment:** Isolate compromised systems rapidly (e.g., disconnecting a VM from the network, disabling compromised IAM roles).
- **Eradication:** Remove the threat actor's access and malware from the environment.

### Communications (RS.CO)
- **Internal:** Notify stakeholders, legal teams, and executives.
- **External:** Coordinate with PR, regulatory bodies, and law enforcement as required by law.

## RECOVER (RC)
Recovery is about resilience—restoring capabilities or services that were impaired due to a cybersecurity event.

### Recovery Plan Execution (RC.RP)
- **Backups:** Ensure immutable, offsite backups are available and tested.
- **RTO/RPO:** Meet defined Recovery Time Objectives and Recovery Point Objectives.

### Continual Improvement (RC.CI)
- **Lessons Learned:** Conduct blameless post-incident reviews (PIRs).
- **Framework Updates:** Update the Target Profile, risk assessments, and playbooks based on lessons learned.

> [!IMPORTANT]
> The effectiveness of Respond and Recover relies entirely on preparation. Conduct regular tabletop exercises simulating ransomware or cloud compromises to test your RC.RP and RS.MA outcomes.
